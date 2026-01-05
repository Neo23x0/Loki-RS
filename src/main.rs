mod helpers;
mod modules;

use std::fs;
use rustop::opts;
use flexi_logger::*;
use colored::Colorize;
use arrayvec::ArrayVec;
use csv::ReaderBuilder;
use rayon::ThreadPoolBuilder;
use chrono::Local;

use yara_x::{Compiler, Rules};

use crate::helpers::helpers::{get_hostname, get_os_type, evaluate_env};
use crate::helpers::jsonl_logger::JsonlLogger;
use crate::modules::process_check::scan_processes;
use crate::modules::filesystem_scan::scan_path;

// Specific TODOs
// - skipping non-local file systems like network mounts or cloudfs drives

// General TODOs
// - better error handling
// - putting all modules in an array and looping over that list instead of a fixed sequence
// - restructuring project to multiple files

const VERSION: &str = "2.1.0";

const SIGNATURE_SOURCE: &str = "./signatures";
const MODULES: &'static [&'static str] = &["FileScan", "ProcessCheck"];

#[derive(Debug)]
pub struct GenMatch {
    message: String,
    score: i16,
}

pub struct YaraMatch {
    pub rulename: String,
    pub score: i16,
    pub description: String,
    pub author: String,
    pub matched_strings: Vec<String>,  // Format: "identifier: 'value' @ offset"
}

pub struct ScanConfig {
    pub max_file_size: usize,
    pub show_access_errors: bool,
    pub scan_all_types: bool,
    pub scan_all_drives: bool,
    pub alert_threshold: i16,
    pub warning_threshold: i16,
    pub notice_threshold: i16,
    pub max_reasons: usize,
    pub threads: usize,
    pub cpu_limit: u8,
}

#[derive(Debug)]
pub struct ExtVars {
    filename: String,
    filepath: String,
    filetype: String,
    extension: String,
    owner: String,
}

#[derive(Debug)]
pub struct HashIOC {
    hash_type: HashType,
    hash_value: String,
    description: String,
    score: i16,
}

// Sorted hash collections for binary search
pub struct HashIOCCollections {
    pub md5_iocs: Vec<HashIOC>,
    pub sha1_iocs: Vec<HashIOC>,
    pub sha256_iocs: Vec<HashIOC>,
}

// False positive hash collections (same structure)
pub type FalsePositiveHashCollections = HashIOCCollections;

#[derive(Debug)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Unknown
}

use regex::Regex;

#[derive(Debug)]
pub struct FilenameIOC {
    pub pattern: String, 
    pub regex: Regex,
    pub regex_fp: Option<Regex>,  // False positive regex (optional)
    pub description: String, 
    pub score: i16,
}

#[derive(Debug)]
pub struct C2IOC {
    pub server: String,  // Lowercased C2 server (IP or domain)
    pub description: String,
    pub score: i16,
}

#[derive(Debug)]
pub enum FilenameIOCType {
    String,
    Regex
}

// TODO: under construction - the data structure to hold the IOCs is still limited to 100.000 elements. 
//       I have to find a data structure that allows to store an unknown number of entries.
// Initialize the IOCs
fn initialize_hash_iocs() -> Vec<HashIOC> {
    // Compose the location of the hash IOC file
    let hash_ioc_file = format!("{}/iocs/hash-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let hash_iocs_string = match fs::read_to_string(&hash_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            log::error!("Unable to read hash IOC file {}: {:?}", hash_ioc_file, e);
            log::error!("Please ensure signature-base is available at {}", SIGNATURE_SOURCE);
            return Vec::new(); // Return empty vector instead of panicking
        }
    };
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(hash_iocs_string.as_bytes());
    // Vector that holds the hashes
    let mut hash_iocs:Vec<HashIOC> = Vec::new();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => { log::debug!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e); continue;}
        };
        // Skip comment lines and empty lines
        if record.is_empty() || record[0].starts_with("#") || record[0].trim().is_empty() {
            continue;
        }
        
        // Parse hash IOC - support 2 and 3 column formats
        // Format 1: hash;description (score defaults to 75)
        // Format 2: hash;score;description
        let hash = record[0].trim().to_ascii_lowercase();
        if hash.is_empty() {
            continue;
        }
        
        let hash_type: HashType = get_hash_type(&hash);
        if matches!(hash_type, HashType::Unknown) {
            log::debug!("Skipping invalid hash (unknown type): {}", hash);
            continue;
        }
        
        let (score, description) = if record.len() >= 3 {
            // 3-column format: hash;score;description
            match record[1].trim().parse::<i16>() {
                Ok(s) if s > 0 && s <= 100 => {
                    (s, record[2].trim().to_string())
                }
                Ok(s) => {
                    log::debug!("Invalid score {} for hash {}, using default 75", s, hash);
                    (75, record[2].trim().to_string())
                }
                Err(_) => {
                    // If score column is not a number, treat as 2-column format
                    log::debug!("Score column is not a number for hash {}, treating as 2-column format", hash);
                    (75, record[1].trim().to_string())
                }
            }
        } else if record.len() >= 2 {
            // 2-column format: hash;description (default score 75)
            (75, record[1].trim().to_string())
        } else {
            // Invalid format, skip
            log::debug!("Skipping hash IOC with invalid format: {:?}", record);
            continue;
        };
        
        log::trace!("Read hash IOC HASH: {} DESC: {} SCORE: {} TYPE: {:?}", hash, description, score, hash_type);
        hash_iocs.push(
            HashIOC { 
                hash_type,
                hash_value: hash, 
                description, 
                score,
            });
    }
    log::info!("Successfully initialized {} hash values", hash_iocs.len());
    
    // Sort hashes by value for binary search
    hash_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    
    return hash_iocs;
}

// Initialize false positive hash IOCs
// Files must contain both "hash" and "falsepositive" in filename
fn initialize_false_positive_hash_iocs() -> Vec<HashIOC> {
    // Compose the location of the hash IOC directory
    let hash_ioc_dir = format!("{}/iocs", SIGNATURE_SOURCE);
    
    // Read directory and find files with "hash" and "falsepositive" in name
    let dir = match fs::read_dir(&hash_ioc_dir) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("Unable to read IOC directory {}: {:?}", hash_ioc_dir, e);
            return Vec::new();
        }
    };
    
    let mut all_fp_hashes = Vec::new();
    
    // Find all files with "hash" and "falsepositive" in filename
    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy().to_lowercase();
        
        // Check if filename contains both "hash" and "falsepositive"
        if file_name_str.contains("hash") && file_name_str.contains("falsepositive") {
            let file_path = entry.path();
            log::info!("Loading false positive hash file: {:?}", file_path);
            
            // Read the file
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("Unable to read false positive hash file {:?}: {:?}", file_path, e);
                    continue;
                }
            };
            
            // Parse the file (same format as regular hash IOCs)
            let mut reader = ReaderBuilder::new()
                .delimiter(b';')
                .flexible(true)
                .from_reader(content.as_bytes());
            
            for result in reader.records() {
                let record = match result {
                    Ok(r) => r,
                    Err(e) => {
                        log::debug!("Cannot read line in false positive hash file (which can be okay) ERROR: {:?}", e);
                        continue;
                    }
                };
                
                // Skip comment lines and empty lines
                if record.is_empty() || record[0].starts_with("#") || record[0].trim().is_empty() {
                    continue;
                }
                
                // Parse hash (same as regular hash IOCs, but we don't need score/description for false positives)
                let hash = record[0].trim().to_ascii_lowercase();
                if hash.is_empty() {
                    continue;
                }
                
                let hash_type: HashType = get_hash_type(&hash);
                if matches!(hash_type, HashType::Unknown) {
                    log::debug!("Skipping invalid false positive hash (unknown type): {}", hash);
                    continue;
                }
                
                // For false positives, we only need the hash (score/description not used)
                let description = if record.len() >= 2 {
                    record[1].trim().to_string()
                } else {
                    "False positive".to_string()
                };
                
                log::trace!("Read false positive hash HASH: {} TYPE: {:?}", hash, hash_type);
                all_fp_hashes.push(
                    HashIOC {
                        hash_type: hash_type,
                        hash_value: hash,
                        description: description,
                        score: 0, // Not used for false positives
                    }
                );
            }
        }
    }
    
    log::info!("Successfully initialized {} false positive hash values", all_fp_hashes.len());
    all_fp_hashes.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    all_fp_hashes
}

// Organize hash IOCs by type for efficient binary search
fn organize_hash_iocs(hash_iocs: Vec<HashIOC>, label: &str) -> HashIOCCollections {
    let mut md5_iocs = Vec::new();
    let mut sha1_iocs = Vec::new();
    let mut sha256_iocs = Vec::new();
    
    for ioc in hash_iocs {
        match ioc.hash_type {
            HashType::Md5 => md5_iocs.push(ioc),
            HashType::Sha1 => sha1_iocs.push(ioc),
            HashType::Sha256 => sha256_iocs.push(ioc),
            HashType::Unknown => continue,
        }
    }
    
    // Sort each collection by hash value
    md5_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    sha1_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    sha256_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    
    log::info!("Organized {} - MD5: {} SHA1: {} SHA256: {}", 
        label, md5_iocs.len(), sha1_iocs.len(), sha256_iocs.len());
    
    HashIOCCollections {
        md5_iocs,
        sha1_iocs,
        sha256_iocs,
    }
}

// Binary search for hash in sorted collection
pub fn find_hash_ioc<'a>(hash_value: &str, iocs: &'a [HashIOC]) -> Option<&'a HashIOC> {
    iocs.binary_search_by(|ioc| ioc.hash_value.as_str().cmp(hash_value))
        .ok()
        .map(|idx| &iocs[idx])
}

// Get the hash type
fn get_hash_type(hash_value: &str) -> HashType {
    let hash_value_length = hash_value.len();
    match hash_value_length {
        32 => HashType::Md5,
        40 => HashType::Sha1,
        64 => HashType::Sha256,
        _ => HashType::Unknown,
    }
}

// Initialize C2 IOCs
// Files must contain "c2" in filename
fn initialize_c2_iocs() -> Vec<C2IOC> {
    // Compose the location of the IOC directory
    let ioc_dir = format!("{}/iocs", SIGNATURE_SOURCE);
    
    // Read directory and find files with "c2" in name
    let dir = match fs::read_dir(&ioc_dir) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("Unable to read IOC directory {}: {:?}", ioc_dir, e);
            return Vec::new();
        }
    };
    
    let mut all_c2_iocs = Vec::new();
    let mut last_comment = String::new();
    
    // Find all files with "c2" in filename
    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy().to_lowercase();
        
        // Check if filename contains "c2"
        if file_name_str.contains("c2") {
            let file_path = entry.path();
            log::info!("Loading C2 IOC file: {:?}", file_path);
            
            // Read the file
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("Unable to read C2 IOC file {:?}: {:?}", file_path, e);
                    continue;
                }
            };
            
            // Reset last comment for each file
            last_comment.clear();
            
            // Parse the file line by line
            for line in content.lines() {
                let line = line.trim();
                
                // Comments and empty lines
                if line.is_empty() {
                    continue;
                }
                
                if line.starts_with("#") {
                    // Store comment as description for following C2 entries
                    last_comment = line.trim_start_matches("#").trim().to_string();
                    continue;
                }
                
                // Parse C2 server (format: C2_Server[;Score])
                let parts: Vec<&str> = line.split(';').collect();
                let c2_server = parts[0].trim().to_lowercase();
                
                // Check minimum length (4 characters)
                if c2_server.len() < 4 {
                    log::debug!("C2 server definition is suspiciously short - will not add: {}", c2_server);
                    continue;
                }
                
                // Parse score (optional, default 75)
                let score = if parts.len() >= 2 {
                    match parts[1].trim().parse::<i16>() {
                        Ok(s) if s > 0 && s <= 100 => s,
                        Ok(s) => {
                            log::debug!("Invalid score {} for C2 server {}, using default 75", s, c2_server);
                            75
                        }
                        Err(_) => {
                            log::debug!("Score column is not a number for C2 server {}, using default 75", c2_server);
                            75
                        }
                    }
                } else {
                    75  // Default score
                };
                
                let description = if last_comment.is_empty() {
                    String::new()
                } else {
                    last_comment.clone()
                };
                
                log::trace!("Read C2 IOC SERVER: {} SCORE: {} DESC: {}", c2_server, score, description);
                all_c2_iocs.push(
                    C2IOC {
                        server: c2_server,
                        description: description,
                        score: score,
                    }
                );
            }
        }
    }
    
    log::info!("Successfully initialized {} C2 IOC values", all_c2_iocs.len());
    all_c2_iocs
}

// Check if a remote address matches any C2 IOC
// Supports IP exact match, CIDR match, and domain substring match
pub fn check_c2_match<'a>(remote_addr: &str, c2_iocs: &'a [C2IOC]) -> Option<&'a C2IOC> {
    let remote_lower = remote_addr.to_lowercase();
    
    for c2_ioc in c2_iocs {
        // For IP addresses: exact match or CIDR match
        if is_ip_address(&remote_lower) {
            // Exact match
            if c2_ioc.server == remote_lower {
                return Some(c2_ioc);
            }
            // TODO: CIDR match (would need ipnet crate)
            // For now, we'll do exact match only
        } else {
            // For domains: check if remote ends with the IOC domain
            // e.g., "dga1.evildomain.com" matches IOC "evildomain.com"
            if remote_lower.ends_with(&c2_ioc.server) || remote_lower == c2_ioc.server {
                return Some(c2_ioc);
            }
        }
    }
    
    None
}

// Simple IP address check (IPv4)
fn is_ip_address(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    true
} 

// Initialize filename IOCs / patterns
fn initialize_filename_iocs() -> Vec<FilenameIOC> {
    // Compose the location of the filename IOC file
    let filename_ioc_file = format!("{}/iocs/filename-iocs.txt", SIGNATURE_SOURCE);
    // Read the filename IOC file
    let filename_iocs_string = match fs::read_to_string(&filename_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            log::error!("Unable to read filename IOC file {}: {:?}", filename_ioc_file, e);
            log::error!("Please ensure signature-base is available at {}", SIGNATURE_SOURCE);
            return Vec::new(); // Return empty vector instead of panicking
        }
    };
    // Vector that holds the hashes
    let mut filename_iocs:Vec<FilenameIOC> = Vec::new();
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(filename_iocs_string.as_bytes());
    
    // Preset description 
    let mut description = "N/A".to_string();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(e) => { 
                log::debug!("Cannot read line in filename IOCs file (which can be okay) ERROR: {:?}", e); 
                continue;
            }
        };
        
        // Skip empty lines
        if record.is_empty() {
            continue;
        }
        
        // Handle comment lines (description)
        if record.len() == 1 && record[0].starts_with("#") {
            description = record[0]
                .strip_prefix("# ")
                .or_else(|| record[0].strip_prefix("#"))
                .unwrap_or("")
                .trim()
                .to_string();
            continue;
        }
        
        // Skip comment-only lines
        if record[0].starts_with("#") {
            continue;
        }
        
        // Parse filename IOC pattern
        // Format: pattern[;score[;false_positive_regex]]
        if record.len() >= 1 {
            let pattern = record[0].trim();
            if pattern.is_empty() {
                continue;
            }
            
            // Parse score (default if not provided)
            let score = if record.len() >= 2 {
                match record[1].trim().parse::<i16>() {
                    Ok(s) if s > 0 && s <= 100 => s,
                    Ok(s) => {
                        log::debug!("Invalid score {} for pattern {}, using default 75", s, pattern);
                        75
                    }
                    Err(_) => {
                        // If score is not a number, treat as description (old format)
                        log::debug!("Score column is not a number for pattern {}, using default 75", pattern);
                        75
                    }
                }
            } else {
                75  // Default score
            };
            
            // Parse false positive regex (optional third column)
            let regex_fp = if record.len() >= 3 && !record[2].trim().is_empty() {
                match Regex::new(record[2].trim()) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        log::debug!("Invalid false positive regex for pattern {}: {:?}", pattern, e);
                        None
                    }
                }
            } else {
                None
            };
            
            // Compile main regex pattern
            // Note: Patterns are case-sensitive in v1, so we don't lowercase them
            let regex = match Regex::new(pattern) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Invalid regex pattern in filename IOC: {} ERROR: {:?}", pattern, e);
                    continue; // Skip invalid patterns
                }
            };
            
            log::trace!("Read filename IOC PATTERN: {} SCORE: {} DESC: {}", pattern, score, description);
            filename_iocs.push(
                FilenameIOC { 
                    pattern: pattern.to_string(),
                    regex,
                    regex_fp,
                    description: description.clone(), 
                    score,
                });
        }
    }
    log::info!("Successfully initialized {} filename IOC values", filename_iocs.len());

    // Return file name IOCs
    return filename_iocs;
}

// Filename IOC type detection is no longer needed - we always compile as regex
// This function is kept for potential future use but not currently called
#[allow(dead_code)]
fn get_filename_ioc_type(_filename_ioc_value: &str) -> FilenameIOCType {
    FilenameIOCType::Regex
} 

// Initialize the rule files
fn initialize_yara_rules() -> Result<Rules, String> {
    // Composed YARA rule set 
    // we're concatenating all rules from all rule files to a single string and 
    // compile them all together into a single big rule set for performance purposes
    let mut all_rules = String::new();
    let mut count = 0u16;
    // Reading the signature folder
    let yara_sigs_folder = format!("{}/yara", SIGNATURE_SOURCE);
    let files = match fs::read_dir(&yara_sigs_folder) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!("Cannot read YARA rules directory {}: {:?}", yara_sigs_folder, e));
        }
    };
    // Filter 
    let filtered_files = files
        .filter_map(Result::ok)
        .filter(|d| if let Some(e) = d.path().extension() { e == "yar" } else { false })
        .into_iter();
    // Test compile each rule
    for file in filtered_files {
        log::debug!("Reading YARA rule file {} ...", file.path().to_str().unwrap());
        // Read the rule file
        let rules_string = match fs::read_to_string(file.path()) {
            Ok(content) => content,
            Err(e) => {
                log::error!("Unable to read YARA rule file {:?}: {:?}", file.path(), e);
                continue;
            }
        };
        let compiled_file_result = compile_yara_rules(&rules_string);
        match compiled_file_result {
            Ok(_) => { 
                log::debug!("Successfully compiled rule file {:?} - adding it to the big set", file.path().to_str().unwrap());
                // adding content of that file to the whole rules string
                all_rules += &rules_string;
                count += 1;
            },
            Err(e) => {
                log::error!("Cannot compile rule file {:?}. Ignoring file. ERROR: {:?}", file.path().to_str().unwrap(), e)                
            }
        };
    }
    // Compile the full set and return the compiled rules
    let compiled_all_rules = match compile_yara_rules(&all_rules) {
        Ok(rules) => rules,
        Err(e) => {
            return Err(format!("Error parsing the composed rule set: {:?}", e));
        }
    };
    
    // Count initialized rules by analyzing the source string (approximate)
    // Counts lines starting with "rule " (ignoring whitespace)
    let rule_count = all_rules.lines()
        .filter(|line| line.trim().starts_with("rule "))
        .count();
    
    log::info!("Successfully compiled {} rules from {} rule files into a big set", rule_count, count);
    Ok(compiled_all_rules)
}

// Compile a rule set string and check for errors
fn compile_yara_rules(rules_string: &str) -> Result<Rules, String> {
    // YARA-X API: Create compiler and add rules
    let mut compiler = Compiler::new();
    
    // Define external variables (global variables in YARA-X)
    compiler.define_global("filename", "").map_err(|e| format!("Error defining filename variable: {:?}", e))?;
    compiler.define_global("filepath", "").map_err(|e| format!("Error defining filepath variable: {:?}", e))?;
    compiler.define_global("extension", "").map_err(|e| format!("Error defining extension variable: {:?}", e))?;
    compiler.define_global("filetype", "").map_err(|e| format!("Error defining filetype variable: {:?}", e))?;
    compiler.define_global("owner", "").map_err(|e| format!("Error defining owner variable: {:?}", e))?;
    
    // Add rules from string
    compiler.add_source(rules_string).map_err(|e| format!("Error adding rules: {:?}", e))?;
    
    // Build the rules
    let rules = compiler.build();
    
    Ok(rules)
}

// Log file format for files
fn log_file_format(
    write: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
 ) -> std::io::Result<()> {
    write!(
        write,
        "[{}] {} {}",
        now.format("%Y-%m-%dT%H:%M:%SZ"),
        record.level(),
        &record.args()
    )
}

// Log file format for command line
fn log_cmdline_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    let msg = record.args().to_string();
    
    // Determine color based on level and message content
    // Standard (Green) -> Info (not starting with NOTICE)
    // Notice (Light Blue) -> Info (starting with NOTICE)
    // Warnings (Yellow) -> Warn
    // Alerts (Red) -> Error (starting with ALERT)
    // Errors (Purple) -> Error (not starting with ALERT)
    
    let colored_msg = match level {
        log::Level::Error => {
            if msg.starts_with("ALERT") {
                let clean_msg = msg.trim_start_matches("ALERT").trim();
                format!("[ALERT] {}", clean_msg).red()
            } else {
                format!("[{}] {}", level, msg).purple()
            }
        },
        log::Level::Warn => {
            if msg.starts_with("WARNING") {
                let clean_msg = msg.trim_start_matches("WARNING").trim();
                format!("[WARNING] {}", clean_msg).yellow()
            } else {
                format!("[{}] {}", level, msg).yellow()
            }
        },
        log::Level::Info => {
            if msg.starts_with("NOTICE") {
                let clean_msg = msg.trim_start_matches("NOTICE").trim();
                format!("[NOTICE] {}", clean_msg).bright_cyan()
            } else {
                format!("[{}] {}", level, msg).green()
            }
        },
        log::Level::Debug => format!("[{}] {}", level, msg).white(),
        log::Level::Trace => format!("[{}] {}", level, msg).white().dimmed(),
    };
    
    write!(w, "{}", colored_msg)
}

// Welcome message
fn welcome_message() {
    println!("------------------------------------------------------------------------");
    println!("     __   ____  __ ______  ____                                        ");
    println!("    / /  / __ \\/ //_/  _/ / __/______ ____  ___  ___ ____              ");
    println!("   / /__/ /_/ / ,< _/ /  _\\ \\/ __/ _ `/ _ \\/ _ \\/ -_) __/           ");
    println!("  /____/\\____/_/|_/___/ /___/\\__/\\_,_/_//_/_//_/\\__/_/              ");
    println!("  Simple IOC and YARA Scanner                                           ");
    println!(" ");
    println!("  Version {} (Rust)                                            ", VERSION);
    println!("  Florian Roth 2026                                                     ");
    println!(" ");
    println!("------------------------------------------------------------------------");                      
}

fn main() {

    // Show welcome message
    welcome_message();

    // Parsing command line flags
    let (args, _rest) = opts! {
        synopsis "Loki-RS YARA and IOC Scanner";
        opt cpu_limit:u8=100, desc:"CPU utilization limit percentage (1-100, default: 100)";
        opt max_file_size:usize=64_000_000, desc:"Maximum file size to scan (default: 64MB)";
        opt show_access_errors:bool, desc:"Show all file and process access errors";
        opt scan_all_drives:bool, desc:"Scan all drives (including mounted drives, usb drives, cloud drives)";
        opt scan_all_files:bool, desc:"Scan all files regardless of their file type / extension";
        opt debug:bool, desc:"Show debugging information";
        opt trace:bool, desc:"Show very verbose trace output";
        opt folder:Option<String>, desc:"Folder to scan";
        opt noprocs:bool, desc:"Don't scan processes";
        opt nofs:bool, desc:"Don't scan the file system";
        opt alert_level:i16=80, desc:"Alert score threshold (default: 80)";
        opt warning_level:i16=60, desc:"Warning score threshold (default: 60)";
        opt notice_level:i16=40, desc:"Notice score threshold (default: 40)";
        opt max_reasons:usize=2, desc:"Maximum number of reasons to show (default: 2)";
        opt jsonl:Option<String>, desc:"Enable JSONL output to specified file";
        opt version:bool, desc:"Show version information and exit";
        opt threads:i32=-2, desc:"Number of threads to use (0=all cores, -1=all-1, -2=all-2)";
    }.parse_or_exit();
    
    // Handle version flag
    if args.version {
        println!("Loki-RS Version {} (Rust)", VERSION);
        std::process::exit(0);
    }
    
    // Determine number of threads
    let num_threads = if args.threads > 0 {
        args.threads as usize
    } else if args.threads == 0 {
        num_cpus::get()
    } else {
        let cpus = num_cpus::get();
        if args.threads == -1 {
             if cpus > 1 { cpus - 1 } else { 1 }
        } else if args.threads == -2 {
             if cpus > 2 { cpus - 2 } else { 1 }
        } else {
             // Fallback for other negative numbers, treat as 1 or default?
             // User only specified -1 and -2. Let's default to 1 for other negative values or clamp.
             1
        }
    };
    
    // Start time
    let start_time = Local::now();

    // Logger
    let mut log_level: String = "info".to_string(); let mut std_out = Duplicate::Info; // default
    if args.debug { log_level = "debug".to_string(); std_out = Duplicate::Debug; }  // set to debug level
    if args.trace { log_level = "trace".to_string(); std_out = Duplicate::Trace; }  // set to trace level
    let log_file_name = format!("loki_{}", get_hostname());
    let logger_handle = Logger::try_with_str(log_level).unwrap()
        .log_to_file(
            FileSpec::default()
                .basename(log_file_name.clone())
        )
        .use_utc()
        .format(log_cmdline_format)
        .format_for_files(log_file_format)
        .duplicate_to_stdout(std_out)
        .append()
        .start()
        .unwrap();
    log::info!("Loki-RS scan started VERSION: {}", VERSION);

    // Configure thread pool
    match ThreadPoolBuilder::new().num_threads(num_threads).build_global() {
        Ok(_) => log::info!("Initialized thread pool with {} threads", num_threads),
        Err(e) => log::error!("Failed to initialize thread pool: {}", e),
    }

    // Initialize JSONL logger if requested
    let jsonl_logger: Option<JsonlLogger> = if let Some(ref jsonl_file) = args.jsonl {
        match JsonlLogger::new(jsonl_file) {
            Ok(logger) => {
                log::info!("JSONL logging enabled: {}", jsonl_file);
                Some(logger)
            }
            Err(e) => {
                log::error!("Failed to open JSONL log file {}: {}", jsonl_file, e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Print platform & environment information
    evaluate_env();
    log::info!("Thread pool THREADS: {} (requested: {})", num_threads, args.threads);

    // Evaluate active modules
    let mut active_modules: ArrayVec<String, 20> = ArrayVec::<String, 20>::new();
    for module in MODULES {
        if args.noprocs && module.to_string() == "ProcessCheck" { continue; }
        if args.nofs && module.to_string() == "FileScan" { continue; }
        active_modules.insert(active_modules.len(), module.to_string());
    }
    log::info!("Active modules MODULES: {:?}", active_modules);

    // Set some default values
    // default target folder
    let mut target_folder: String = '/'.to_string(); 
    if get_os_type() == "windows" { target_folder = "C:\\".to_string(); }
    // if target folder has ben set via command line flag
    if let Some(args_target_folder) = args.folder {
        target_folder = args_target_folder;
    }

    // Validate thresholds
    if args.alert_level < args.warning_level || args.warning_level < args.notice_level {
        eprintln!("Error: Thresholds must be in order: alert >= warning >= notice");
        eprintln!("  Alert: {}, Warning: {}, Notice: {}", args.alert_level, args.warning_level, args.notice_level);
        std::process::exit(1);
    }
    
    // Create a config
    let scan_config = ScanConfig {
        max_file_size: args.max_file_size,
        show_access_errors: args.show_access_errors,
        scan_all_types: args.scan_all_files,
        scan_all_drives: args.scan_all_drives,
        alert_threshold: args.alert_level,
        warning_threshold: args.warning_level,
        notice_threshold: args.notice_level,
        max_reasons: args.max_reasons,
        threads: num_threads,
        cpu_limit: args.cpu_limit,
    };
    
    // Print scan configuration limits
    log::info!("Scan limits MAX_FILE_SIZE: {} bytes ({:.1} MB)", 
        scan_config.max_file_size, 
        scan_config.max_file_size as f64 / 1_000_000.0);
    log::info!("Scan limits SCAN_ALL_TYPES: {} SCAN_ALL_DRIVES: {}", 
        scan_config.scan_all_types, 
        scan_config.scan_all_drives);
    if !scan_config.scan_all_types {
        log::info!("Scanned extensions: .exe, .dll, .bat, .ps1, .asp, .aspx, .jsp, .jspx, .php, .plist, .sh, .vbs, .js, .dmp, .py, .msix");
        log::info!("Scanned file types: Executable, DLL, ISO, ZIP, LNK, CHM, PCAP and more (use --scan-all-files to scan all)");
    }
    if !scan_config.scan_all_drives {
        log::info!("Excluded paths: /proc, /dev, /sys/kernel, /media, /volumes, /Volumes, CloudStorage (use --scan-all-drives to include)");
    }

    // Initialize IOCs 
    log::info!("Initialize hash IOCs ...");
    let hash_iocs = initialize_hash_iocs();
    let hash_collections = organize_hash_iocs(hash_iocs, "hash IOCs");
    log::info!("Initialize false positive hash IOCs ...");
    let fp_hash_iocs = initialize_false_positive_hash_iocs();
    let fp_hash_collections = organize_hash_iocs(fp_hash_iocs, "false positive hash IOCs");
    log::info!("Initialize filename IOCs ...");
    let filename_iocs = initialize_filename_iocs();
    log::info!("Initialize C2 IOCs ...");
    let c2_iocs = initialize_c2_iocs();

    // Initialize the YARA rules
    log::info!("Initializing YARA rules ...");
    let compiled_rules = match initialize_yara_rules() {
        Ok(rules) => rules,
        Err(e) => {
            log::error!("Failed to initialize YARA rules: {}", e);
            log::error!("Please check signature-base availability at {}", SIGNATURE_SOURCE);
            std::process::exit(1);
        }
    };

    // Process scan
    let (proc_scanned, proc_matched, proc_alerts, proc_warnings, proc_notices) = 
        if active_modules.contains(&"ProcessCheck".to_owned()) {
            log::info!("Scanning running processes ... ");
            scan_processes(&compiled_rules, &scan_config, &c2_iocs, jsonl_logger.as_ref(), None)
        } else {
            (0, 0, 0, 0, 0)
        };

    // File system scan
    let (files_scanned, files_matched, file_alerts, file_warnings, file_notices) = 
        if active_modules.contains(&"FileScan".to_owned()) {
            log::info!("Scanning local file system ... ");
            scan_path(target_folder, &compiled_rules, &scan_config, &hash_collections, &fp_hash_collections, &filename_iocs, jsonl_logger.as_ref(), None)
        } else {
            (0, 0, 0, 0, 0)
        };

    // Finished scan - collect summary
    let total_alerts = file_alerts + proc_alerts;
    let total_warnings = file_warnings + proc_warnings;
    let total_notices = file_notices + proc_notices;
    
    // Capture end time and calculate duration
    let end_time = Local::now();
    let duration = end_time.signed_duration_since(start_time);
    
    // Print summary
    log::info!("Loki-RS scan finished");
    log::info!("Summary - Files scanned: {} Matched: {} | Processes scanned: {} Matched: {} | Alerts: {} Warnings: {} Notices: {}", 
        files_scanned, files_matched,
        proc_scanned, proc_matched,
        total_alerts, total_warnings, total_notices);
        
    // Print duration and time
    log::info!("Scan Duration: {:.2}s (Start: {}, End: {})", 
        duration.num_milliseconds() as f64 / 1000.0,
        start_time.format("%Y-%m-%d %H:%M:%S"),
        end_time.format("%Y-%m-%d %H:%M:%S"));
        
    // Print output file locations
    // Log file
    // Check if we can find the log file
    if let Ok(files) = logger_handle.existing_log_files(&LogfileSelector::default()) {
        if let Some(latest_log) = files.last() {
            log::info!("Log file written to: {}", latest_log.display());
        } else {
            // Fallback if vector is empty but logging is active
            log::info!("Log file written to: ./{}_<date>_r<rotation>.log", log_file_name);
        }
    } else {
        log::info!("Log file written to: ./{}_<date>_r<rotation>.log", log_file_name);
    }
    
    // Determine exit code
    // 0 = success (no matches or only notices)
    // 1 = error (fatal errors occurred - handled earlier)
    // 2 = partial success (matches found but scan completed)
    let exit_code = if total_alerts > 0 || total_warnings > 0 {
        2  // Matches found
    } else {
        0  // No matches or only notices
    };
    
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    mod hash_type_tests {
        use super::*;

        #[test]
        fn test_md5_hash_type() {
            let hash = "d41d8cd98f00b204e9800998ecf8427e";
            assert!(matches!(get_hash_type(hash), HashType::Md5));
        }

        #[test]
        fn test_sha1_hash_type() {
            let hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
            assert!(matches!(get_hash_type(hash), HashType::Sha1));
        }

        #[test]
        fn test_sha256_hash_type() {
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            assert!(matches!(get_hash_type(hash), HashType::Sha256));
        }

        #[test]
        fn test_unknown_hash_type_short() {
            let hash = "abc123";
            assert!(matches!(get_hash_type(hash), HashType::Unknown));
        }

        #[test]
        fn test_unknown_hash_type_long() {
            let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aa";
            assert!(matches!(get_hash_type(hash), HashType::Unknown));
        }

        #[test]
        fn test_empty_hash() {
            let hash = "";
            assert!(matches!(get_hash_type(hash), HashType::Unknown));
        }
    }

    mod ip_address_tests {
        use super::*;

        #[test]
        fn test_valid_ipv4() {
            assert!(is_ip_address("192.168.1.1"));
            assert!(is_ip_address("10.0.0.1"));
            assert!(is_ip_address("127.0.0.1"));
            assert!(is_ip_address("0.0.0.0"));
            assert!(is_ip_address("255.255.255.255"));
        }

        #[test]
        fn test_invalid_ipv4_wrong_parts() {
            assert!(!is_ip_address("192.168.1"));
            assert!(!is_ip_address("192.168.1.1.1"));
            assert!(!is_ip_address("192.168"));
        }

        #[test]
        fn test_invalid_ipv4_out_of_range() {
            assert!(!is_ip_address("256.168.1.1"));
            assert!(!is_ip_address("192.168.1.256"));
        }

        #[test]
        fn test_invalid_ipv4_non_numeric() {
            assert!(!is_ip_address("192.168.1.abc"));
            assert!(!is_ip_address("not.an.ip.address"));
        }

        #[test]
        fn test_domain_not_ip() {
            assert!(!is_ip_address("example.com"));
            assert!(!is_ip_address("malware.evil.com"));
        }
    }

    mod c2_matching_tests {
        use super::*;

        fn create_test_c2_iocs() -> Vec<C2IOC> {
            vec![
                C2IOC {
                    server: "192.168.1.100".to_string(),
                    description: "Test C2 IP".to_string(),
                    score: 80,
                },
                C2IOC {
                    server: "evil.com".to_string(),
                    description: "Test C2 domain".to_string(),
                    score: 75,
                },
                C2IOC {
                    server: "malware.net".to_string(),
                    description: "Test C2 domain 2".to_string(),
                    score: 70,
                },
            ]
        }

        #[test]
        fn test_c2_exact_ip_match() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("192.168.1.100", &c2_iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().score, 80);
        }

        #[test]
        fn test_c2_no_ip_match() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("10.0.0.1", &c2_iocs);
            assert!(result.is_none());
        }

        #[test]
        fn test_c2_exact_domain_match() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("evil.com", &c2_iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().score, 75);
        }

        #[test]
        fn test_c2_subdomain_match() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("dga.evil.com", &c2_iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().description, "Test C2 domain");
        }

        #[test]
        fn test_c2_no_domain_match() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("goodsite.org", &c2_iocs);
            assert!(result.is_none());
        }

        #[test]
        fn test_c2_case_insensitive() {
            let c2_iocs = create_test_c2_iocs();
            let result = check_c2_match("EVIL.COM", &c2_iocs);
            assert!(result.is_some());
        }
    }

    mod hash_ioc_search_tests {
        use super::*;

        fn create_test_hash_iocs() -> Vec<HashIOC> {
            let mut iocs = vec![
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    description: "Test hash A".to_string(),
                    score: 80,
                },
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    description: "Test hash B".to_string(),
                    score: 75,
                },
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "cccccccccccccccccccccccccccccccc".to_string(),
                    description: "Test hash C".to_string(),
                    score: 70,
                },
            ];
            iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
            iocs
        }

        #[test]
        fn test_find_existing_hash() {
            let iocs = create_test_hash_iocs();
            let result = find_hash_ioc("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().score, 75);
        }

        #[test]
        fn test_find_first_hash() {
            let iocs = create_test_hash_iocs();
            let result = find_hash_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().description, "Test hash A");
        }

        #[test]
        fn test_find_last_hash() {
            let iocs = create_test_hash_iocs();
            let result = find_hash_ioc("cccccccccccccccccccccccccccccccc", &iocs);
            assert!(result.is_some());
            assert_eq!(result.unwrap().description, "Test hash C");
        }

        #[test]
        fn test_hash_not_found() {
            let iocs = create_test_hash_iocs();
            let result = find_hash_ioc("dddddddddddddddddddddddddddddddd", &iocs);
            assert!(result.is_none());
        }

        #[test]
        fn test_empty_iocs() {
            let iocs: Vec<HashIOC> = Vec::new();
            let result = find_hash_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &iocs);
            assert!(result.is_none());
        }
    }

    mod hash_collection_tests {
        use super::*;

        #[test]
        fn test_organize_hash_iocs_by_type() {
            let hash_iocs = vec![
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                    description: "MD5 test".to_string(),
                    score: 75,
                },
                HashIOC {
                    hash_type: HashType::Sha1,
                    hash_value: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                    description: "SHA1 test".to_string(),
                    score: 80,
                },
                HashIOC {
                    hash_type: HashType::Sha256,
                    hash_value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                    description: "SHA256 test".to_string(),
                    score: 85,
                },
            ];

            let collections = organize_hash_iocs(hash_iocs, "test");

            assert_eq!(collections.md5_iocs.len(), 1);
            assert_eq!(collections.sha1_iocs.len(), 1);
            assert_eq!(collections.sha256_iocs.len(), 1);
        }

        #[test]
        fn test_organize_empty_iocs() {
            let hash_iocs: Vec<HashIOC> = Vec::new();
            let collections = organize_hash_iocs(hash_iocs, "test");

            assert_eq!(collections.md5_iocs.len(), 0);
            assert_eq!(collections.sha1_iocs.len(), 0);
            assert_eq!(collections.sha256_iocs.len(), 0);
        }

        #[test]
        fn test_organize_multiple_same_type() {
            let hash_iocs = vec![
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    description: "MD5 A".to_string(),
                    score: 75,
                },
                HashIOC {
                    hash_type: HashType::Md5,
                    hash_value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    description: "MD5 B".to_string(),
                    score: 80,
                },
            ];

            let collections = organize_hash_iocs(hash_iocs, "test");

            assert_eq!(collections.md5_iocs.len(), 2);
            assert_eq!(collections.sha1_iocs.len(), 0);
            assert_eq!(collections.sha256_iocs.len(), 0);
            assert_eq!(collections.md5_iocs[0].hash_value, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
    }

    mod filename_ioc_tests {
        use super::*;

        fn create_test_filename_iocs() -> Vec<FilenameIOC> {
            vec![
                FilenameIOC {
                    pattern: r"mimikatz\.exe$".to_string(),
                    regex: Regex::new(r"mimikatz\.exe$").unwrap(),
                    regex_fp: None,
                    description: "Mimikatz tool".to_string(),
                    score: 90,
                },
                FilenameIOC {
                    pattern: r".*\.ps1$".to_string(),
                    regex: Regex::new(r".*\.ps1$").unwrap(),
                    regex_fp: Some(Regex::new(r"legitimate\.ps1$").unwrap()),
                    description: "PowerShell script".to_string(),
                    score: 50,
                },
            ]
        }

        #[test]
        fn test_filename_regex_match() {
            let iocs = create_test_filename_iocs();
            assert!(iocs[0].regex.is_match("/path/to/mimikatz.exe"));
            assert!(!iocs[0].regex.is_match("/path/to/notepad.exe"));
        }

        #[test]
        fn test_filename_with_false_positive() {
            let iocs = create_test_filename_iocs();
            assert!(iocs[1].regex.is_match("/path/to/script.ps1"));
            assert!(iocs[1].regex.is_match("/path/to/legitimate.ps1"));
            assert!(iocs[1].regex_fp.as_ref().unwrap().is_match("/path/to/legitimate.ps1"));
            assert!(!iocs[1].regex_fp.as_ref().unwrap().is_match("/path/to/malicious.ps1"));
        }
    }

    mod scan_config_tests {
        use super::*;

        #[test]
        fn test_default_scan_config() {
            let config = ScanConfig {
                max_file_size: 64_000_000,
                show_access_errors: false,
                scan_all_types: false,
                scan_all_drives: false,
                alert_threshold: 80,
                warning_threshold: 60,
                notice_threshold: 40,
                max_reasons: 2,
                threads: 4,
                cpu_limit: 100,
            };

            assert_eq!(config.max_file_size, 64_000_000);
            assert!(!config.show_access_errors);
            assert_eq!(config.alert_threshold, 80);
            assert!(config.alert_threshold > config.warning_threshold);
            assert!(config.warning_threshold > config.notice_threshold);
        }

        #[test]
        fn test_threshold_ordering() {
            let config = ScanConfig {
                max_file_size: 64_000_000,
                show_access_errors: false,
                scan_all_types: false,
                scan_all_drives: false,
                alert_threshold: 80,
                warning_threshold: 60,
                notice_threshold: 40,
                max_reasons: 2,
                threads: 4,
                cpu_limit: 100,
            };

            assert!(80 >= 60);
            assert!(60 >= 40);
            assert!(config.alert_threshold >= config.warning_threshold);
            assert!(config.warning_threshold >= config.notice_threshold);
        }
    }

    mod ext_vars_tests {
        use super::*;

        #[test]
        fn test_ext_vars_creation() {
            let ext_vars = ExtVars {
                filename: "test.exe".to_string(),
                filepath: "/path/to".to_string(),
                filetype: "WINDOWS EXECUTABLE".to_string(),
                extension: "exe".to_string(),
                owner: "root".to_string(),
            };

            assert_eq!(ext_vars.filename, "test.exe");
            assert_eq!(ext_vars.filepath, "/path/to");
            assert_eq!(ext_vars.extension, "exe");
        }
    }

    mod gen_match_tests {
        use super::*;

        #[test]
        fn test_gen_match_creation() {
            let m = GenMatch {
                message: "Test match".to_string(),
                score: 75,
            };

            assert_eq!(m.message, "Test match");
            assert_eq!(m.score, 75);
        }

        #[test]
        fn test_gen_match_sorting() {
            let mut matches = vec![
                GenMatch { message: "Low".to_string(), score: 40 },
                GenMatch { message: "High".to_string(), score: 90 },
                GenMatch { message: "Medium".to_string(), score: 60 },
            ];

            matches.sort_by(|a, b| b.score.cmp(&a.score));

            assert_eq!(matches[0].score, 90);
            assert_eq!(matches[1].score, 60);
            assert_eq!(matches[2].score, 40);
        }
    }

    mod yara_match_tests {
        use super::*;

        #[test]
        fn test_yara_match_creation() {
            let m = YaraMatch {
                rulename: "TestRule".to_string(),
                score: 80,
                description: "A test rule".to_string(),
                author: "Test Author".to_string(),
                matched_strings: vec!["$s1: 'test' @ 0".to_string()],
            };

            assert_eq!(m.rulename, "TestRule");
            assert_eq!(m.score, 80);
            assert_eq!(m.matched_strings.len(), 1);
        }

        #[test]
        fn test_yara_match_empty_metadata() {
            let m = YaraMatch {
                rulename: "MinimalRule".to_string(),
                score: 75,
                description: String::new(),
                author: String::new(),
                matched_strings: Vec::new(),
            };

            assert!(m.description.is_empty());
            assert!(m.author.is_empty());
            assert!(m.matched_strings.is_empty());
        }
    }
}