mod helpers;
mod modules;

use std::fs;
use rustop::opts;
use flexi_logger::*;
use colored::Colorize;
use arrayvec::ArrayVec;
use csv::ReaderBuilder;

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

const VERSION: &str = "2.0.1-alpha";

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
                hash_type: hash_type,
                hash_value: hash, 
                description: description, 
                score: score,
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
            // For domains: substring match (e.g., "evildomain.com" matches "dga1.evildomain.com")
            if remote_lower.contains(&c2_ioc.server) || c2_ioc.server.contains(&remote_lower) {
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
                    regex: regex,
                    regex_fp: regex_fp,
                    description: description.clone(), 
                    score: score,
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
        synopsis "LOKI YARA and IOC Scanner";
        opt max_file_size:usize=10_000_000, desc:"Maximum file size to scan";
        opt show_access_errors:bool, desc:"Show all file and process access errors";
        opt scan_all_files:bool, desc:"Scan all files regardless of their file type / extension";
        opt scan_all_drives:bool, desc:"Scan all drives (including mounted drives, usb drives, cloud drives)";
        opt debug:bool, desc:"Show debugging information";
        opt trace:bool, desc:"Show very verbose trace output";
        opt noprocs:bool, desc:"Don't scan processes";
        opt nofs:bool, desc:"Don't scan the file system";
        opt folder:Option<String>, desc:"Folder to scan"; // an optional (positional) parameter
        opt alert_level:i16=80, desc:"Alert score threshold (default: 80)";
        opt warning_level:i16=60, desc:"Warning score threshold (default: 60)";
        opt notice_level:i16=40, desc:"Notice score threshold (default: 40)";
        opt max_reasons:usize=2, desc:"Maximum number of reasons to show (default: 2)";
        opt jsonl:Option<String>, desc:"Enable JSONL output to specified file";
        opt version:bool, desc:"Show version information and exit";
    }.parse_or_exit();
    
    // Handle version flag
    if args.version {
        println!("LOKI Version {} (Rust)", VERSION);
        std::process::exit(0);
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
    };

    // Logger
    let mut log_level: String = "info".to_string(); let mut std_out = Duplicate::Info; // default
    if args.debug { log_level = "debug".to_string(); std_out = Duplicate::Debug; }  // set to debug level
    if args.trace { log_level = "trace".to_string(); std_out = Duplicate::Trace; }  // set to trace level
    let log_file_name = format!("loki_{}", get_hostname());
    Logger::try_with_str(log_level).unwrap()
        .log_to_file(
            FileSpec::default()
                .basename(log_file_name)
        )
        .use_utc()
        .format(log_cmdline_format)
        .format_for_files(log_file_format)
        .duplicate_to_stdout(std_out)
        .append()
        .start()
        .unwrap();
    log::info!("LOKI scan started VERSION: {}", VERSION);

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
            scan_processes(&compiled_rules, &scan_config, &c2_iocs, jsonl_logger.as_ref())
        } else {
            (0, 0, 0, 0, 0)
        };

    // File system scan
    let (files_scanned, files_matched, file_alerts, file_warnings, file_notices) = 
        if active_modules.contains(&"FileScan".to_owned()) {
            log::info!("Scanning local file system ... ");
            scan_path(target_folder, &compiled_rules, &scan_config, &hash_collections, &fp_hash_collections, &filename_iocs, jsonl_logger.as_ref())
        } else {
            (0, 0, 0, 0, 0)
        };

    // Finished scan - collect summary
    let total_alerts = file_alerts + proc_alerts;
    let total_warnings = file_warnings + proc_warnings;
    let total_notices = file_notices + proc_notices;
    
    // Print summary
    log::info!("LOKI scan finished");
    log::info!("Summary - Files scanned: {} Matched: {} | Processes scanned: {} Matched: {} | Alerts: {} Warnings: {} Notices: {}", 
        files_scanned, files_matched,
        proc_scanned, proc_matched,
        total_alerts, total_warnings, total_notices);
    
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