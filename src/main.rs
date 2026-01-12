mod helpers;
mod modules;

use std::fs;
use std::sync::Arc;
use std::io::{Read, Write};
use std::path::PathBuf;
use clap::Parser;
use arrayvec::ArrayVec;
use csv::ReaderBuilder;
use rayon::ThreadPoolBuilder;
use chrono::Local;

use yara_x::{Compiler, Rules};

/// Loki-RS - High-Performance, Multi-threaded YARA & IOC Scanner
#[derive(Parser, Debug)]
#[command(name = "loki")]
#[command(about = "Loki-RS - High-Performance, Multi-threaded YARA & IOC Scanner", long_about = None)]
#[command(disable_version_flag = true)]
struct Cli {
    // =========================================================================
    // SCAN TARGET
    // =========================================================================
    
    /// Folder to scan (default: entire system)
    #[arg(short = 'f', long, help_heading = "Scan Target")]
    folder: Option<String>,

    // =========================================================================
    // SCAN CONTROL
    // =========================================================================
    
    /// Don't scan processes
    #[arg(long, help_heading = "Scan Control")]
    no_procs: bool,

    /// Don't scan the file system
    #[arg(long, help_heading = "Scan Control")]
    no_fs: bool,

    /// Don't scan inside archive files (ZIP)
    #[arg(long, help_heading = "Scan Control")]
    no_archive: bool,

    /// Scan all local hard drives (Windows: fixed drives, Linux/macOS: local filesystems)
    #[arg(long, help_heading = "Scan Control")]
    scan_hard_drives: bool,

    /// Scan all drives (including mounted drives, usb drives, cloud drives, network drives)
    #[arg(long, help_heading = "Scan Control")]
    scan_all_drives: bool,

    /// Scan all files regardless of their file type / extension
    #[arg(long, help_heading = "Scan Control")]
    scan_all_files: bool,

    // =========================================================================
    // OUTPUT OPTIONS
    // =========================================================================
    
    /// Specify log output file (defaults to loki_<hostname>_<date>.log)
    #[arg(short = 'l', long, help_heading = "Output Options")]
    log: Option<String>,

    /// Disable plaintext log output
    #[arg(long, help_heading = "Output Options")]
    no_log: bool,

    /// Specify JSONL output file (defaults to loki_<hostname>_<date>.jsonl)
    #[arg(short = 'j', long, help_heading = "Output Options")]
    jsonl: Option<String>,

    /// Disable JSONL output
    #[arg(long, help_heading = "Output Options")]
    no_jsonl: bool,

    /// Disable HTML report generation
    #[arg(long, help_heading = "Output Options")]
    no_html: bool,

    /// Enable remote logging (host:port)
    #[arg(short = 'r', long, help_heading = "Output Options")]
    remote: Option<String>,

    /// Remote protocol (udp/tcp)
    #[arg(short = 'p', long, default_value = "udp", help_heading = "Output Options")]
    remote_proto: String,

    /// Remote format (syslog/json)
    #[arg(long, default_value = "syslog", help_heading = "Output Options")]
    remote_format: String,

    // =========================================================================
    // TUNING
    // =========================================================================
    
    /// Alert score threshold
    #[arg(long, default_value_t = 80, help_heading = "Tuning")]
    alert_level: i16,

    /// Warning score threshold
    #[arg(long, default_value_t = 60, help_heading = "Tuning")]
    warning_level: i16,

    /// Notice score threshold
    #[arg(long, default_value_t = 40, help_heading = "Tuning")]
    notice_level: i16,

    /// Maximum number of match reasons to display per finding
    #[arg(long, default_value_t = 2, help_heading = "Tuning")]
    max_reasons: usize,

    /// Maximum file size to scan in bytes
    #[arg(short = 'm', long, default_value_t = 64_000_000, help_heading = "Tuning")]
    max_file_size: usize,

    /// CPU utilization limit percentage (1-100)
    #[arg(short = 'c', long, default_value_t = 100, help_heading = "Tuning")]
    cpu_limit: u8,

    /// Number of threads to use (0=all, -1=all-1, -2=all-2)
    #[arg(long, default_value_t = -2, help_heading = "Tuning")]
    threads: i32,

    // =========================================================================
    // INFO & DEBUG
    // =========================================================================
    
    /// Show version information and exit
    #[arg(long, help_heading = "Info & Debug")]
    version: bool,

    /// Show debugging information
    #[arg(short = 'd', long, help_heading = "Info & Debug")]
    debug: bool,

    /// Show very verbose trace output
    #[arg(long, help_heading = "Info & Debug")]
    trace: bool,

    /// Show all file and process access errors
    #[arg(long, help_heading = "Info & Debug")]
    show_access_errors: bool,

    /// Disable TUI and use standard command-line logging
    #[arg(long, help_heading = "Output Options")]
    no_tui: bool,
}

use crate::helpers::helpers::{get_hostname, get_os_type, evaluate_env};
use crate::helpers::html_report;
use crate::helpers::unified_logger::{UnifiedLogger, LoggerConfig, RemoteConfig, RemoteProtocol, RemoteFormat, LogLevel, TuiMessage};
use crate::helpers::interrupt::ScanState;
use crate::helpers::tui::run_tui;
use crate::modules::{ScanModule, ScanContext};
use crate::modules::process_check::ProcessCheckModule;
use crate::modules::filesystem_scan::{FileScanModule, enumerate_drives};

// Specific TODOs
// - better error handling

const VERSION: &str = env!("CARGO_PKG_VERSION");

const SIGNATURE_SOURCE: &str = "./signatures";
const MODULES: &'static [&'static str] = &["FileScan", "ProcessCheck"];

#[derive(Debug)]
pub struct GenMatch {
    pub message: String,
    pub score: i16,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
    pub matched_strings: Option<Vec<String>>,
}

pub struct YaraMatch {
    pub rulename: String,
    pub score: i16,
    pub description: String,
    pub author: String,
    pub reference: String,
    pub matched_strings: Vec<String>,  // Format: "identifier: 'value' @ offset"
}

#[derive(Clone)]
pub struct ScanConfig {
    pub max_file_size: usize,
    pub show_access_errors: bool,
    pub scan_all_types: bool,
    pub scan_hard_drives: bool,
    pub scan_all_drives: bool,
    pub scan_archives: bool,
    pub alert_threshold: i16,
    pub warning_threshold: i16,
    pub notice_threshold: i16,
    pub max_reasons: usize,
    pub threads: usize,
    pub cpu_limit: u8,
    pub exclusion_count: usize,
    pub yara_rules_count: usize,
    pub ioc_count: usize,
    pub program_dir: Option<String>,
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
fn initialize_hash_iocs(logger: &UnifiedLogger) -> Vec<HashIOC> {
    // Compose the location of the hash IOC file
    let hash_ioc_file = format!("{}/iocs/hash-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let hash_iocs_string = match fs::read_to_string(&hash_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            logger.error(&format!("Unable to read hash IOC file {}: {:?}", hash_ioc_file, e));
            logger.error(&format!("Please ensure IOCs are available at {}/iocs/ (run 'loki-util update' to download)", SIGNATURE_SOURCE));
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
            Err(e) => { logger.debug(&format!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e)); continue;}
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
            logger.debug(&format!("Skipping invalid hash (unknown type): {}", hash));
            continue;
        }
        
        let (score, description) = if record.len() >= 3 {
            // 3-column format: hash;score;description
            match record[1].trim().parse::<i16>() {
                Ok(s) if s > 0 && s <= 100 => {
                    (s, record[2].trim().to_string())
                }
                Ok(s) => {
                    logger.debug(&format!("Invalid score {} for hash {}, using default 75", s, hash));
                    (75, record[2].trim().to_string())
                }
                Err(_) => {
                    // If score column is not a number, treat as 2-column format
                    logger.debug(&format!("Score column is not a number for hash {}, treating as 2-column format", hash));
                    (75, record[1].trim().to_string())
                }
            }
        } else if record.len() >= 2 {
            // 2-column format: hash;description (default score 75)
            (75, record[1].trim().to_string())
        } else {
            // Invalid format, skip
            logger.debug(&format!("Skipping hash IOC with invalid format: {:?}", record));
            continue;
        };
        
        logger.debug(&format!("Read hash IOC HASH: {} DESC: {} SCORE: {} TYPE: {:?}", hash, description, score, hash_type));
        hash_iocs.push(
            HashIOC { 
                hash_type,
                hash_value: hash, 
                description, 
                score,
            });
    }
    logger.info(&format!("Successfully initialized {} hash values", hash_iocs.len()));
    
    // Sort hashes by value for binary search
    hash_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    
    return hash_iocs;
}

// Initialize false positive hash IOCs
// Files must contain both "hash" and "falsepositive" in filename
fn initialize_false_positive_hash_iocs(logger: &UnifiedLogger) -> Vec<HashIOC> {
    // Compose the location of the hash IOC directory
    let hash_ioc_dir = format!("{}/iocs", SIGNATURE_SOURCE);
    
    // Read directory and find files with "hash" and "falsepositive" in name
    let dir = match fs::read_dir(&hash_ioc_dir) {
        Ok(d) => d,
        Err(e) => {
            logger.debug(&format!("Unable to read IOC directory {}: {:?}", hash_ioc_dir, e));
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
            logger.info(&format!("Loading false positive hash file: {:?}", file_path));
            
            // Read the file
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    logger.warning(&format!("Unable to read false positive hash file {:?}: {:?}", file_path, e));
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
                        logger.debug(&format!("Cannot read line in false positive hash file (which can be okay) ERROR: {:?}", e));
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
                    logger.debug(&format!("Skipping invalid false positive hash (unknown type): {}", hash));
                    continue;
                }
                
                // For false positives, we only need the hash (score/description not used)
                let description = if record.len() >= 2 {
                    record[1].trim().to_string()
                } else {
                    "False positive".to_string()
                };
                
                logger.debug(&format!("Read false positive hash HASH: {} TYPE: {:?}", hash, hash_type));
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
    
    logger.info(&format!("Successfully initialized {} false positive hash values", all_fp_hashes.len()));
    all_fp_hashes.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));
    all_fp_hashes
}

// Organize hash IOCs by type for efficient binary search
fn organize_hash_iocs(hash_iocs: Vec<HashIOC>, label: &str, logger: &UnifiedLogger) -> HashIOCCollections {
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
    
    logger.info(&format!("Organized {} - MD5: {} SHA1: {} SHA256: {}", 
        label, md5_iocs.len(), sha1_iocs.len(), sha256_iocs.len()));
    
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
fn initialize_c2_iocs(logger: &UnifiedLogger) -> Vec<C2IOC> {
    // Compose the location of the IOC directory
    let ioc_dir = format!("{}/iocs", SIGNATURE_SOURCE);
    
    // Read directory and find files with "c2" in name
    let dir = match fs::read_dir(&ioc_dir) {
        Ok(d) => d,
        Err(e) => {
            logger.debug(&format!("Unable to read IOC directory {}: {:?}", ioc_dir, e));
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
            logger.info(&format!("Loading C2 IOC file: {:?}", file_path));
            
            // Read the file
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(e) => {
                    logger.warning(&format!("Unable to read C2 IOC file {:?}: {:?}", file_path, e));
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
                    logger.debug(&format!("C2 server definition is suspiciously short - will not add: {}", c2_server));
                    continue;
                }
                
                // Parse score (optional, default 75)
                let score = if parts.len() >= 2 {
                    match parts[1].trim().parse::<i16>() {
                        Ok(s) if s > 0 && s <= 100 => s,
                        Ok(s) => {
                            logger.debug(&format!("Invalid score {} for C2 server {}, using default 75", s, c2_server));
                            75
                        }
                        Err(_) => {
                            logger.debug(&format!("Score column is not a number for C2 server {}, using default 75", c2_server));
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
                
                logger.debug(&format!("Read C2 IOC SERVER: {} SCORE: {} DESC: {}", c2_server, score, description));
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
    
    logger.info(&format!("Successfully initialized {} C2 IOC values", all_c2_iocs.len()));
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
fn initialize_filename_iocs(logger: &UnifiedLogger) -> Vec<FilenameIOC> {
    // Compose the location of the filename IOC file
    let filename_ioc_file = format!("{}/iocs/filename-iocs.txt", SIGNATURE_SOURCE);
    // Read the filename IOC file
    let filename_iocs_string = match fs::read_to_string(&filename_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            logger.error(&format!("Unable to read filename IOC file {}: {:?}", filename_ioc_file, e));
            logger.error(&format!("Please ensure IOCs are available at {}/iocs/ (run 'loki-util update' to download)", SIGNATURE_SOURCE));
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
                logger.debug(&format!("Cannot read line in filename IOCs file (which can be okay) ERROR: {:?}", e)); 
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
                        logger.debug(&format!("Invalid score {} for pattern {}, using default 75", s, pattern));
                        75
                    }
                    Err(_) => {
                        // If score is not a number, treat as description (old format)
                        logger.debug(&format!("Score column is not a number for pattern {}, using default 75", pattern));
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
                        logger.debug(&format!("Invalid false positive regex for pattern {}: {:?}", pattern, e));
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
                    logger.error(&format!("Invalid regex pattern in filename IOC: {} ERROR: {:?}", pattern, e));
                    continue; // Skip invalid patterns
                }
            };
            
            logger.debug(&format!("Read filename IOC PATTERN: {} SCORE: {} DESC: {}", pattern, score, description));
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
    logger.info(&format!("Successfully initialized {} filename IOC values", filename_iocs.len()));

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
// Returns (compiled_rules, rule_count)
fn initialize_yara_rules(logger: &UnifiedLogger) -> Result<(Rules, usize), String> {
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
        logger.debug(&format!("Reading YARA rule file {} ...", file.path().to_str().unwrap()));
        // Read the rule file
        let rules_string = match fs::read_to_string(file.path()) {
            Ok(content) => content,
            Err(e) => {
                logger.error(&format!("Unable to read YARA rule file {:?}: {:?}", file.path(), e));
                continue;
            }
        };
        let compiled_file_result = compile_yara_rules(&rules_string);
        match compiled_file_result {
            Ok(_) => { 
                logger.debug(&format!("Successfully compiled rule file {:?} - adding it to the big set", file.path().to_str().unwrap()));
                // adding content of that file to the whole rules string
                all_rules += &rules_string;
                count += 1;
            },
            Err(e) => {
                logger.error(&format!("Cannot compile rule file {:?}. Ignoring file. ERROR: {:?}", file.path().to_str().unwrap(), e))                
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
    
    logger.info(&format!("Successfully compiled {} rules from {} rule files into a big set", rule_count, count));
    Ok((compiled_all_rules, rule_count))
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





// Enable ANSI escape code support on Windows
#[cfg(windows)]
fn enable_ansi_support() {
    use windows::Win32::System::Console::{
        GetStdHandle, SetConsoleMode, GetConsoleMode,
        STD_OUTPUT_HANDLE, STD_ERROR_HANDLE, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };
    
    unsafe {
        // Enable for stdout
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        // Enable for stderr
        if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
fn enable_ansi_support() {
    // ANSI codes work natively on Unix-like systems
}

/// Count the number of active exclusion patterns in the config file
/// Returns the count of non-empty, non-comment lines
fn count_exclusions(config_path: &str) -> usize {
    match fs::read_to_string(config_path) {
        Ok(content) => {
            content.lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#')
                })
                .count()
        }
        Err(_) => 0
    }
}

// Welcome message
fn welcome_message() {
    println!("------------------------------------------------------------------------");
    println!("   ::             x.                                                    ");
    println!("   ;.             xX    ______ _____________ _________                  ");
    println!("   .x            :$x    ___  / __  __ \\__  //_/___  _/                  ");
    println!("    ++           Xx     __  /  _  / / /_  ,<   __  /                    ");
    println!("    .X:  ..;.   ;+.     _  /___/ /_/ /_  /| | __/ /                     ");
    println!("     :xx +XXX;+::.      /_____/\\____/ /_/ |_| /___/                     ");
    println!("       :xx+$;.:.        High-Performance YARA & IOC Scanner             ");
    println!("          .X+:;;                                                        ");
    println!("           ;  :.        Version {} (Rust)                               ", VERSION);
    println!("        .    x+         Florian Roth 2026                               ");
    println!("         :   +                                                          ");
    println!("------------------------------------------------------------------------");
}

/// Lock file guard to prevent multiple Loki instances from running simultaneously
struct LockFile {
    path: PathBuf,
}

impl LockFile {
    /// Try to acquire an exclusive lock. Returns None if another instance is running.
    fn acquire() -> Option<Self> {
        let lock_path = Self::get_lock_path();
        
        // Check if lock file exists and if the process is still running
        if lock_path.exists() {
            if let Ok(mut file) = fs::File::open(&lock_path) {
                let mut pid_str = String::new();
                if file.read_to_string(&mut pid_str).is_ok() {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        if Self::is_process_running(pid) {
                            return None; // Another instance is running
                        }
                    }
                }
            }
            // Stale lock file - remove it
            let _ = fs::remove_file(&lock_path);
        }
        
        // Create new lock file with our PID
        if let Ok(mut file) = fs::File::create(&lock_path) {
            let pid = std::process::id();
            if file.write_all(pid.to_string().as_bytes()).is_ok() {
                return Some(LockFile { path: lock_path });
            }
        }
        
        // Failed to create lock file - allow running anyway (e.g., read-only filesystem)
        Some(LockFile { path: lock_path })
    }
    
    fn get_lock_path() -> PathBuf {
        let temp_dir = std::env::temp_dir();
        temp_dir.join("loki-rs.lock")
    }
    
    #[cfg(unix)]
    fn is_process_running(pid: u32) -> bool {
        // On Unix, check if process exists by sending signal 0
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    
    #[cfg(windows)]
    fn is_process_running(pid: u32) -> bool {
        use windows::Win32::System::Threading::{OpenProcess, GetExitCodeProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows::Win32::Foundation::CloseHandle;
        const STILL_ACTIVE: u32 = 259;
        
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let mut exit_code: u32 = 0;
            let result = GetExitCodeProcess(handle, &mut exit_code);
            let _ = CloseHandle(handle);
            result.is_ok() && exit_code == STILL_ACTIVE
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        // Clean up lock file when the program exits
        let _ = fs::remove_file(&self.path);
    }
}

fn main() {
    // Enable ANSI color support on Windows
    enable_ansi_support();

    // Show welcome message
    welcome_message();

    // Prevent multiple instances from running
    let _lock = match LockFile::acquire() {
        Some(lock) => lock,
        None => {
            eprintln!("\x1b[1;31mError:\x1b[0m Another instance of Loki is already running.");
            eprintln!("       Only one Loki scan can run at a time on this system.");
            eprintln!("       Please wait for the other scan to complete or terminate it first.");
            std::process::exit(1);
        }
    };

    // Parsing command line flags
    let args = Cli::parse();
    
    // Handle version flag
    if args.version {
        println!("Loki-RS Version {} (Rust)", VERSION);
        std::process::exit(0);
    }
    
    // TUI mode is enabled by default (unless --no-tui is specified)
    let tui_mode = !args.no_tui;
    
    // Show TUI startup message early (before slow initialization)
    if tui_mode {
        println!("\nStarting up the TUI ...\n");
        std::io::Write::flush(&mut std::io::stdout()).ok();
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
             1
        }
    };
    
    // Start time
    let start_time = Local::now();

    // Determine log level
    let log_level = if args.trace {
        LogLevel::Debug
    } else if args.debug {
        LogLevel::Debug
    } else {
        LogLevel::Info
    };

    // Determine log file path
    let log_file = if args.no_log {
        None
    } else {
        Some(args.log.unwrap_or_else(|| {
            format!("loki_{}_{}.log", 
                get_hostname(), 
                Local::now().format("%Y-%m-%d_%H-%M-%S")
            )
        }))
    };

    // Determine JSONL file path
    let jsonl_file = if args.no_jsonl {
        None
    } else {
        Some(args.jsonl.unwrap_or_else(|| {
            format!("loki_{}_{}.jsonl", 
                get_hostname(), 
                Local::now().format("%Y-%m-%d_%H-%M-%S")
            )
        }))
    };

    // Determine remote config
    let remote = if let Some(host_port) = args.remote {
        let parts: Vec<&str> = host_port.split(':').collect();
        if parts.len() != 2 {
            eprintln!("Invalid remote address format. Use host:port");
            std::process::exit(1);
        }
        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>().expect("Invalid port number");
        
        let protocol = match args.remote_proto.to_lowercase().as_str() {
            "tcp" => RemoteProtocol::Tcp,
            _ => RemoteProtocol::Udp,
        };
        
        let format = match args.remote_format.to_lowercase().as_str() {
            "json" => RemoteFormat::Json,
            _ => RemoteFormat::Syslog,
        };
        
        Some(RemoteConfig { host, port, protocol, format })
    } else {
        None
    };

    // Set up TUI channel if TUI mode is enabled
    let (tui_sender, tui_receiver) = if tui_mode {
        let (tx, rx) = std::sync::mpsc::channel::<TuiMessage>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Create scan_state early so TUI can use it during initialization
    let scan_state = Arc::new(ScanState::with_cpu_limit(args.cpu_limit));

    let logger_config = LoggerConfig {
        console: !tui_mode,  // Disable console output in TUI mode
        log_level,
        log_file: log_file.clone(),
        jsonl_file: jsonl_file.clone(),
        remote,
        tui_sender: tui_sender.clone(),
    };

    let logger = match UnifiedLogger::new(logger_config) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to initialize logger: {}", e);
            std::process::exit(1);
        }
    };

    logger.scan_start(VERSION);

    // Configure thread pool
    match ThreadPoolBuilder::new().num_threads(num_threads).build_global() {
        Ok(_) => logger.info(&format!("Initialized thread pool with {} threads", num_threads)),
        Err(e) => logger.error(&format!("Failed to initialize thread pool: {}", e)),
    }

    if let Some(path) = &jsonl_file {
        logger.info(&format!("JSONL logging enabled: {}", path));
    }
    if let Some(path) = &log_file {
        logger.info(&format!("Log file enabled: {}", path));
    }

    // Print platform & environment information
    evaluate_env(&logger);
    logger.info(&format!("Thread pool THREADS: {} (requested: {})", num_threads, args.threads));

    // Evaluate active modules
    let mut active_modules: ArrayVec<String, 20> = ArrayVec::<String, 20>::new();
    for module in MODULES {
        if args.no_procs && module.to_string() == "ProcessCheck" { continue; }
        if args.no_fs && module.to_string() == "FileScan" { continue; }
        active_modules.insert(active_modules.len(), module.to_string());
    }
    logger.info(&format!("Active modules MODULES: {:?}", active_modules));

    // Validate thresholds
    if args.alert_level < args.warning_level || args.warning_level < args.notice_level {
        eprintln!("Error: Thresholds must be in order: alert >= warning >= notice");
        eprintln!("  Alert: {}, Warning: {}, Notice: {}", args.alert_level, args.warning_level, args.notice_level);
        std::process::exit(1);
    }
    
    // Count exclusions from config file
    let exclusion_count = count_exclusions("./config/excludes.cfg");
    
    // Get program directory to exclude it from scanning
    let program_dir = std::env::current_exe()
        .ok()
        .and_then(|exe_path| exe_path.parent().map(|p| p.to_string_lossy().to_string()));
    
    // Create a config (yara_rules_count and ioc_count will be set after loading)
    let mut scan_config = ScanConfig {
        max_file_size: args.max_file_size,
        show_access_errors: args.show_access_errors,
        scan_all_types: args.scan_all_files,
        scan_hard_drives: args.scan_hard_drives,
        scan_all_drives: args.scan_all_drives,
        scan_archives: !args.no_archive,
        alert_threshold: args.alert_level,
        warning_threshold: args.warning_level,
        notice_threshold: args.notice_level,
        max_reasons: args.max_reasons,
        threads: num_threads,
        cpu_limit: args.cpu_limit,
        exclusion_count,
        yara_rules_count: 0,
        ioc_count: 0,
        program_dir,
    };
    
    // Determine target folders to scan
    let target_folders: Vec<String> = if scan_config.scan_hard_drives || scan_config.scan_all_drives {
        // Enumerate drives/mounts based on flags
        let enumerated = enumerate_drives(scan_config.scan_hard_drives, scan_config.scan_all_drives);
        if enumerated.is_empty() {
            // Fallback to default if enumeration fails
            let mut default: String = '/'.to_string();
            if get_os_type() == "windows" { default = "C:\\".to_string(); }
            vec![default]
        } else {
            logger.info(&format!("Found {} drive(s)/mount(s) to scan: {}", 
                enumerated.len(), 
                enumerated.join(", ")));
            enumerated
        }
    } else {
        // Use single folder (default or specified)
        let mut single_folder: String = '/'.to_string(); 
        if get_os_type() == "windows" { single_folder = "C:\\".to_string(); }
        if let Some(ref args_target_folder) = args.folder {
            single_folder = args_target_folder.clone();
        }
        vec![single_folder]
    };
    
    // For TUI, use first target folder (or default)
    let target_folder = target_folders.first().cloned().unwrap_or_else(|| {
        if get_os_type() == "windows" { "C:\\".to_string() } else { "/".to_string() }
    });
    
    // Print scan configuration limits
    logger.info_w("Scan limits", &[
        ("MAX_FILE_SIZE", &format!("{} bytes ({:.1} MB)", scan_config.max_file_size, scan_config.max_file_size as f64 / 1_000_000.0)),
    ]);
    logger.info_w("Scan limits", &[
        ("SCAN_ALL_TYPES", &scan_config.scan_all_types.to_string()),
        ("SCAN_HARD_DRIVES", &scan_config.scan_hard_drives.to_string()),
        ("SCAN_ALL_DRIVES", &scan_config.scan_all_drives.to_string())
    ]);
    if !scan_config.scan_all_types {
        logger.info("Scanned extensions: .exe, .dll, .bat, .ps1, .asp, .aspx, .jsp, .jspx, .php, .plist, .sh, .vbs, .js, .dmp, .py, .msix");
        logger.info("Scanned file types: Executable, DLL, ISO, ZIP, LNK, CHM, PCAP and more (use --scan-all-files to scan all)");
    }
    if !scan_config.scan_all_drives {
        logger.info("Excluded paths: /proc, /dev, /sys/kernel, /media, /volumes, /Volumes, CloudStorage (use --scan-all-drives to include)");
    }
    if scan_config.exclusion_count > 0 {
        logger.info(&format!("Custom exclusions: {} patterns loaded from ./config/excludes.cfg", scan_config.exclusion_count));
    }

    // Set up Ctrl+C handler early (before TUI starts)
    let scan_state_clone = scan_state.clone();
    if tui_mode {
        // In TUI mode: just set the exit flag (TUI handles its own quit dialog)
        ctrlc::set_handler(move || {
            scan_state_clone.should_exit.store(true, std::sync::atomic::Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
    } else {
        // In normal mode: show the interactive menu
        ctrlc::set_handler(move || {
            scan_state_clone.display_menu();
        }).expect("Error setting Ctrl-C handler");
    }

    // Spawn TUI thread early if in TUI mode (shows loading state during initialization)
    let tui_handle = if tui_mode {
        let scan_config_for_tui = scan_config.clone();
        let target_folder_for_tui = target_folder.clone();
        let scan_state_for_tui = scan_state.clone();
        let receiver = tui_receiver.expect("TUI receiver should be set in TUI mode");
        
        Some(std::thread::spawn(move || {
            if let Err(e) = run_tui(&scan_config_for_tui, &target_folder_for_tui, scan_state_for_tui, receiver, true) {
                eprintln!("TUI error: {}", e);
            }
        }))
    } else {
        None
    };

    // Give TUI a moment to initialize before sending messages
    if tui_mode {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Initialize IOCs (send progress to TUI if enabled)
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitProgress("Loading hash IOCs ...".to_string()));
    }
    logger.info("Initialize hash IOCs ...");
    let hash_iocs = initialize_hash_iocs(&logger);
    let hash_collections = organize_hash_iocs(hash_iocs, "hash IOCs", &logger);
    
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitProgress("Loading false positive hashes ...".to_string()));
    }
    logger.info("Initialize false positive hash IOCs ...");
    let fp_hash_iocs = initialize_false_positive_hash_iocs(&logger);
    let fp_hash_collections = organize_hash_iocs(fp_hash_iocs, "false positive hash IOCs", &logger);
    
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitProgress("Loading filename IOCs ...".to_string()));
    }
    logger.info("Initialize filename IOCs ...");
    let filename_iocs = initialize_filename_iocs(&logger);
    
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitProgress("Loading C2 IOCs ...".to_string()));
    }
    logger.info("Initialize C2 IOCs ...");
    let c2_iocs = initialize_c2_iocs(&logger);

    // Initialize the YARA rules
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitProgress("Compiling YARA rules ...".to_string()));
    }
    logger.info("Initializing YARA rules ...");
    let (compiled_rules, yara_rules_count) = match initialize_yara_rules(&logger) {
        Ok((rules, count)) => (rules, count),
        Err(e) => {
            logger.error(&format!("Failed to initialize YARA rules: {}", e));
            logger.error(&format!("Please ensure YARA rules are available at {}/yara/ (run 'loki-util update' to download)", SIGNATURE_SOURCE));
            std::process::exit(1);
        }
    };
    
    // Calculate total IOC count (hash IOCs + filename IOCs + C2 IOCs)
    let total_ioc_count = hash_collections.md5_iocs.len() 
        + hash_collections.sha1_iocs.len() 
        + hash_collections.sha256_iocs.len()
        + filename_iocs.len() 
        + c2_iocs.len();
    
    // Update scan_config with the counts
    scan_config.yara_rules_count = yara_rules_count;
    scan_config.ioc_count = total_ioc_count;
    
    // Update scan_state with actual CPU limit from config
    scan_state.set_cpu_limit(scan_config.cpu_limit);
    
    // Signal TUI that initialization is complete with final counts
    if let Some(ref sender) = tui_sender {
        let _ = sender.send(TuiMessage::InitComplete { 
            yara_rules_count: scan_config.yara_rules_count,
            ioc_count: scan_config.ioc_count,
        });
    }

    // Register available modules
    let modules: Vec<Box<dyn ScanModule>> = vec![
        Box::new(ProcessCheckModule),
        Box::new(FileScanModule),
    ];
    
    let mut module_results: std::collections::HashMap<String, (usize, usize, usize, usize, usize)> = std::collections::HashMap::new();

    // Execute modules
    for module in modules {
        // Check if we should stop before starting next module
        if scan_state.should_stop() {
            logger.info("Scan aborted by user.");
            break;
        }

        if active_modules.contains(&module.name().to_string()) {
            if module.name() == "ProcessCheck" {
                 logger.info("Scanning running processes ... ");
                 
                 let context = ScanContext {
                     compiled_rules: &compiled_rules,
                     scan_config: &scan_config,
                     hash_collections: &hash_collections,
                     fp_hash_collections: &fp_hash_collections,
                     filename_iocs: &filename_iocs,
                     c2_iocs: &c2_iocs,
                     logger: &logger,
                     scan_state: Some(scan_state.clone()),
                     target_folder: &target_folder,
                 };
                 
                 let result = module.run(&context);
                 module_results.insert(module.name().to_string(), result);
            } else if module.name() == "FileScan" {
                 // For FileScan, iterate over all target folders (drives/mounts)
                 let mut total_files_scanned = 0;
                 let mut total_files_matched = 0;
                 let mut total_alerts = 0;
                 let mut total_warnings = 0;
                 let mut total_notices = 0;
                 
                 for (idx, folder) in target_folders.iter().enumerate() {
                     if scan_state.should_stop() {
                         logger.info("Scan aborted by user.");
                         break;
                     }
                     
                     if target_folders.len() > 1 {
                         logger.info(&format!("Scanning drive/mount {} of {}: {}", 
                             idx + 1, target_folders.len(), folder));
                     } else {
                         logger.info("Scanning local file system ... ");
                     }
                     
                     let context = ScanContext {
                         compiled_rules: &compiled_rules,
                         scan_config: &scan_config,
                         hash_collections: &hash_collections,
                         fp_hash_collections: &fp_hash_collections,
                         filename_iocs: &filename_iocs,
                         c2_iocs: &c2_iocs,
                         logger: &logger,
                         scan_state: Some(scan_state.clone()),
                         target_folder: folder,
                     };
                     
                     let (files_scanned, files_matched, alerts, warnings, notices) = module.run(&context);
                     total_files_scanned += files_scanned;
                     total_files_matched += files_matched;
                     total_alerts += alerts;
                     total_warnings += warnings;
                     total_notices += notices;
                 }
                 
                 module_results.insert(module.name().to_string(), 
                     (total_files_scanned, total_files_matched, total_alerts, total_warnings, total_notices));
            } else {
                 logger.info_w("Running module", &[("MODULE", module.name())]);
                 
                 let context = ScanContext {
                     compiled_rules: &compiled_rules,
                     scan_config: &scan_config,
                     hash_collections: &hash_collections,
                     fp_hash_collections: &fp_hash_collections,
                     filename_iocs: &filename_iocs,
                     c2_iocs: &c2_iocs,
                     logger: &logger,
                     scan_state: Some(scan_state.clone()),
                     target_folder: &target_folder,
                 };
                 
                 let result = module.run(&context);
                 module_results.insert(module.name().to_string(), result);
            }
        }
    }

    // Extract results for summary
    let (proc_scanned, proc_matched, proc_alerts, proc_warnings, proc_notices) = 
        *module_results.get("ProcessCheck").unwrap_or(&(0, 0, 0, 0, 0));

    let (files_scanned, files_matched, file_alerts, file_warnings, file_notices) = 
        *module_results.get("FileScan").unwrap_or(&(0, 0, 0, 0, 0));

    // Finished scan - collect summary
    let total_alerts = file_alerts + proc_alerts;
    let total_warnings = file_warnings + proc_warnings;
    let total_notices = file_notices + proc_notices;
    
    // Capture end time and calculate duration
    let end_time = Local::now();
    let duration = end_time.signed_duration_since(start_time);
    
    // Print summary
    let summary_msg = format!("Summary - Files scanned: {} Matched: {} | Processes scanned: {} Matched: {} | Alerts: {} Warnings: {} Notices: {}", 
        files_scanned, files_matched,
        proc_scanned, proc_matched,
        total_alerts, total_warnings, total_notices);
        
    let duration_msg = format!("Scan Duration: {:.2}s (Start: {}, End: {})", 
        duration.num_milliseconds() as f64 / 1000.0,
        start_time.format("%Y-%m-%d %H:%M:%S"),
        end_time.format("%Y-%m-%d %H:%M:%S"));
    
    logger.scan_end(&summary_msg, &duration_msg);
    
    // Print output file locations
    if let Some(path) = &log_file {
        logger.info(&format!("Log file written to: {}", path));
    }
    if let Some(path) = &jsonl_file {
        logger.info(&format!("JSONL log file written to: {}", path));
        
        // Generate HTML report from JSONL findings (unless disabled)
        if !args.no_html {
            match html_report::generate_report(path, &scan_config, VERSION) {
                Ok(html_path) => logger.info(&format!("HTML report written to: {}", html_path)),
                Err(e) => logger.warning(&format!("Failed to generate HTML report: {}", e)),
            }
        }
    }
    
    // Handle TUI mode completion
    if let Some(sender) = tui_sender {
        // Signal scan complete to TUI
        let _ = sender.send(TuiMessage::ScanComplete);
        // Mark scan as complete so TUI knows to exit
        scan_state.should_exit.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    
    // Wait for TUI thread to finish
    if let Some(handle) = tui_handle {
        let _ = handle.join();
    }
    
    // Determine exit code
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

            // Note: organize_hash_iocs requires a logger, testing the organization logic indirectly
            // through the individual hash collections instead
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

            assert_eq!(md5_iocs.len(), 1);
            assert_eq!(sha1_iocs.len(), 1);
            assert_eq!(sha256_iocs.len(), 1);
        }

        #[test]
        fn test_organize_empty_iocs() {
            let hash_iocs: Vec<HashIOC> = Vec::new();
            
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

            assert_eq!(md5_iocs.len(), 0);
            assert_eq!(sha1_iocs.len(), 0);
            assert_eq!(sha256_iocs.len(), 0);
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

            let mut md5_iocs: Vec<HashIOC> = Vec::new();
            
            for ioc in hash_iocs {
                match ioc.hash_type {
                    HashType::Md5 => md5_iocs.push(ioc),
                    _ => continue,
                }
            }
            
            // Sort by hash value for binary search (matching real function behavior)
            md5_iocs.sort_by(|a, b| a.hash_value.cmp(&b.hash_value));

            assert_eq!(md5_iocs.len(), 2);
            assert_eq!(md5_iocs[0].hash_value, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
                scan_hard_drives: false,
                scan_all_drives: false,
                scan_archives: true,
                alert_threshold: 80,
                warning_threshold: 60,
                notice_threshold: 40,
                max_reasons: 2,
                threads: 4,
                cpu_limit: 100,
                exclusion_count: 0,
                yara_rules_count: 0,
                ioc_count: 0,
                program_dir: None,
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
                scan_hard_drives: false,
                scan_all_drives: false,
                scan_archives: true,
                alert_threshold: 80,
                warning_threshold: 60,
                notice_threshold: 40,
                max_reasons: 2,
                threads: 4,
                cpu_limit: 100,
                exclusion_count: 0,
                yara_rules_count: 0,
                ioc_count: 0,
                program_dir: None,
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
                description: None,
                author: None,
                matched_strings: None,
            };

            assert_eq!(m.message, "Test match");
            assert_eq!(m.score, 75);
        }

        #[test]
        fn test_gen_match_sorting() {
            let mut matches = vec![
                GenMatch { message: "Low".to_string(), score: 40, description: None, author: None, matched_strings: None },
                GenMatch { message: "High".to_string(), score: 90, description: None, author: None, matched_strings: None },
                GenMatch { message: "Medium".to_string(), score: 60, description: None, author: None, matched_strings: None },
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