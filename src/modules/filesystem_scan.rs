use std::{fs};
use std::time::{UNIX_EPOCH};
use arrayvec::ArrayVec;
use filesize::PathExt;
use file_format::FileFormat;
use chrono::offset::Utc;
use chrono::prelude::*;
use sha2::{Sha256, Digest};
use sha1::*;
use memmap2::MmapOptions;
use walkdir::{WalkDir, DirEntry};
use yara_x::{Scanner, Rules};
use rayon::prelude::*;
use colored::*;

#[cfg(windows)]
use windows::core::{PCWSTR, HSTRING};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, DRIVE_REMOTE, DRIVE_NO_ROOT_DIR};

use crate::{ScanConfig, GenMatch, HashIOCCollections, FalsePositiveHashCollections, ExtVars, YaraMatch, FilenameIOC, find_hash_ioc};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::jsonl_logger::{JsonlLogger, MatchReason};
use crate::helpers::remote_logger::RemoteLogger;
use crate::helpers::throttler::{init_thread_throttler, throttle_start, throttle_end};
use crate::helpers::helpers::log_access_error;

const REL_EXTS: &'static [&'static str] = &[".exe", ".dll", ".bat", ".ps1", ".asp", ".aspx", ".jsp", ".jspx", 
    ".php", ".plist", ".sh", ".vbs", ".js", ".dmp", ".py", ".msix"];
const FILE_TYPES: &'static [&'static str] = &[
    "Debian Binary Package",
    "Executable and Linkable Format",
    "Google Chrome Extension",
    "ISO 9660",
    // "Java Class", // buggy .. many other types get detected as Java Class
    "Microsoft Compiled HTML Help",
    "MS-DOS Executable",
    "PCAP Dump",
    "PCAP Next Generation Dump",
    "Windows Executable",
    "Windows Shortcut",
    "ZIP",
];  // see https://docs.rs/file-format/latest/file_format/index.html
const ALL_DRIVE_EXCLUDES: &'static [&'static str] = &[
    "/Library/CloudStorage/",
    "/Volumes/"
];

// Windows cloud storage paths
const WINDOWS_CLOUD_PATHS: &[&str] = &[
    "\\OneDrive",
    "\\Dropbox", 
    "\\Google Drive",
    "\\iCloudDrive",
    "\\Box",
    "\\Nextcloud",
    "\\Tresorit",
    "\\TresoritDrive",
    "\\Tresors",
    "\\pCloud",
    "\\MEGA",
    "\\Sync",
    "\\SpiderOak Hive",
    "\\Egnyte",
    "\\ShareFile",
    "\\Syncplicity Folders",
    "\\Seafile",
    "\\Resilio Sync",
    "\\Syncthing",
    "\\ownCloud",
];

// Unix cloud storage paths (in addition to existing ALL_DRIVE_EXCLUDES)
const UNIX_CLOUD_PATHS: &[&str] = &[
    "/OneDrive",
    "/Dropbox",
    "/.dropbox",
    "/Google Drive",
    "/Box",
    "/Nextcloud",
    "/Tresorit",
    "/TresoritDrive",
    "/Tresors",
    "/pCloud",
    "/MEGA",
    "/MEGAsync",
    "/Sync",
    "/SpiderOak Hive",
    "/Seafile",
    "/Resilio Sync",
    "/Syncthing",
    "/ownCloud",
    "/Koofr",
    "/Icedrive",
];

// Linux/Mac path exclusions (start of path)
const LINUX_PATH_SKIPS_START: &'static [&'static str] = &[
    "/proc",
    "/dev",
    "/sys/kernel/debug",
    "/sys/kernel/slab",
    "/sys/devices",
    "/usr/src/linux",
];

// Linux/Mac mounted devices (excluded unless --scan-all-drives)
const MOUNTED_DEVICES: &'static [&'static str] = &[
    "/media",
    "/volumes",
];

// Linux/Mac path exclusions (end of path)
const LINUX_PATH_SKIPS_END: &'static [&'static str] = &[
    "/initctl",
];

#[derive(Debug)]
struct SampleInfo {
    md5: String,
    sha1: String,
    sha256: String,
    #[allow(dead_code)]
    atime: String,
    #[allow(dead_code)]
    mtime: String,
    #[allow(dead_code)]
    ctime: String,
}

// Check if a path is likely a cloud storage folder
fn is_cloud_or_remote_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    
    // Windows checks
    if cfg!(windows) {
        for cloud_path in WINDOWS_CLOUD_PATHS {
            if path_lower.contains(&cloud_path.to_lowercase()) {
                return true;
            }
        }
    } else {
        // Unix checks
        for cloud_path in UNIX_CLOUD_PATHS {
            if path_lower.contains(&cloud_path.to_lowercase()) {
                return true;
            }
        }
    }
    
    false
}

// Check if a root path is a network drive (Windows only)
#[cfg(windows)]
fn is_network_drive(path: &str) -> bool {
    // Need a root path like "C:\" or "\\server\share"
    // If path is just a letter "C:", append backslash
    let root = if path.len() == 2 && path.chars().nth(1) == Some(':') {
        format!("{}\\", path)
    } else {
        path.to_string()
    };
    
    let h_root = HSTRING::from(&root);
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(h_root.as_ptr())) };
    
    // DRIVE_REMOTE = 4, DRIVE_NO_ROOT_DIR = 1
    drive_type == DRIVE_REMOTE || drive_type == DRIVE_NO_ROOT_DIR
}

#[cfg(not(windows))]
fn is_network_drive(_path: &str) -> bool {
    false
}

use crate::modules::{ScanModule, ScanContext, ModuleResult};

pub struct FileScanModule;

impl ScanModule for FileScanModule {
    fn name(&self) -> &'static str {
        "FileScan"
    }

    fn run(&self, context: &ScanContext) -> ModuleResult {
        scan_path(
            context.target_folder,
            context.compiled_rules,
            context.scan_config,
            context.hash_collections,
            context.fp_hash_collections,
            context.filename_iocs,
            context.jsonl_logger,
            context.remote_logger
        )
    }
}

// Scan a given file system path
pub fn scan_path (
    target_folder: &str, 
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    hash_collections: &HashIOCCollections,
    fp_hash_collections: &FalsePositiveHashCollections,
    filename_iocs: &Vec<FilenameIOC>,
    jsonl_logger: Option<&JsonlLogger>,
    remote_logger: Option<&RemoteLogger>) -> (usize, usize, usize, usize, usize) {
    
    let cpu_limit = scan_config.cpu_limit;
    
    // Check if target folder itself is on a network drive or cloud path
    // Only check if we are NOT scanning all drives explicitly
    if !scan_config.scan_all_drives {
        if is_network_drive(target_folder) {
            log::warn!("Skipping network drive TARGET: {}", target_folder);
            return (0, 0, 0, 0, 0);
        }
        
        if is_cloud_or_remote_path(target_folder) {
            log::warn!("Skipping cloud storage folder TARGET: {}", target_folder);
            return (0, 0, 0, 0, 0);
        }
    }
    
    // Walk the file system (don't follow symlinks to match v1 behavior)
    let walk = WalkDir::new(target_folder)
        .follow_links(false)  // Match v1 behavior: followlinks=False
        .into_iter();
        
    // Process files in parallel
    let (files_scanned, files_matched, alert_count, warning_count, notice_count) = walk.par_bridge()
        .map(|entry_res| {
            init_thread_throttler(cpu_limit);
            match entry_res {
                Ok(entry) => {
                    throttle_start();
                    let result = process_file_entry(
                        entry, 
                        compiled_rules, 
                        scan_config, 
                        hash_collections, 
                        fp_hash_collections, 
                        filename_iocs, 
                        jsonl_logger,
                        remote_logger
                    );
                    throttle_end();
                    result
                },
                Err(e) => {
                    log_access_error("fs_object", &e, scan_config.show_access_errors);
                    (0, 0, 0, 0, 0)
                }
            }
        })
        .reduce(
            || (0, 0, 0, 0, 0),
            |a, b| (
                a.0 + b.0,
                a.1 + b.1,
                a.2 + b.2,
                a.3 + b.3,
                a.4 + b.4
            )
        );
            
    // Return summary statistics
    (files_scanned, files_matched, alert_count, warning_count, notice_count)
}

fn process_file_entry(
    entry: DirEntry,
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    hash_collections: &HashIOCCollections,
    fp_hash_collections: &FalsePositiveHashCollections,
    filename_iocs: &Vec<FilenameIOC>,
    jsonl_logger: Option<&JsonlLogger>,
    remote_logger: Option<&RemoteLogger>
) -> (usize, usize, usize, usize, usize) {
    let mut files_scanned = 0;
    let mut files_matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;

    let file_path = entry.path();
    let file_path_str = file_path.to_string_lossy();
    
    // Determine if we should exclude mounted devices
    let exclude_mounted = !scan_config.scan_all_drives;

    // Cloud/Network exclusions (skip if path contains cloud keywords)
    if exclude_mounted && is_cloud_or_remote_path(&file_path_str) {
        log::trace!("Skipping cloud storage path FILE: {}", file_path_str);
        return (0, 0, 0, 0, 0);
    }

    // Platform-specific path exclusions (Linux/Mac)
    if cfg!(unix) {
        // Check start-of-path exclusions
        for skip_path in LINUX_PATH_SKIPS_START.iter() {
            if file_path_str.starts_with(skip_path) {
                log::trace!("Skipping excluded path (start) FILE: {} MATCH: {}", file_path_str, skip_path);
                return (0, 0, 0, 0, 0);
            }
        }
        
        // Check mounted devices (if not --scan-all-drives)
        if exclude_mounted {
            for skip_path in MOUNTED_DEVICES.iter() {
                if file_path_str.starts_with(skip_path) {
                    log::trace!("Skipping mounted device FILE: {} MATCH: {}", file_path_str, skip_path);
                    return (0, 0, 0, 0, 0);
                }
            }
        }
        
        // Check end-of-path exclusions
        for skip_path in LINUX_PATH_SKIPS_END.iter() {
            if file_path_str.ends_with(skip_path) {
                log::trace!("Skipping excluded path (end) FILE: {} MATCH: {}", file_path_str, skip_path);
                return (0, 0, 0, 0, 0);
            }
        }
    }
    
    // Skip certain drives and folders (macOS/Windows)
    for skip_dir_value in ALL_DRIVE_EXCLUDES.iter() {
        if file_path_str.contains(skip_dir_value) {
            return (0, 0, 0, 0, 0);
        }
    }
    
    // Skip all elements that aren't files
    if !entry.path().is_file() { 
        log::trace!("Skipped element that isn't a file ELEMENT: {}", entry.path().display());
        return (0, 0, 0, 0, 0);
    };
    // Skip big files
    let metadata_result = entry.path().symlink_metadata();
    let metadata = match metadata_result {
        Ok(metadata) => metadata,
        Err(e) => { 
            log_access_error(&file_path_str, &e, scan_config.show_access_errors);
            return (0, 0, 0, 0, 0);
        }
    };
    let realsize_result = entry.path().size_on_disk_fast(&metadata);
    let realsize = match realsize_result {
        Ok(realsize) => realsize,
        Err(e) => { 
            log_access_error(&file_path_str, &e, scan_config.show_access_errors);
            return (0, 0, 0, 0, 0);
        }
    };
    if realsize > scan_config.max_file_size as u64 || metadata.len() > scan_config.max_file_size as u64 { 
        log::trace!("Skipping file due to size FILE: {} SIZE: {} LOGICAL_SIZE: {} MAX_FILE_SIZE: {}", 
        entry.path().display(), realsize, metadata.len(), scan_config.max_file_size);
        return (0, 0, 0, 0, 0); 
    }
    // Skip certain file types
    let extension_raw = entry.path().extension().unwrap_or_default().to_str().unwrap();
    // Keep extension for later use (without dot)
    let extension = extension_raw;
    
    let file_format = FileFormat::from_file(entry.path()).unwrap_or_default();
    let file_format_desc = file_format.to_owned().to_string();
    let file_format_extension = file_format.name();

    // Check if file should be scanned based on:
    // 1. File type (magic header detection)
    // 2. File extension (with leading dot to match REL_EXTS format)
    // 3. scan_all_types flag
    let matches_file_type = FILE_TYPES.contains(&file_format_desc.as_str());
    let matches_extension = if extension_raw.is_empty() {
        false
    } else {
        let ext_with_dot = format!(".{}", extension_raw);
        REL_EXTS.contains(&ext_with_dot.as_str())
    };
    
    if !matches_file_type && !matches_extension && !scan_config.scan_all_types {
        log::trace!("Skipping file due to extension or type FILE: {} EXT: {:?} TYPE: {:?}", 
            entry.path().display(), extension_raw, file_format_desc);
        return (0, 0, 0, 0, 0);
    }

    // Debug output : show every file that gets scanned
    log::debug!("Scanning file {} TYPE: {:?}", entry.path().display(), file_format_desc);
    
    // Increment files scanned counter - file passed all filters
    files_scanned += 1;
    
    // ------------------------------------------------------------
    // VARS
    // Matches (all types)
    let mut sample_matches = ArrayVec::<GenMatch, 100>::new();

    // TIME STAMPS
    let metadata = fs::metadata(entry.path()).unwrap();
    let ts_m_result = &metadata.modified();
    let ts_a_result = &metadata.accessed();
    let ts_c_result = &metadata.created();
    let msecs = match ts_m_result {
        Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        Err(_) => 0u64,
    };
    let asecs = match ts_a_result {
        Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        Err(_) => 0u64,
    };
    let csecs = match ts_c_result {
        Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        Err(_) => 0u64,
    };
    let mtime = Utc.timestamp_opt(msecs as i64, 0).single().unwrap_or_else(|| Utc::now());
    let atime = Utc.timestamp_opt(asecs as i64, 0).single().unwrap_or_else(|| Utc::now());
    let ctime = Utc.timestamp_opt(csecs as i64, 0).single().unwrap_or_else(|| Utc::now());

    // ------------------------------------------------------------
    // READ FILE
    // Read file to data blob
    let result = fs::File::open(&entry.path());
    let file_handle = match &result {
        Ok(data) => data,
        Err(e) => { 
            log_access_error(&file_path_str, &e, scan_config.show_access_errors);
            return (files_scanned, 0, 0, 0, 0); // skip the rest of the analysis 
        }
    };
    let mmap = match unsafe { MmapOptions::new().map(file_handle) } {
        Ok(m) => m,
        Err(e) => {
            log_access_error(&file_path_str, &e, scan_config.show_access_errors);
            return (files_scanned, 0, 0, 0, 0); // Skip this file
        }
    };

    // ------------------------------------------------------------
    // IOC Matching

    // Filename Matching
    let file_path_str = entry.path().to_string_lossy();
    for fioc in filename_iocs.iter() {
        if !sample_matches.is_full() {
            // Check if pattern matches
            if fioc.regex.is_match(&file_path_str) {
                // Check false positive regex if present
                let is_false_positive = if let Some(ref fp_regex) = fioc.regex_fp {
                    fp_regex.is_match(&file_path_str)
                } else {
                    false
                };
                
                if !is_false_positive {
                    let match_message = format!("File Name IOC matched\n         PATTERN: {}\n         DESC: {}", 
                        fioc.pattern, fioc.description);
                    sample_matches.insert(
                        sample_matches.len(),
                        GenMatch {
                            message: match_message,
                            score: fioc.score
                        }
                    );
                    log::trace!("Filename IOC match FILE: {} PATTERN: {} SCORE: {}", 
                        file_path_str, fioc.pattern, fioc.score);
                } else {
                    log::trace!("Filename IOC match suppressed by false positive regex FILE: {} PATTERN: {}", 
                        file_path_str, fioc.pattern);
                }
            }
        }
    }

    // Hash Matching
    // Generate hashes
    let md5_value = format!("{:x}", md5::compute(&mmap));
    let sha1_hash_array = Sha1::new()
        .chain_update(&mmap)
        .finalize();
    let sha256_hash_array = Sha256::new()
        .chain_update(&mmap)
        .finalize();
    let sha1_value = hex::encode(&sha1_hash_array);
    let sha256_value = hex::encode(&sha256_hash_array);
    //let md5_hash = hex::encode(&md5_hash_array);
    log::trace!("Hashes of FILE: {:?} SHA256: {} SHA1: {} MD5: {}", entry.path(), sha256_value, sha1_value, md5_value);
    
    // Check false positive hashes first - if match, skip file entirely
    let is_false_positive = find_hash_ioc(&md5_value, &fp_hash_collections.md5_iocs).is_some()
        || find_hash_ioc(&sha1_value, &fp_hash_collections.sha1_iocs).is_some()
        || find_hash_ioc(&sha256_value, &fp_hash_collections.sha256_iocs).is_some();
    
    if is_false_positive {
        log::debug!("File skipped due to false positive hash match FILE: {:?}", entry.path());
        return (files_scanned, 0, 0, 0, 0); // Skip this file entirely
    }
    
    // Compare hashes with hash IOCs (using binary search)
    if !sample_matches.is_full() {
        // Binary search for MD5
        if let Some(hash_ioc) = find_hash_ioc(&md5_value, &hash_collections.md5_iocs) {
            let match_message = format!("HASH match with IOC\n         HASH: {}\n         DESC: {}", hash_ioc.hash_value, hash_ioc.description);
            sample_matches.insert(
                sample_matches.len(),
                GenMatch{message: match_message, score: hash_ioc.score}
            );
        }
        
        // Binary search for SHA1
        if let Some(hash_ioc) = find_hash_ioc(&sha1_value, &hash_collections.sha1_iocs) {
            let match_message = format!("HASH match with IOC\n         HASH: {}\n         DESC: {}", hash_ioc.hash_value, hash_ioc.description);
            sample_matches.insert(
                sample_matches.len(),
                GenMatch{message: match_message, score: hash_ioc.score}
            );
        }
        
        // Binary search for SHA256
        if let Some(hash_ioc) = find_hash_ioc(&sha256_value, &hash_collections.sha256_iocs) {
            let match_message = format!("HASH match with IOC\n         HASH: {}\n         DESC: {}", hash_ioc.hash_value, hash_ioc.description);
            sample_matches.insert(
                sample_matches.len(),
                GenMatch{message: match_message, score: hash_ioc.score}
            );
        }
    }
    
    // ------------------------------------------------------------
    // SAMPLE INFO 
    // Note: SampleInfo fields are kept for future use (logging, reporting)
    #[allow(dead_code)]
    let sample_info = SampleInfo {
        md5: md5_value,
        sha1: sha1_value,
        sha256: sha256_value,
        atime: atime.to_rfc3339(),
        mtime: mtime.to_rfc3339(),
        ctime: ctime.to_rfc3339(),
    };

    // ------------------------------------------------------------
    // YARA scanning
    // Preparing the external variables
    let ext_vars = ExtVars{
        filename: entry.path().file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        filepath: entry.path().parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        extension: extension.to_string(),
        filetype: file_format_extension.to_ascii_uppercase(),
        owner: "".to_string(),  // TODO
    };
    log::trace!("Passing external variables to the scan EXT_VARS: {:?}", ext_vars);
    // Actual scanning and result analysis
    let yara_matches = 
        scan_file(&compiled_rules, &mmap, scan_config, &ext_vars);
    for ymatch in yara_matches.iter() {
        if !sample_matches.is_full() {
            // Build match message with metadata
            let mut match_message = format!("YARA match with rule {}", ymatch.rulename);
            if !ymatch.description.is_empty() {
                match_message.push_str(&format!("\n         DESC: {}", ymatch.description));
            }
            if !ymatch.author.is_empty() {
                match_message.push_str(&format!("\n         AUTHOR: {}", ymatch.author));
            }
            if !ymatch.matched_strings.is_empty() {
                // Limit string matches to first 3 and truncate long strings
                let mut strings_display = Vec::new();
                for s in ymatch.matched_strings.iter().take(3) {
                    let truncated = if s.len() > 140 {
                        format!("{}...", &s[..137])
                    } else {
                        s.clone()
                    };
                    strings_display.push(truncated);
                }
                match_message.push_str(&format!("\n         STRINGS: {}", strings_display.join(" ")));
                if ymatch.matched_strings.len() > 3 {
                    match_message.push_str(&format!(" (and {} more)", ymatch.matched_strings.len() - 3));
                }
            }
            sample_matches.insert(
                sample_matches.len(), 
                GenMatch{message: match_message, score: ymatch.score}
            );
        }
    }
    // Scan Results
    if !sample_matches.is_empty() {
        // File has matches
        files_matched += 1;
        
        // Extract sub-scores for weighted calculation
        let sub_scores: Vec<i16> = sample_matches.iter().map(|m| m.score).collect();
        
        // Calculate weighted total score
        let total_score = calculate_weighted_score(&sub_scores);
        
        // Determine message level based on thresholds
        let message_level = if total_score >= scan_config.alert_threshold as f64 {
            alert_count += 1;
            "ALERT"
        } else if total_score >= scan_config.warning_threshold as f64 {
            warning_count += 1;
            "WARNING"
        } else if total_score >= scan_config.notice_threshold as f64 {
            notice_count += 1;
            "NOTICE"
        } else {
            // Below notice threshold, skip logging unless debug
            log::debug!("File match below notice threshold FILE: {} SCORE: {:.2}", 
                entry.path().display(), total_score);
            return (files_scanned, 0, 0, 0, 0);
        };
        
        // Limit reasons shown
        let reasons_to_show = std::cmp::min(sample_matches.len(), scan_config.max_reasons);
        let shown_reasons: Vec<&GenMatch> = sample_matches.iter().take(reasons_to_show).collect();
        
        // Format output
        let mut output = format!("FILE: {}\n      {}: {:.0} {}: {} {}: {}\n", 
            entry.path().display(),
            "SCORE".red(),
            total_score.round().to_string().white(),
            "TYPE".red(),
            file_format_desc.white(),
            "SIZE".red(),
            realsize.to_string().white());
        
        // Add hash info
        output.push_str(&format!("      {}: {}\n      {}: {}\n      {}: {}\n", 
            "MD5".red(), sample_info.md5.white(), 
            "SHA1".red(), sample_info.sha1.white(), 
            "SHA256".red(), sample_info.sha256.white()));
        
        // Add reasons
        for (i, reason) in shown_reasons.iter().enumerate() {
            output.push_str(&format!("      {}_{}: {}\n         {}: {}\n", 
                "REASON".red(), 
                i + 1, 
                reason.message.white(), 
                "SUBSCORE".red(), 
                reason.score.to_string().white()));
        }
        
        if sample_matches.len() > reasons_to_show {
            output.push_str(&format!("      (and {} more reasons)\n", sample_matches.len() - reasons_to_show));
        }
        
        // Log with appropriate level
        match message_level {
            "ALERT" => log::error!("{} {}", message_level, output),
            "WARNING" => log::warn!("{} {}", message_level, output),
            "NOTICE" => log::info!("{} {}", message_level, output),
            _ => log::debug!("{} {}", message_level, output),
        }
        
        // Write to JSONL if enabled
        if let Some(logger) = jsonl_logger {
            let jsonl_reasons: Vec<MatchReason> = shown_reasons.iter()
                .map(|r| MatchReason {
                    message: r.message.clone(),
                    score: r.score,
                })
                .collect();
            let _ = logger.log_file_match(
                message_level,
                &entry.path().to_string_lossy(),
                total_score,
                &file_format_desc,
                realsize,
                &sample_info.md5,
                &sample_info.sha1,
                &sample_info.sha256,
                jsonl_reasons,
            );
        }

        // Send to remote logger if enabled
        if let Some(logger) = remote_logger {
            let remote_reasons: Vec<MatchReason> = shown_reasons.iter()
                .map(|r| MatchReason {
                    message: r.message.clone(),
                    score: r.score,
                })
                .collect();
            logger.log_file_match(
                message_level,
                &entry.path().to_string_lossy(),
                total_score,
                &file_format_desc,
                &remote_reasons,
            );
        }
    }
    
    // Return summary statistics
    (files_scanned, files_matched, alert_count, warning_count, notice_count)
}

// scan a file
fn scan_file(rules: &Rules, file_content: &[u8], scan_config: &ScanConfig, ext_vars: &ExtVars) -> ArrayVec<YaraMatch, 100> {
    // YARA-X: Create scanner from rules
    let mut scanner = Scanner::new(rules);
    
    // Set timeout (in seconds)
    scanner.set_timeout(std::time::Duration::from_secs(10));
    
    // Define external variables (global variables in YARA-X)
    // YARA-X accepts strings directly for set_global
    if let Err(e) = scanner.set_global("filename", ext_vars.filename.as_str()) {
        log::debug!("Error setting filename global: {:?}", e);
    }
    if let Err(e) = scanner.set_global("filepath", ext_vars.filepath.as_str()) {
        log::debug!("Error setting filepath global: {:?}", e);
    }
    if let Err(e) = scanner.set_global("extension", ext_vars.extension.as_str()) {
        log::debug!("Error setting extension global: {:?}", e);
    }
    if let Err(e) = scanner.set_global("filetype", ext_vars.filetype.as_str()) {
        log::debug!("Error setting filetype global: {:?}", e);
    }
    if let Err(e) = scanner.set_global("owner", ext_vars.owner.as_str()) {
        log::debug!("Error setting owner global: {:?}", e);
    }
    
    // Scan file content directly (already in memory/mmap)
    let results = scanner.scan(file_content);
    
    // Handle scan results
    let mut yara_matches = ArrayVec::<YaraMatch, 100>::new();
    match results {
        Ok(scan_results) => {
            // YARA-X: Use matching_rules() to iterate over results
            for matching_rule in scan_results.matching_rules() {
                if !yara_matches.is_full() {
                    // Extract rule identifier
                    let rulename = matching_rule.identifier().to_string();
                    
                    // Extract metadata from rule
                    let mut description = String::new();
                    let mut author = String::new();
                    let mut score = 75; // Default score
                    
                    // Get rule metadata - YARA-X metadata() returns iterator of (key, MetaValue)
                    for (key, value) in matching_rule.metadata() {
                        match key {
                            "description" => {
                                // MetaValue is an enum, need to match on it
                                match value {
                                    yara_x::MetaValue::String(s) => description = s.to_string(),
                                    _ => {}
                                }
                            }
                            "author" => {
                                match value {
                                    yara_x::MetaValue::String(s) => author = s.to_string(),
                                    _ => {}
                                }
                            }
                            "score" => {
                                match value {
                                    yara_x::MetaValue::Integer(i) => {
                                        let s = i as i16;
                                        if s > 0 && s <= 100 {
                                            score = s;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    // Extract matched strings from patterns
                    let mut matched_strings: Vec<String> = Vec::new();
                    for pattern in matching_rule.patterns() {
                        for pattern_match in pattern.matches() {
                            let identifier = pattern.identifier();
                            let offset = pattern_match.range().start;
                            let data = pattern_match.data();
                            
                            // Format string match
                            let value_str = if data.iter().all(|&b| b.is_ascii() && (b >= 32 || b == 9 || b == 10 || b == 13)) {
                                match String::from_utf8(data.to_vec()) {
                                    Ok(s) => format!("'{}'", s),
                                    Err(_) => hex::encode(data)
                                }
                            } else {
                                hex::encode(data)
                            };
                            
                            matched_strings.push(format!("{}: {} @ {}", identifier, value_str, offset));
                        }
                    }
                    
                    log::debug!("YARA-X match found RULE: {} SCORE: {}", rulename, score);
                    
                    yara_matches.insert(
                        yara_matches.len(),
                        YaraMatch{
                            rulename: rulename,
                            score: score,
                            description: description,
                            author: author,
                            matched_strings: matched_strings,
                        }
                    );
                }
            }
        },
        Err(e) => { 
            if scan_config.show_access_errors { 
                log::error!("YARA-X scan error: {:?}", e); 
            } else {
                log::debug!("YARA-X scan error: {:?}", e);
            }
        }
    }
    return yara_matches;
}

#[cfg(test)]
mod tests {
    use super::*;

    mod extension_tests {
        use super::*;

        #[test]
        fn test_relevant_extensions_contains_exe() {
            assert!(REL_EXTS.contains(&".exe"));
        }

        #[test]
        fn test_relevant_extensions_contains_dll() {
            assert!(REL_EXTS.contains(&".dll"));
        }

        #[test]
        fn test_relevant_extensions_contains_ps1() {
            assert!(REL_EXTS.contains(&".ps1"));
        }

        #[test]
        fn test_relevant_extensions_contains_sh() {
            assert!(REL_EXTS.contains(&".sh"));
        }

        #[test]
        fn test_relevant_extensions_count() {
            assert!(REL_EXTS.len() >= 10);
        }
    }

    mod file_types_tests {
        use super::*;

        #[test]
        fn test_file_types_contains_windows_executable() {
            assert!(FILE_TYPES.contains(&"Windows Executable"));
        }

        #[test]
        fn test_file_types_contains_elf() {
            assert!(FILE_TYPES.contains(&"Executable and Linkable Format"));
        }

        #[test]
        fn test_file_types_contains_zip() {
            assert!(FILE_TYPES.contains(&"ZIP"));
        }
    }

    mod path_exclusion_tests {
        use super::*;

        #[test]
        fn test_linux_path_skips_proc() {
            assert!(LINUX_PATH_SKIPS_START.contains(&"/proc"));
        }

        #[test]
        fn test_linux_path_skips_dev() {
            assert!(LINUX_PATH_SKIPS_START.contains(&"/dev"));
        }

        #[test]
        fn test_linux_path_skips_sys_kernel_debug() {
            assert!(LINUX_PATH_SKIPS_START.contains(&"/sys/kernel/debug"));
        }

        #[test]
        fn test_mounted_devices_media() {
            assert!(MOUNTED_DEVICES.contains(&"/media"));
        }

        #[test]
        fn test_all_drive_excludes_cloud_storage() {
            assert!(ALL_DRIVE_EXCLUDES.contains(&"/Library/CloudStorage/"));
        }

        #[test]
        fn test_path_skip_matching_start() {
            let test_path = "/proc/1234/cmdline";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| test_path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_path_skip_matching_end() {
            let test_path = "/some/path/initctl";
            let should_skip = LINUX_PATH_SKIPS_END.iter().any(|skip| test_path.ends_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_regular_path_not_skipped() {
            let test_path = "/home/user/documents/file.txt";
            let should_skip_start = LINUX_PATH_SKIPS_START.iter().any(|skip| test_path.starts_with(skip));
            let should_skip_end = LINUX_PATH_SKIPS_END.iter().any(|skip| test_path.ends_with(skip));
            assert!(!should_skip_start);
            assert!(!should_skip_end);
        }
    }

    mod sample_info_tests {
        use super::*;

        #[test]
        fn test_sample_info_creation() {
            let info = SampleInfo {
                md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                atime: "2024-01-01T00:00:00Z".to_string(),
                mtime: "2024-01-01T00:00:00Z".to_string(),
                ctime: "2024-01-01T00:00:00Z".to_string(),
            };

            assert_eq!(info.md5.len(), 32);
            assert_eq!(info.sha1.len(), 40);
            assert_eq!(info.sha256.len(), 64);
        }
    }

    mod extension_matching_tests {
        use super::*;

        #[test]
        fn test_extension_match_with_dot() {
            let ext = "exe";
            let ext_with_dot = format!(".{}", ext);
            assert!(REL_EXTS.contains(&ext_with_dot.as_str()));
        }

        #[test]
        fn test_extension_match_ps1() {
            let ext = "ps1";
            let ext_with_dot = format!(".{}", ext);
            assert!(REL_EXTS.contains(&ext_with_dot.as_str()));
        }

        #[test]
        fn test_extension_no_match_txt() {
            let ext = "txt";
            let ext_with_dot = format!(".{}", ext);
            assert!(!REL_EXTS.contains(&ext_with_dot.as_str()));
        }

        #[test]
        fn test_extension_no_match_pdf() {
            let ext = "pdf";
            let ext_with_dot = format!(".{}", ext);
            assert!(!REL_EXTS.contains(&ext_with_dot.as_str()));
        }
    }
}
