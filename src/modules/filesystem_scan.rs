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
use walkdir::WalkDir;
use yara_x::{Scanner, Rules};

use crate::{ScanConfig, GenMatch, HashIOCCollections, FalsePositiveHashCollections, ExtVars, YaraMatch, FilenameIOC, find_hash_ioc};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::jsonl_logger::{JsonlLogger, MatchReason};

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

// Scan a given file system path
pub fn scan_path (
    target_folder: String, 
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    hash_collections: &HashIOCCollections,
    fp_hash_collections: &FalsePositiveHashCollections,
    filename_iocs: &Vec<FilenameIOC>,
    jsonl_logger: Option<&JsonlLogger>) -> (usize, usize, usize, usize, usize) {
    // Returns: (files_scanned, files_matched, alerts, warnings, notices)
    let mut files_scanned = 0;
    let mut files_matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;

    // Determine if we should exclude mounted devices
    let exclude_mounted = !scan_config.scan_all_drives;
    
    // Walk the file system (don't follow symlinks to match v1 behavior)
    let mut it = WalkDir::new(&target_folder)
        .follow_links(false)  // Match v1 behavior: followlinks=False
        .into_iter();
    loop {
        // Error handling
        let entry = match it.next() {
            None => break,
            Some(Err(err)) => {
                log::debug!("Cannot access file system object ERROR: {:?}", err);
                continue;
            },
            Some(Ok(entry)) => entry,
        };
        
        let file_path = entry.path();
        let file_path_str = file_path.to_string_lossy();
        
        // Platform-specific path exclusions (Linux/Mac)
        if cfg!(unix) {
            // Check start-of-path exclusions
            let mut should_skip = false;
            for skip_path in LINUX_PATH_SKIPS_START.iter() {
                if file_path_str.starts_with(skip_path) {
                    log::trace!("Skipping excluded path (start) FILE: {} MATCH: {}", file_path_str, skip_path);
                    should_skip = true;
                    break;
                }
            }
            
            // Check mounted devices (if not --scan-all-drives)
            if exclude_mounted {
                for skip_path in MOUNTED_DEVICES.iter() {
                    if file_path_str.starts_with(skip_path) {
                        log::trace!("Skipping mounted device FILE: {} MATCH: {}", file_path_str, skip_path);
                        should_skip = true;
                        break;
                    }
                }
            }
            
            // Check end-of-path exclusions
            for skip_path in LINUX_PATH_SKIPS_END.iter() {
                if file_path_str.ends_with(skip_path) {
                    log::trace!("Skipping excluded path (end) FILE: {} MATCH: {}", file_path_str, skip_path);
                    should_skip = true;
                    break;
                }
            }
            
            if should_skip {
                it.skip_current_dir();
                continue;
            }
        }
        
        // Skip certain drives and folders (macOS/Windows)
        for skip_dir_value in ALL_DRIVE_EXCLUDES.iter() {
            if file_path_str.contains(skip_dir_value) {
                it.skip_current_dir();
                break;
            }
        }
        
        // Skip all elements that aren't files
        if !entry.path().is_file() { 
            log::trace!("Skipped element that isn't a file ELEMENT: {}", entry.path().display());
            continue;
        };
        // Skip big files
        let metadata_result = entry.path().symlink_metadata();
        let metadata = match metadata_result {
            Ok(metadata) => metadata,
            Err(e) => { if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e) }; continue; }
        };
        let realsize_result = entry.path().size_on_disk_fast(&metadata);
        let realsize = match realsize_result {
            Ok(realsize) => realsize,
            Err(e) => { if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e) }; continue; }
        };
        if realsize > scan_config.max_file_size as u64 || metadata.len() > scan_config.max_file_size as u64 { 
            log::trace!("Skipping file due to size FILE: {} SIZE: {} LOGICAL_SIZE: {} MAX_FILE_SIZE: {}", 
            entry.path().display(), realsize, metadata.len(), scan_config.max_file_size);
            continue; 
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
            continue; 
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
                if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e); }
                else { log::debug!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e); }
                continue; // skip the rest of the analysis 
            }
        };
        let mmap = match unsafe { MmapOptions::new().map(file_handle) } {
            Ok(m) => m,
            Err(e) => {
                if scan_config.show_access_errors {
                    log::error!("Cannot memory-map file FILE: {:?} ERROR: {:?}", entry.path(), e);
                } else {
                    log::debug!("Cannot memory-map file FILE: {:?} ERROR: {:?}", entry.path(), e);
                }
                continue; // Skip this file
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
            continue; // Skip this file entirely
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
        if sample_matches.len() > 0 {
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
                continue;
            };
            
            // Limit reasons shown
            let reasons_to_show = std::cmp::min(sample_matches.len(), scan_config.max_reasons);
            let shown_reasons: Vec<&GenMatch> = sample_matches.iter().take(reasons_to_show).collect();
            
            // Format output
            let mut output = format!("FILE: {}\n      SCORE: {:.0} TYPE: {} SIZE: {}\n", 
                entry.path().display(),
                total_score.round(),
                file_format_desc,
                realsize);
            
            // Add hash info
            output.push_str(&format!("      MD5: {}\n      SHA1: {}\n      SHA256: {}\n", 
                sample_info.md5, sample_info.sha1, sample_info.sha256));
            
            // Add reasons
            for (i, reason) in shown_reasons.iter().enumerate() {
                output.push_str(&format!("      REASON_{}: {}\n         SUBSCORE: {}\n", i + 1, reason.message, reason.score));
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
