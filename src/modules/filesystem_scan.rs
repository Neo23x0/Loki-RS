use std::{fs};
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::{UNIX_EPOCH};
use std::sync::Arc;
use arrayvec::ArrayVec;
use filesize::PathExt;
use file_format::FileFormat;
use chrono::offset::Utc;
use chrono::prelude::*;
use regex::Regex;
use sha2::{Sha256, Digest};
use sha1::*;
use memmap2::MmapOptions;
use walkdir::{WalkDir, DirEntry};
use yara_x::{Scanner, Rules};
use rayon::prelude::*;
use zip::ZipArchive;

#[cfg(windows)]
use windows::core::{PCWSTR, HSTRING};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

// Define constants manually to avoid import issues
#[cfg(windows)]
const DRIVE_UNKNOWN: u32 = 0;
#[cfg(windows)]
const DRIVE_NO_ROOT_DIR: u32 = 1;
#[cfg(windows)]
const DRIVE_REMOVABLE: u32 = 2;
#[cfg(windows)]
const DRIVE_FIXED: u32 = 3;
#[cfg(windows)]
const DRIVE_REMOTE: u32 = 4;
#[cfg(windows)]
const DRIVE_CDROM: u32 = 5;
#[cfg(windows)]
const DRIVE_RAMDISK: u32 = 6;

use crate::{ScanConfig, GenMatch, HashIOCCollections, FalsePositiveHashCollections, ExtVars, YaraMatch, FilenameIOC, find_hash_ioc};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::unified_logger::{UnifiedLogger, MatchReason, LogLevel};
use crate::helpers::throttler::{throttle_start, throttle_end_with_limit};
use crate::helpers::helpers::log_access_error;
use crate::helpers::interrupt::ScanState;

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

// Cloud storage root folder segment allowlist.
// Matching is done on normalized path segments (not substring matches).
const CLOUD_ROOT_SEGMENTS: &[&str] = &[
    // Cross-platform common roots
    "onedrive",
    "dropbox",
    ".dropbox",
    "google drive",
    "googledrive",
    "icloud drive",
    "box",
    "box-box",
    "mega",
    "megasync",
    "nextcloud",
    "owncloud",
    "tresorit",
    "tresorit drive",
    "syncthing",
];

// Linux/Mac path exclusions (start of path)
const LINUX_PATH_SKIPS_START: &'static [&'static str] = &[
    "/proc",
    "/dev",
    "/sys/kernel/debug",
    "/sys/kernel/slab",
    "/sys/kernel/tracing",
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
#[allow(dead_code)]
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
    let path_lower = path.replace('\\', "/").to_lowercase();
    let segments: Vec<&str> = path_lower.split('/').filter(|s| !s.is_empty()).collect();

    // Direct segment matches (no substring matches)
    if segments
        .iter()
        .any(|segment| CLOUD_ROOT_SEGMENTS.contains(segment))
    {
        return true;
    }

    // Dynamic provider segment patterns:
    // - OneDrive - <OrgName> (Windows)
    // - OneDrive-<TenantName> (macOS File Provider style)
    // - Nextcloud-<accountName> (macOS Virtual Files domains)
    if segments.iter().any(|segment| {
        segment.starts_with("onedrive - ")
            || segment.starts_with("onedrive-")
            || segment.starts_with("nextcloud-")
    }) {
        return true;
    }

    // macOS CloudStorage root marker: ~/Library/CloudStorage/*
    if segments
        .windows(2)
        .any(|pair| pair[0] == "library" && pair[1] == "cloudstorage")
    {
        return true;
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

// Check if a filesystem type is a network filesystem (Linux/macOS)
fn is_network_filesystem(fs_type: &str) -> bool {
    let fs_lower = fs_type.to_lowercase();
    matches!(
        fs_lower.as_str(),
        "nfs" | "nfs4" | "cifs" | "smbfs" | "smb3" | "sshfs" | "fuse.sshfs" | "afp" | "webdav" | "davfs2"
    )
}

// Enumerate Windows drives based on scan configuration
#[cfg(windows)]
pub fn enumerate_windows_drives(scan_hard_drives: bool, scan_all_drives: bool) -> Vec<String> {
    let mut drives = Vec::new();
    
    if !scan_hard_drives && !scan_all_drives {
        return drives;
    }
    
    let drive_mask = unsafe { GetLogicalDrives() };
    
    for i in 0..26 {
        if (drive_mask & (1 << i)) != 0 {
            let drive_letter = (b'A' + i as u8) as char;
            let drive_path = format!("{}:\\", drive_letter);
            
            let h_drive = HSTRING::from(&drive_path);
            let drive_type = unsafe { GetDriveTypeW(PCWSTR(h_drive.as_ptr())) };
            
            // Skip invalid drives
            if drive_type == DRIVE_NO_ROOT_DIR {
                continue;
            }
            
            // Filter based on flags
            if scan_hard_drives {
                // Only include fixed drives (local hard drives)
                if drive_type == DRIVE_FIXED {
                    drives.push(drive_path);
                }
            } else if scan_all_drives {
                // Include all drives (fixed, removable, CD-ROM, network, etc.)
                if drive_type != DRIVE_NO_ROOT_DIR && drive_type != DRIVE_UNKNOWN {
                    drives.push(drive_path);
                }
            }
        }
    }
    
    drives
}

// Enumerate Linux mount points based on scan configuration
#[cfg(target_os = "linux")]
pub fn enumerate_linux_mounts(scan_hard_drives: bool, scan_all_drives: bool) -> Vec<String> {
    let mut mounts = Vec::new();
    
    if !scan_hard_drives && !scan_all_drives {
        return mounts;
    }
    
    // Read /proc/mounts
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        let mut root_found = false;
        
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            
            let mount_point = parts[1];
            let fs_type = parts[2];
            
            // Skip special filesystems
            let special_fs = matches!(
                fs_type,
                "proc" | "sysfs" | "devtmpfs" | "devpts" | "tmpfs" | "cgroup" | "cgroup2" | "pstore" | "bpf" | "tracefs" | "debugfs" | "securityfs" | "hugetlbfs" | "mqueue" | "overlay" | "autofs"
            );
            
            if special_fs {
                continue;
            }
            
            // Track if root filesystem is found
            if mount_point == "/" {
                root_found = true;
            }
            
            if scan_hard_drives {
                // Only include local filesystems
                if !is_network_filesystem(fs_type) {
                    if !mounts.contains(&mount_point.to_string()) {
                        mounts.push(mount_point.to_string());
                    }
                }
            } else if scan_all_drives {
                // Include all filesystems including network
                if !mounts.contains(&mount_point.to_string()) {
                    mounts.push(mount_point.to_string());
                }
            }
        }
        
        // Always ensure root is included if it's a local filesystem and scan_hard_drives is set
        if scan_hard_drives && !root_found {
            // Try to add root if it wasn't found (shouldn't happen, but safety check)
            if !mounts.contains(&"/".to_string()) {
                mounts.insert(0, "/".to_string());
            }
        }
    }
    
    mounts
}

// Enumerate macOS mount points based on scan configuration
#[cfg(target_os = "macos")]
pub fn enumerate_macos_mounts(scan_hard_drives: bool, scan_all_drives: bool) -> Vec<String> {
    let mut mounts = Vec::new();
    
    if !scan_hard_drives && !scan_all_drives {
        return mounts;
    }
    
    // Always include root filesystem
    if scan_hard_drives || scan_all_drives {
        mounts.push("/".to_string());
    }
    
    // Read /etc/mtab for mount information on macOS
    // Note: /etc/mtab may not exist on all macOS versions, so we also check /Volumes
    if let Ok(content) = fs::read_to_string("/etc/mtab") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            
            let mount_point = parts[1];
            let fs_type = parts[2];
            
            // Skip root (already added)
            if mount_point == "/" {
                continue;
            }
            
            // Skip special filesystems
            let special_fs = matches!(
                fs_type,
                "devfs" | "fdesc" | "linprocfs" | "linsysfs" | "tmpfs"
            );
            
            if special_fs {
                continue;
            }
            
            if scan_hard_drives {
                // Only include local filesystems
                if !is_network_filesystem(fs_type) {
                    if !mounts.contains(&mount_point.to_string()) {
                        mounts.push(mount_point.to_string());
                    }
                }
            } else if scan_all_drives {
                // Include all filesystems including network
                if !mounts.contains(&mount_point.to_string()) {
                    mounts.push(mount_point.to_string());
                }
            }
        }
    }
    
    // Also scan /Volumes directory for external drives on macOS
    // This catches drives that might not be in /etc/mtab
    if scan_hard_drives || scan_all_drives {
        if let Ok(entries) = fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let mount_path = path.to_string_lossy().to_string();
                    // Only add if not already in list and if scan_hard_drives, check it's not a network mount
                    if !mounts.contains(&mount_path) {
                        // For /Volumes, we assume they're local unless we can determine otherwise
                        // Since we can't easily check filesystem type here, we'll include them
                        // when scan_hard_drives is set (user wants local drives, /Volumes are typically local)
                        if scan_hard_drives || scan_all_drives {
                            mounts.push(mount_path);
                        }
                    }
                }
            }
        }
    }
    
    mounts
}

// Unified function to enumerate drives/mounts based on platform
pub fn enumerate_drives(scan_hard_drives: bool, scan_all_drives: bool) -> Vec<String> {
    #[cfg(windows)]
    {
        enumerate_windows_drives(scan_hard_drives, scan_all_drives)
    }
    
    #[cfg(target_os = "linux")]
    {
        enumerate_linux_mounts(scan_hard_drives, scan_all_drives)
    }
    
    #[cfg(target_os = "macos")]
    {
        enumerate_macos_mounts(scan_hard_drives, scan_all_drives)
    }
    
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
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
            context.exclusion_patterns,
            context.logger,
            context.scan_state.as_ref()
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
    exclusion_patterns: &Vec<Regex>,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>) -> (usize, usize, usize, usize, usize) {
    
    let cpu_limit = scan_config.cpu_limit;
    
    // Check if target folder itself is on a network drive or cloud path
    // When scan_hard_drives is true: skip network drives but allow local drives
    // When scan_all_drives is true: don't skip anything
    if scan_config.scan_hard_drives {
        // Only scan local hard drives, skip network drives
        if is_network_drive(target_folder) {
            logger.warning(&format!("Skipping network drive TARGET: {}", target_folder));
            return (0, 0, 0, 0, 0);
        }
        
        // Still skip cloud storage paths even when scanning hard drives
        if is_cloud_or_remote_path(target_folder) {
            logger.warning(&format!("Skipping cloud storage folder TARGET: {}", target_folder));
            return (0, 0, 0, 0, 0);
        }
    } else if !scan_config.scan_all_drives {
        // Default behavior: skip network drives and cloud paths
        if is_network_drive(target_folder) {
            logger.warning(&format!("Skipping network drive TARGET: {}", target_folder));
            return (0, 0, 0, 0, 0);
        }
        
        if is_cloud_or_remote_path(target_folder) {
            logger.warning(&format!("Skipping cloud storage folder TARGET: {}", target_folder));
            return (0, 0, 0, 0, 0);
        }
    }
    // When scan_all_drives is true, don't skip anything
    
    // Walk the file system (don't follow symlinks to match v1 behavior)
    let walk = WalkDir::new(target_folder)
        .follow_links(false)  // Match v1 behavior: followlinks=False
        .into_iter();
        
    let scan_state_ref = scan_state.cloned();

    // Process files in parallel
    let (files_scanned, files_matched, alert_count, warning_count, notice_count) = walk.par_bridge()
        .map(|entry_res| {
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
                        exclusion_patterns,
                        logger,
                        scan_state_ref.as_ref()
                    );
                    // Use dynamic CPU limit from ScanState if available
                    let current_cpu_limit = scan_state_ref.as_ref()
                        .map(|s| s.get_cpu_limit())
                        .unwrap_or(cpu_limit);
                    throttle_end_with_limit(current_cpu_limit);
                    result
                },
                Err(e) => {
                    log_access_error(logger, "fs_object", &e, scan_config.show_access_errors);
                    if let Some(ref state) = scan_state_ref {
                        state.increment_errors();
                    }
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
    exclusion_patterns: &Vec<Regex>,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>
) -> (usize, usize, usize, usize, usize) {
    let mut files_scanned = 0;
    let mut files_matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;

    let file_path = entry.path();
    let file_path_str = file_path.to_string_lossy();

    // Check interrupt state
    if let Some(state) = scan_state {
        if state.should_stop() { return (0, 0, 0, 0, 0); }
        state.wait_for_resume();
        if state.should_stop() { return (0, 0, 0, 0, 0); }
        state.set_current_element(file_path_str.to_string());
        state.increment_files();
    }
    
    // Always exclude the program's own directory to prevent scanning itself
    if let Some(ref program_dir) = scan_config.program_dir {
        let program_dir_path = Path::new(program_dir);
        if file_path.starts_with(program_dir_path) {
            logger.debug(&format!("Skipping program directory FILE: {} PROGRAM_DIR: {}", file_path_str, program_dir));
            if let Some(state) = scan_state { state.increment_skipped(); }
            return (0, 0, 0, 0, 0);
        }
    }

    // Check custom exclusion patterns from config/excludes.cfg
    for pattern in exclusion_patterns.iter() {
        if pattern.is_match(&file_path_str) {
            logger.debug(&format!("Skipping excluded path (config pattern) FILE: {} PATTERN: {}", file_path_str, pattern.as_str()));
            if let Some(state) = scan_state { state.increment_skipped(); }
            return (0, 0, 0, 0, 0);
        }
    }

    // Determine if we should exclude mounted devices
    // When scan_all_drives is true: don't exclude anything
    // When scan_hard_drives is true: we've already enumerated the right drives, so don't exclude mounted devices
    // Otherwise: exclude mounted devices
    let exclude_mounted = !scan_config.scan_all_drives && !scan_config.scan_hard_drives;

    // Cloud/Network exclusions (skip if path contains cloud keywords)
    // Always exclude cloud paths unless scan_all_drives is true
    if !scan_config.scan_all_drives && is_cloud_or_remote_path(&file_path_str) {
        logger.debug(&format!("Skipping cloud storage path FILE: {}", file_path_str));
        if let Some(state) = scan_state { state.increment_skipped(); }
        return (0, 0, 0, 0, 0);
    }

    // Platform-specific path exclusions (Linux/Mac)
    if cfg!(unix) {
        for skip_path in LINUX_PATH_SKIPS_START.iter() {
            if file_path_str.starts_with(skip_path) {
                logger.debug(&format!("Skipping excluded path (start) FILE: {} MATCH: {}", file_path_str, skip_path));
                if let Some(state) = scan_state { state.increment_skipped(); }
                return (0, 0, 0, 0, 0);
            }
        }
        if exclude_mounted {
            for skip_path in MOUNTED_DEVICES.iter() {
                if file_path_str.starts_with(skip_path) {
                    logger.debug(&format!("Skipping mounted device FILE: {} MATCH: {}", file_path_str, skip_path));
                    if let Some(state) = scan_state { state.increment_skipped(); }
                    return (0, 0, 0, 0, 0);
                }
            }
        }
        for skip_path in LINUX_PATH_SKIPS_END.iter() {
            if file_path_str.ends_with(skip_path) {
                logger.debug(&format!("Skipping excluded path (end) FILE: {} MATCH: {}", file_path_str, skip_path));
                if let Some(state) = scan_state { state.increment_skipped(); }
                return (0, 0, 0, 0, 0);
            }
        }
    }
    
    // Skip certain drives and folders (macOS/Windows)
    for skip_dir_value in ALL_DRIVE_EXCLUDES.iter() {
        if file_path_str.contains(skip_dir_value) {
            if let Some(state) = scan_state { state.increment_skipped(); }
            return (0, 0, 0, 0, 0);
        }
    }
    
    // Skip all elements that aren't files (directories, symlinks, etc.)
    if !entry.path().is_file() { 
        logger.debug(&format!("Skipped element that isn't a file ELEMENT: {}", entry.path().display()));
        // Don't count directories as skipped - only files
        return (0, 0, 0, 0, 0);
    };
    
    // Skip big files
    let metadata = match entry.path().symlink_metadata() {
        Ok(m) => m,
        Err(e) => { 
            log_access_error(logger, &file_path_str, &e, scan_config.show_access_errors);
            return (0, 0, 0, 0, 0);
        }
    };
    let realsize = entry.path().size_on_disk_fast(&metadata).unwrap_or(metadata.len());
    if realsize > scan_config.max_file_size as u64 || metadata.len() > scan_config.max_file_size as u64 { 
        logger.debug(&format!("Skipping file due to size FILE: {} SIZE: {} MAX_FILE_SIZE: {}", 
        entry.path().display(), realsize, scan_config.max_file_size));
        if let Some(state) = scan_state { state.increment_skipped(); }
        return (0, 0, 0, 0, 0); 
    }
    
    // Type detection
    let extension_raw = entry.path().extension().unwrap_or_default().to_str().unwrap_or("");
    let file_format = FileFormat::from_file(entry.path()).unwrap_or_default();
    let _file_format_desc = file_format.name(); 
    let file_type_long = file_format.to_owned().to_string(); 

    // Check if file should be scanned
    let matches_file_type = FILE_TYPES.contains(&file_type_long.as_str());
    let matches_extension = if extension_raw.is_empty() { false } else {
        let ext_with_dot = format!(".{}", extension_raw);
        REL_EXTS.contains(&ext_with_dot.as_str())
    };
    
    if !matches_file_type && !matches_extension && !scan_config.scan_all_types {
        logger.debug(&format!("Skipping file due to extension or type FILE: {} EXT: {:?} TYPE: {:?}", 
            entry.path().display(), extension_raw, file_type_long));
        if let Some(state) = scan_state { state.increment_skipped(); }
        return (0, 0, 0, 0, 0);
    }

    logger.debug(&format!("Scanning file {} TYPE: {:?}", entry.path().display(), file_type_long));
    
    // READ FILE
    let file = match fs::File::open(entry.path()) {
        Ok(f) => f,
        Err(e) => { 
            log_access_error(logger, &file_path_str, &e, scan_config.show_access_errors);
            return (0, 0, 0, 0, 0); 
        }
    };
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(e) => {
            log_access_error(logger, &file_path_str, &e, scan_config.show_access_errors);
            return (0, 0, 0, 0, 0); 
        }
    };

    // Timestamps
    let msecs = metadata.modified().map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()).unwrap_or(0);
    let asecs = metadata.accessed().map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()).unwrap_or(0);
    let csecs = metadata.created().map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()).unwrap_or(0);

    // Scan the file itself
    let (s, m, a, w, n) = scan_memory_buffer(
        &mmap, &file_path_str, 
        entry.path().file_name().map(|n| n.to_string_lossy()).unwrap_or_default().as_ref(),
        extension_raw, &file_format.name().to_ascii_uppercase(), (msecs as i64, asecs as i64, csecs as i64),
        compiled_rules, scan_config, hash_collections, fp_hash_collections, filename_iocs,
        logger, scan_state, None, None
    );
    files_scanned += s; files_matched += m; alert_count += a; warning_count += w; notice_count += n;

    // Check for archive (if archive scanning is enabled)
    if file_format == FileFormat::Zip && scan_config.scan_archives {
        logger.debug(&format!("Scanning ZIP archive content: {}", file_path_str));
        // Calculate container info for linking
        let md5_val = format!("{:x}", md5::compute(&mmap));
        let sha1_val = hex::encode(Sha1::new().chain_update(&mmap).finalize());
        let sha256_val = hex::encode(Sha256::new().chain_update(&mmap).finalize());
        let mtime = Utc.timestamp_opt(msecs as i64, 0).single().unwrap_or_else(|| Utc::now());
        let atime = Utc.timestamp_opt(asecs as i64, 0).single().unwrap_or_else(|| Utc::now());
        let ctime = Utc.timestamp_opt(csecs as i64, 0).single().unwrap_or_else(|| Utc::now());
        
        let container_info = SampleInfo {
            md5: md5_val, sha1: sha1_val, sha256: sha256_val,
            atime: atime.to_rfc3339(), mtime: mtime.to_rfc3339(), ctime: ctime.to_rfc3339(),
        };

        match ZipArchive::new(Cursor::new(&mmap)) {
            Ok(mut archive) => {
                for i in 0..archive.len() {
                    if let Ok(mut zfile) = archive.by_index(i) {
                        if zfile.is_file() && zfile.size() < scan_config.max_file_size as u64 {
                            let mut buffer = Vec::with_capacity(zfile.size() as usize);
                            if zfile.read_to_end(&mut buffer).is_ok() {
                                let entry_name = zfile.name().to_string();
                                let display_path = format!("{}->{}", file_path_str, entry_name);
                                let ext = Path::new(&entry_name).extension().map(|e| e.to_string_lossy()).unwrap_or_default();
                                
                                let (s, m, a, w, n) = scan_memory_buffer(
                                    &buffer, &display_path, &entry_name, &ext, "ARCHIVE_ENTRY",
                                    (0, 0, 0), // Timestamps inside zip? zfile.last_modified()
                                    compiled_rules, scan_config, hash_collections, fp_hash_collections, filename_iocs,
                                    logger, scan_state, 
                                    Some(&container_info), Some(&file_path_str)
                                );
                                files_scanned += s; files_matched += m; alert_count += a; warning_count += w; notice_count += n;
                            }
                        }
                    }
                }
            },
            Err(e) => logger.debug(&format!("Failed to open ZIP archive {}: {:?}", file_path_str, e)),
        }
    }

    if let Some(state) = scan_state { state.clear_current_element(); }
    (files_scanned, files_matched, alert_count, warning_count, notice_count)
}

fn scan_memory_buffer(
    content: &[u8],
    path_display: &str,
    filename_str: &str,
    extension: &str,
    filetype: &str,
    timestamps: (i64, i64, i64), // mtime, atime, ctime (secs)
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    hash_collections: &HashIOCCollections,
    fp_hash_collections: &FalsePositiveHashCollections,
    filename_iocs: &Vec<FilenameIOC>,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
    _container_info: Option<&SampleInfo>,
    _container_path: Option<&str>,
) -> (usize, usize, usize, usize, usize) {
    let scanned = 1;
    let mut matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;
    
    // Convert timestamps (mtime, atime, ctime) to RFC3339 strings
    let mtime_str = Utc.timestamp_opt(timestamps.0, 0).single()
        .map(|dt| dt.to_rfc3339());
    let atime_str = Utc.timestamp_opt(timestamps.1, 0).single()
        .map(|dt| dt.to_rfc3339());
    let ctime_str = Utc.timestamp_opt(timestamps.2, 0).single()
        .map(|dt| dt.to_rfc3339());

    let mut sample_matches = ArrayVec::<GenMatch, 100>::new();

    // 1. Filename IOCs
    for fioc in filename_iocs.iter() {
        if !sample_matches.is_full() {
            if fioc.regex.is_match(path_display) || fioc.regex.is_match(filename_str) {
                 let is_false_positive = if let Some(ref fp_regex) = fioc.regex_fp {
                    fp_regex.is_match(path_display) || fp_regex.is_match(filename_str)
                 } else { false };
                 
                 if !is_false_positive {
                    let match_message = format!("File Name IOC matched PATTERN: {}", fioc.pattern);
                    sample_matches.insert(sample_matches.len(), GenMatch { 
                        message: match_message, 
                        score: fioc.score,
                        description: Some(fioc.description.clone()),
                        author: None,
                        reference: None,
                        matched_strings: None,
                    });
                    logger.debug(&format!("Filename IOC match FILE: {} PATTERN: {} SCORE: {}", path_display, fioc.pattern, fioc.score));
                 }
            }
        }
    }

    // 2. Hash Calculation & Matching
    let md5_value = format!("{:x}", md5::compute(content));
    let sha1_value = hex::encode(Sha1::new().chain_update(content).finalize());
    let sha256_value = hex::encode(Sha256::new().chain_update(content).finalize());
    
    // FP Check
    if find_hash_ioc(&md5_value, &fp_hash_collections.md5_iocs).is_some() ||
       find_hash_ioc(&sha1_value, &fp_hash_collections.sha1_iocs).is_some() ||
       find_hash_ioc(&sha256_value, &fp_hash_collections.sha256_iocs).is_some() {
        logger.debug(&format!("File skipped due to false positive hash match FILE: {}", path_display));
        return (1, 0, 0, 0, 0);
    }
    
    // Hash IOCs
    if !sample_matches.is_full() {
        if let Some(ioc) = find_hash_ioc(&md5_value, &hash_collections.md5_iocs) {
             let match_message = format!("HASH match with IOC HASH: {}", ioc.hash_value);
             sample_matches.insert(sample_matches.len(), GenMatch{
                 message: match_message, 
                 score: ioc.score,
                 description: Some(ioc.description.clone()),
                 author: None,
                 reference: None,
                 matched_strings: None,
             });
        }
        if let Some(ioc) = find_hash_ioc(&sha1_value, &hash_collections.sha1_iocs) {
             let match_message = format!("HASH match with IOC HASH: {}", ioc.hash_value);
             sample_matches.insert(sample_matches.len(), GenMatch{
                 message: match_message, 
                 score: ioc.score,
                 description: Some(ioc.description.clone()),
                 author: None,
                 reference: None,
                 matched_strings: None,
             });
        }
        if let Some(ioc) = find_hash_ioc(&sha256_value, &hash_collections.sha256_iocs) {
             let match_message = format!("HASH match with IOC HASH: {}", ioc.hash_value);
             sample_matches.insert(sample_matches.len(), GenMatch{
                 message: match_message, 
                 score: ioc.score,
                 description: Some(ioc.description.clone()),
                 author: None,
                 reference: None,
                 matched_strings: None,
             });
        }
    }
    
    let _sample_info = SampleInfo {
        md5: md5_value.clone(),
        sha1: sha1_value.clone(),
        sha256: sha256_value.clone(),
        atime: atime_str.clone().unwrap_or_default(),
        mtime: mtime_str.clone().unwrap_or_default(),
        ctime: ctime_str.clone().unwrap_or_default(),
    };

    // 3. YARA Scan
    let ext_vars = ExtVars {
        filename: filename_str.to_string(),
        filepath: path_display.to_string(),
        extension: extension.to_string(),
        filetype: filetype.to_string(),
        owner: "".to_string(),
    };
    
    let yara_matches = scan_file(compiled_rules, content, scan_config, &ext_vars);
    for ymatch in yara_matches.iter() {
        if !sample_matches.is_full() {
            let match_message = format!("YARA match with rule {}", ymatch.rulename);
            sample_matches.insert(sample_matches.len(), GenMatch{
                message: match_message, 
                score: ymatch.score,
                description: if ymatch.description.is_empty() { None } else { Some(ymatch.description.clone()) },
                author: if ymatch.author.is_empty() { None } else { Some(ymatch.author.clone()) },
                reference: if ymatch.reference.is_empty() { None } else { Some(ymatch.reference.clone()) },
                matched_strings: if ymatch.matched_strings.is_empty() { None } else { Some(ymatch.matched_strings.clone()) },
            });
        }
    }

    // 4. Reporting
    if !sample_matches.is_empty() {
        matched = 1;
        let sub_scores: Vec<i16> = sample_matches.iter().map(|m| m.score).collect();
        let total_score = calculate_weighted_score(&sub_scores).round() as i16;
        
        let log_level = if total_score as f64 >= scan_config.alert_threshold as f64 {
            alert_count += 1;
            if let Some(state) = scan_state { state.add_alerts(1); }
            LogLevel::Alert
        } else if total_score as f64 >= scan_config.warning_threshold as f64 {
            warning_count += 1;
            if let Some(state) = scan_state { state.add_warnings(1); }
            LogLevel::Warning
        } else if total_score as f64 >= scan_config.notice_threshold as f64 {
            notice_count += 1;
            if let Some(state) = scan_state { state.add_notices(1); }
            LogLevel::Notice
        } else {
            logger.debug(&format!("Match below threshold FILE: {} SCORE: {}", path_display, total_score));
            return (scanned, 0, 0, 0, 0);
        };
        
        let reasons_to_show = std::cmp::min(sample_matches.len(), scan_config.max_reasons);
        let shown_reasons: Vec<MatchReason> = sample_matches.iter().take(reasons_to_show)
            .map(|m| MatchReason { 
                message: m.message.clone(), 
                score: m.score,
                description: m.description.clone(),
                author: m.author.clone(),
                reference: m.reference.clone(),
                matched_strings: m.matched_strings.clone(),
            })
            .collect();
        
        // Unified Logging call
        logger.file_match(
            log_level,
            path_display,
            total_score as f64,
            filetype,
            content.len() as u64,
            &md5_value,
            &sha1_value,
            &sha256_value,
            shown_reasons,
            // Timestamps: (created, modified, accessed)
            Some((ctime_str.clone(), mtime_str.clone(), atime_str.clone())),
        );
    }
    
    (scanned, matched, alert_count, warning_count, notice_count)
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
                    let mut reference = String::new();
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
                            "reference" => {
                                match value {
                                    yara_x::MetaValue::String(s) => reference = s.to_string(),
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
                            reference: reference,
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
        fn test_linux_path_skips_sys_kernel_tracing() {
            assert!(LINUX_PATH_SKIPS_START.contains(&"/sys/kernel/tracing"));
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

    #[cfg(unix)]
    mod cloud_path_exclusion_tests_unix {
        use super::*;

        #[test]
        fn test_unix_dropbox_path_excluded() {
            let path = "/home/user/Dropbox/documents/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_dropbox_hidden_path_excluded() {
            let path = "/home/user/.dropbox/cache/file.dll";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_onedrive_path_excluded() {
            let path = "/home/user/OneDrive/work/report.ps1";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_google_drive_path_excluded() {
            let path = "/home/user/Google Drive/shared/script.sh";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_nextcloud_path_excluded() {
            let path = "/home/user/Nextcloud/projects/app.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_mega_path_excluded() {
            let path = "/home/user/MEGA/backups/archive.zip";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_megasync_path_excluded() {
            let path = "/home/user/MEGAsync/sync/data.bin";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_pcloud_path_excluded() {
            let path = "/home/user/pCloud/photos/image.jpg";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_seafile_path_excluded() {
            let path = "/home/user/Seafile/library/document.docx";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_owncloud_path_excluded() {
            let path = "/home/user/ownCloud/shared/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_syncthing_path_excluded() {
            let path = "/home/user/Syncthing/folder/data.dll";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_unix_resilio_sync_path_excluded() {
            let path = "/home/user/Resilio Sync/shared/file.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_regular_path_not_excluded() {
            let path = "/home/user/documents/work/project.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_tmp_path_not_excluded_as_cloud() {
            let path = "/tmp/suspicious.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_var_path_not_excluded_as_cloud() {
            let path = "/var/log/app.log";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_opt_path_not_excluded_as_cloud() {
            let path = "/opt/application/bin/app";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_case_insensitive_dropbox() {
            // Test that cloud path matching is case-insensitive
            let path_lower = "/home/user/dropbox/file.exe";
            let path_upper = "/home/user/DROPBOX/file.exe";
            let path_mixed = "/home/user/DropBox/file.exe";
            assert!(is_cloud_or_remote_path(path_lower));
            assert!(is_cloud_or_remote_path(path_upper));
            assert!(is_cloud_or_remote_path(path_mixed));
        }

        #[test]
        fn test_case_insensitive_onedrive() {
            let path_lower = "/home/user/onedrive/file.exe";
            let path_upper = "/home/user/ONEDRIVE/file.exe";
            assert!(is_cloud_or_remote_path(path_lower));
            assert!(is_cloud_or_remote_path(path_upper));
        }

        #[test]
        fn test_dynamic_onedrive_org_segment_excluded() {
            let path = "/home/user/OneDrive - Acme Corp/docs/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_dynamic_onedrive_tenant_segment_excluded() {
            let path = "/Users/user/Library/CloudStorage/OneDrive-Contoso/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_dynamic_nextcloud_account_segment_excluded() {
            let path = "/Users/user/Library/CloudStorage/Nextcloud-john@example.com/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_cloudstorage_parent_segments_excluded() {
            let path = "/Users/user/Library/CloudStorage/UnknownProvider/file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_no_substring_match_sync_segment() {
            let path = "/home/user/projects/sync-tools/sample.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_no_substring_match_mega_segment() {
            let path = "/home/user/projects/megatest/sample.exe";
            assert!(!is_cloud_or_remote_path(path));
        }
    }

    #[cfg(windows)]
    mod cloud_path_exclusion_tests_windows {
        use super::*;

        #[test]
        fn test_windows_onedrive_path_excluded() {
            let path = r"C:\Users\user\OneDrive\documents\file.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_dropbox_path_excluded() {
            let path = r"C:\Users\user\Dropbox\work\report.docx";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_google_drive_path_excluded() {
            let path = r"C:\Users\user\Google Drive\shared\script.ps1";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_nextcloud_path_excluded() {
            let path = r"C:\Users\user\Nextcloud\projects\app.exe";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_mega_path_excluded() {
            let path = r"C:\Users\user\MEGA\backups\archive.zip";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_pcloud_path_not_excluded() {
            let path = r"C:\Users\user\pCloud\photos\image.jpg";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_box_path_excluded() {
            let path = r"C:\Users\user\Box\documents\file.pdf";
            assert!(is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_regular_path_not_excluded() {
            let path = r"C:\Users\user\Documents\work\project.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_program_files_not_excluded() {
            let path = r"C:\Program Files\Application\app.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_windows_temp_not_excluded() {
            let path = r"C:\Windows\Temp\suspicious.exe";
            assert!(!is_cloud_or_remote_path(path));
        }

        #[test]
        fn test_case_insensitive_onedrive_windows() {
            let path_mixed = r"C:\Users\user\onedrive\file.exe";
            let path_upper = r"C:\Users\user\ONEDRIVE\file.exe";
            assert!(is_cloud_or_remote_path(path_mixed));
            assert!(is_cloud_or_remote_path(path_upper));
        }
    }

    mod system_path_exclusion_tests {
        use super::*;

        #[test]
        fn test_proc_cmdline_excluded() {
            let path = "/proc/1234/cmdline";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_proc_exe_excluded() {
            let path = "/proc/1/exe";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_dev_null_excluded() {
            let path = "/dev/null";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_dev_sda_excluded() {
            let path = "/dev/sda1";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_sys_kernel_debug_excluded() {
            let path = "/sys/kernel/debug/tracing/trace";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_sys_kernel_tracing_excluded() {
            let path = "/sys/kernel/tracing/events";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_sys_kernel_slab_excluded() {
            let path = "/sys/kernel/slab/kmalloc-64";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_sys_devices_excluded() {
            let path = "/sys/devices/pci0000:00/0000:00:1f.0";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_usr_src_linux_excluded() {
            let path = "/usr/src/linux/kernel/sched.c";
            let should_skip = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_initctl_path_excluded() {
            let path = "/run/initctl";
            let should_skip = LINUX_PATH_SKIPS_END.iter().any(|skip| path.ends_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_var_run_initctl_excluded() {
            let path = "/var/run/initctl";
            let should_skip = LINUX_PATH_SKIPS_END.iter().any(|skip| path.ends_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_media_usb_excluded() {
            let path = "/media/usb/files/document.exe";
            let should_skip = MOUNTED_DEVICES.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_volumes_external_excluded() {
            let path = "/volumes/External/backup.tar";
            let should_skip = MOUNTED_DEVICES.iter().any(|skip| path.starts_with(skip));
            assert!(should_skip);
        }

        #[test]
        fn test_home_path_not_excluded() {
            let path = "/home/user/.local/bin/app";
            let should_skip_start = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            let should_skip_end = LINUX_PATH_SKIPS_END.iter().any(|skip| path.ends_with(skip));
            let should_skip_mounted = MOUNTED_DEVICES.iter().any(|skip| path.starts_with(skip));
            assert!(!should_skip_start);
            assert!(!should_skip_end);
            assert!(!should_skip_mounted);
        }

        #[test]
        fn test_usr_bin_not_excluded() {
            let path = "/usr/bin/python3";
            let should_skip_start = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(!should_skip_start);
        }

        #[test]
        fn test_etc_not_excluded() {
            let path = "/etc/passwd";
            let should_skip_start = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(!should_skip_start);
        }

        #[test]
        fn test_var_log_not_excluded() {
            let path = "/var/log/syslog";
            let should_skip_start = LINUX_PATH_SKIPS_START.iter().any(|skip| path.starts_with(skip));
            assert!(!should_skip_start);
        }
    }

    mod program_directory_exclusion_tests {
        use super::*;
        use std::path::Path;

        #[test]
        fn test_program_dir_match() {
            let program_dir = "/opt/loki";
            let file_path = Path::new("/opt/loki/signatures/rules.yar");
            let program_dir_path = Path::new(program_dir);
            assert!(file_path.starts_with(program_dir_path));
        }

        #[test]
        fn test_program_dir_exact_match() {
            let program_dir = "/opt/loki";
            let file_path = Path::new("/opt/loki");
            let program_dir_path = Path::new(program_dir);
            assert!(file_path.starts_with(program_dir_path));
        }

        #[test]
        fn test_program_dir_no_match_similar_prefix() {
            let program_dir = "/opt/loki";
            let file_path = Path::new("/opt/loki2/file.exe");
            let program_dir_path = Path::new(program_dir);
            // This should NOT match because loki2 is different from loki
            assert!(!file_path.starts_with(program_dir_path));
        }

        #[test]
        fn test_program_dir_no_match_different_path() {
            let program_dir = "/opt/loki";
            let file_path = Path::new("/home/user/malware.exe");
            let program_dir_path = Path::new(program_dir);
            assert!(!file_path.starts_with(program_dir_path));
        }

        #[test]
        fn test_program_dir_nested_file() {
            let program_dir = "/usr/local/loki";
            let file_path = Path::new("/usr/local/loki/config/excludes.cfg");
            let program_dir_path = Path::new(program_dir);
            assert!(file_path.starts_with(program_dir_path));
        }
    }

    mod config_file_exclusion_tests {
        use super::*;

        fn create_test_exclusion_patterns() -> Vec<Regex> {
            vec![
                Regex::new(r"^/proc/.*").unwrap(),
                Regex::new(r"^/dev/.*").unwrap(),
                Regex::new(r".*\.tmp$").unwrap(),
                Regex::new(r".*\.swp$").unwrap(),
                Regex::new(r".*node_modules.*").unwrap(),
                Regex::new(r".*/\.git/.*").unwrap(),
                Regex::new(r"^/usr/bin/socat.*").unwrap(),
            ]
        }

        #[test]
        fn test_proc_path_excluded_by_config() {
            let patterns = create_test_exclusion_patterns();
            let path = "/proc/1234/cmdline";
            let excluded = patterns.iter().any(|p| p.is_match(path));
            assert!(excluded, "Path {} should be excluded by config pattern", path);
        }

        #[test]
        fn test_dev_path_excluded_by_config() {
            let patterns = create_test_exclusion_patterns();
            let path = "/dev/null";
            let excluded = patterns.iter().any(|p| p.is_match(path));
            assert!(excluded, "Path {} should be excluded by config pattern", path);
        }

        #[test]
        fn test_tmp_extension_excluded() {
            let patterns = create_test_exclusion_patterns();
            let path = "/home/user/document.tmp";
            let excluded = patterns.iter().any(|p| p.is_match(path));
            assert!(excluded, "Path {} should be excluded by .tmp pattern", path);
        }

        #[test]
        fn test_swp_extension_excluded() {
            let patterns = create_test_exclusion_patterns();
            let path = "/home/user/.bashrc.swp";
            let excluded = patterns.iter().any(|p| p.is_match(path));
            assert!(excluded, "Path {} should be excluded by .swp pattern", path);
        }

        #[test]
        fn test_node_modules_excluded() {
            let patterns = create_test_exclusion_patterns();
            let paths = vec![
                "/home/user/project/node_modules/package/index.js",
                "/var/www/app/node_modules/express/lib/express.js",
                "/opt/app/node_modules/.bin/npm",
            ];
            for path in paths {
                let excluded = patterns.iter().any(|p| p.is_match(path));
                assert!(excluded, "Path {} should be excluded by node_modules pattern", path);
            }
        }

        #[test]
        fn test_git_directory_excluded() {
            let patterns = create_test_exclusion_patterns();
            let paths = vec![
                "/home/user/project/.git/objects/pack/pack-abc123.idx",
                "/var/repo/.git/config",
                "/opt/app/.git/HEAD",
            ];
            for path in paths {
                let excluded = patterns.iter().any(|p| p.is_match(path));
                assert!(excluded, "Path {} should be excluded by .git pattern", path);
            }
        }

        #[test]
        fn test_socat_binary_excluded() {
            let patterns = create_test_exclusion_patterns();
            let paths = vec![
                "/usr/bin/socat",
                "/usr/bin/socat1",
            ];
            for path in paths {
                let excluded = patterns.iter().any(|p| p.is_match(path));
                assert!(excluded, "Path {} should be excluded by socat pattern", path);
            }
        }

        #[test]
        fn test_regular_paths_not_excluded() {
            let patterns = create_test_exclusion_patterns();
            let paths = vec![
                "/home/user/documents/report.pdf",
                "/usr/local/bin/python3",
                "/opt/application/app.exe",
                "/var/log/syslog",
                "/etc/passwd",
            ];
            for path in paths {
                let excluded = patterns.iter().any(|p| p.is_match(path));
                assert!(!excluded, "Path {} should NOT be excluded", path);
            }
        }

        #[test]
        fn test_empty_patterns_excludes_nothing() {
            let patterns: Vec<Regex> = Vec::new();
            let path = "/proc/1234/cmdline";
            let excluded = patterns.iter().any(|p| p.is_match(path));
            assert!(!excluded, "Empty pattern list should not exclude anything");
        }

        #[test]
        fn test_pattern_case_sensitive() {
            let patterns = vec![
                Regex::new(r".*\.TMP$").unwrap(), // uppercase
            ];
            let path_lower = "/home/user/file.tmp";
            let path_upper = "/home/user/file.TMP";

            let excluded_lower = patterns.iter().any(|p| p.is_match(path_lower));
            let excluded_upper = patterns.iter().any(|p| p.is_match(path_upper));

            assert!(!excluded_lower, "Lowercase .tmp should NOT match uppercase .TMP pattern");
            assert!(excluded_upper, "Uppercase .TMP should match uppercase .TMP pattern");
        }

        #[test]
        fn test_case_insensitive_pattern() {
            let patterns = vec![
                Regex::new(r"(?i).*\.tmp$").unwrap(), // case-insensitive
            ];
            let paths = vec![
                "/home/user/file.tmp",
                "/home/user/file.TMP",
                "/home/user/file.Tmp",
            ];

            for path in paths {
                let excluded = patterns.iter().any(|p| p.is_match(path));
                assert!(excluded, "Path {} should be excluded by case-insensitive pattern", path);
            }
        }
    }
}
