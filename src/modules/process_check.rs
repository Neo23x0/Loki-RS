use std::process;
use arrayvec::ArrayVec;
use yara_x::{Scanner, Rules};
#[cfg(target_os = "linux")]
use std::fs;
use sysinfo::{System, Pid, Process};
use hex;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
use rayon::prelude::*;

use crate::{ScanConfig, GenMatch, C2IOC, check_c2_match};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::jsonl_logger::{JsonlLogger, MatchReason};
use crate::helpers::remote_logger::RemoteLogger;
use crate::helpers::throttler::{init_thread_throttler, throttle_start, throttle_end};

// Scan process memory of all processes
pub fn scan_processes(compiled_rules: &Rules, scan_config: &ScanConfig, c2_iocs: &[C2IOC], jsonl_logger: Option<&JsonlLogger>, remote_logger: Option<&RemoteLogger>) -> (usize, usize, usize, usize, usize) {
    // Check if we are running on Linux
    if cfg!(not(target_os = "linux")) {
        log::warn!("Process scanning is currently only supported on Linux. (yara-x doesn't support process scanning on other platforms, yet)");
        return (0, 0, 0, 0, 0);
    }

    let cpu_limit = scan_config.cpu_limit;

    // Refresh the process information
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Process in parallel
    let (processes_scanned, processes_matched, alert_count, warning_count, notice_count) = sys.processes()
        .par_iter()
        .map(|(pid, process)| {
            init_thread_throttler(cpu_limit);
            throttle_start();
            let result = process_single_process(pid, process, compiled_rules, scan_config, c2_iocs, jsonl_logger, remote_logger);
            throttle_end();
            result
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
    (processes_scanned, processes_matched, alert_count, warning_count, notice_count)
}

fn process_single_process(
    pid: &Pid, 
    process: &Process, 
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    c2_iocs: &[C2IOC], 
    jsonl_logger: Option<&JsonlLogger>,
    remote_logger: Option<&RemoteLogger>
) -> (usize, usize, usize, usize, usize) {
    let mut processes_scanned = 0;
    let mut processes_matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;

    // Get LOKI's own process
    let own_pid = process::id();
    let pid_u32 = pid.as_u32();
    let proc_name = process.name();
    // Skip some processes
    if pid_u32 == own_pid { return (0, 0, 0, 0, 0); }  // skip LOKI's own process
    // Convert process name to string for logging
    let proc_name_str = proc_name.to_string_lossy().to_string();
    // Debug output : show every file that gets scanned
    log::debug!("Trying to scan process PID: {} PROC_NAME: {}", pid_u32, proc_name_str);
    
    // Count this as a process we attempted to scan
    processes_scanned += 1;
    
    // ------------------------------------------------------------
    // Matches (all types)
    let mut proc_matches = ArrayVec::<GenMatch, 100>::new();
    // ------------------------------------------------------------
    // YARA scanning
    // YARA-X: Create scanner and scan process memory
    let mut scanner = Scanner::new(compiled_rules);
    scanner.set_timeout(std::time::Duration::from_secs(30));
    
    // Read process memory from /proc/<pid>/mem (Linux) or use process memory API
    // Note: Reading /proc/<pid>/mem requires special permissions and may not work
    // For now, we'll skip process memory scanning on Linux until we have a better approach
    // YARA-X doesn't have a direct scan_process method like the old YARA
    
    #[cfg(target_os = "linux")]
    let mem_data = {
        let proc_mem_path = format!("/proc/{}/mem", pid_u32);
        match fs::read(&proc_mem_path) {
            Ok(data) => data,
            Err(e) => {
                if scan_config.show_access_errors {
                    log::error!("Cannot read process memory for PID {} ERROR: {:?}", pid_u32, e);
                } else {
                    log::debug!("Cannot read process memory for PID {} ERROR: {:?}", pid_u32, e);
                }
                return (processes_scanned, 0, 0, 0, 0); // Skip this process (but we already counted it as scanned)
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let mem_data: Vec<u8> = Vec::new();

    // Skip scanning if no memory data (non-Linux or read failure)
    if mem_data.is_empty() {
            // For non-Linux, we just proceed to match rule metadata or skip?
            // If we have no data, scanner.scan(&mem_data) returns matches on empty string.
            // Usually we want to skip if we can't read memory.
            // But let's let it run on empty to be safe, or continue?
            // If we continue here, we break the logic below.
            // Better: if mem_data is empty, we might want to skip YARA scan unless we want to match empty.
            if cfg!(not(target_os = "linux")) {
                // log::debug!("Process memory scanning not supported on this OS");
                // We continue loop to check network connections?
                // But scan_result is needed below.
            }
    }
    
    let scan_result = scanner.scan(&mem_data);
    
    log::trace!("YARA-X scan result for PID: {} PROC_NAME: {} RESULT: {:?}", pid_u32, proc_name_str, scan_result);
    
    // Extract YARA match metadata
    let yara_matches = match scan_result {
        Ok(results) => results,
        Err(e) => {
            if scan_config.show_access_errors { 
                log::error!("Error while scanning process memory PROC_NAME: {} ERROR: {:?}", proc_name_str, e); 
            } else { 
                log::debug!("Error while scanning process memory PROC_NAME: {} ERROR: {:?}", proc_name_str, e); 
            }
            return (processes_scanned, 0, 0, 0, 0); // Skip this process (but we already counted it as scanned)
        }
    };
    
    for matching_rule in yara_matches.matching_rules() {
        if !proc_matches.is_full() {
            let rule_id = matching_rule.identifier().to_string();
            
            let mut description = String::new();
            let mut author = String::new();
            let mut score = 75;
            
            for (key, value) in matching_rule.metadata() {
                match key {
                    "description" => {
                        if let yara_x::MetaValue::String(s) = value {
                            description = s.to_string();
                        }
                    }
                    "author" => {
                        if let yara_x::MetaValue::String(s) = value {
                            author = s.to_string();
                        }
                    }
                    "score" => {
                        if let yara_x::MetaValue::Integer(i) = value {
                            let s = i as i16;
                            if s > 0 && s <= 100 {
                                score = s;
                            }
                        }
                    }
                    _ => {}
                }
            }
            
            let mut matched_strings: Vec<String> = Vec::new();
            for pattern in matching_rule.patterns() {
                for pattern_match in pattern.matches() {
                    let identifier = pattern.identifier();
                    let offset = pattern_match.range().start;
                    let data = pattern_match.data();
                    
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
            
            let mut match_message = format!("YARA-X match with rule {}", rule_id);
            if !description.is_empty() {
                match_message.push_str(&format!("\n         DESC: {}", description));
            }
            if !author.is_empty() {
                match_message.push_str(&format!("\n         AUTHOR: {}", author));
            }
            if !matched_strings.is_empty() {
                let mut strings_display = Vec::new();
                for s in matched_strings.iter().take(3) {
                    let truncated = if s.len() > 140 {
                        format!("{}...", &s[..137])
                    } else {
                        s.clone()
                    };
                    strings_display.push(truncated);
                }
                match_message.push_str(&format!("\n         STRINGS: {}", strings_display.join(" ")));
                if matched_strings.len() > 3 {
                    match_message.push_str(&format!(" (and {} more)", matched_strings.len() - 3));
                }
            }
            
            proc_matches.insert(
                proc_matches.len(), 
                GenMatch { message: match_message, score }
            );
        }
    }
    
    // ------------------------------------------------------------
    // C2 IOC Matching - Check process network connections
    if !proc_matches.is_full() {
        let connections = get_process_connections(pid_u32);
        for (remote_ip, remote_port) in connections {
            if let Some(c2_ioc) = check_c2_match(&remote_ip, c2_iocs) {
                let match_message = format!("C2 IOC match in remote address\n         IP: {}\n         PORT: {}\n         DESC: {}", 
                    remote_ip, remote_port, c2_ioc.description);
                proc_matches.insert(
                    proc_matches.len(),
                    GenMatch {
                        message: match_message,
                        score: c2_ioc.score
                    }
                );
                log::trace!("C2 IOC match found PID: {} PROC_NAME: {} REMOTE: {}:{}", 
                    pid_u32, proc_name_str, remote_ip, remote_port);
            }
        }
    }

    // Show matches on process
    if !proc_matches.is_empty() {
        processes_matched += 1;
        
        let sub_scores: Vec<i16> = proc_matches.iter().map(|m| m.score).collect();
        let total_score = calculate_weighted_score(&sub_scores);
        
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
            log::debug!("Process match below notice threshold PID: {} SCORE: {:.2}", pid_u32, total_score);
            return (processes_scanned, 0, 0, 0, 0);
        };
        
        let reasons_to_show = std::cmp::min(proc_matches.len(), scan_config.max_reasons);
        let shown_reasons: Vec<&GenMatch> = proc_matches.iter().take(reasons_to_show).collect();
        
        let mut output = format!("PID: {} PROC_NAME: {}\n      SCORE: {:.0}\n", 
            pid_u32, proc_name_str, total_score.round());
        
        for (i, reason) in shown_reasons.iter().enumerate() {
            output.push_str(&format!("      REASON_{}: {} SUBSCORE: {}\n", i + 1, reason.message, reason.score));
        }
        
        if proc_matches.len() > reasons_to_show {
            output.push_str(&format!("      (and {} more reasons)\n", proc_matches.len() - reasons_to_show));
        }
        
        match message_level {
            "ALERT" => log::error!("{} {}", message_level, output),
            "WARNING" => log::warn!("{} {}", message_level, output),
            "NOTICE" => log::info!("{} {}", message_level, output),
            _ => log::debug!("{} {}", message_level, output),
        }
        
        if let Some(logger) = jsonl_logger {
            let jsonl_reasons: Vec<MatchReason> = shown_reasons.iter()
                .map(|r| MatchReason {
                    message: r.message.clone(),
                    score: r.score,
                })
                .collect();
            let _ = logger.log_process_match(
                message_level,
                pid_u32,
                &proc_name_str,
                total_score,
                jsonl_reasons,
            );
        }
        
        if let Some(logger) = remote_logger {
            let remote_reasons: Vec<MatchReason> = shown_reasons.iter()
                .map(|r| MatchReason {
                    message: r.message.clone(),
                    score: r.score,
                })
                .collect();
            logger.log_process_match(
                message_level,
                pid_u32,
                &proc_name_str,
                total_score,
                &remote_reasons,
            );
        }
    }
    
    (processes_scanned, processes_matched, alert_count, warning_count, notice_count)
}

// Get network connections for a process (Linux-specific)
// Reads from /proc/net/tcp and /proc/net/udp and matches by inode
#[cfg(target_os = "linux")]
fn get_process_connections(pid: u32) -> Vec<(String, u16)> {
    let mut connections = Vec::new();
    
    // Get process socket inodes from /proc/<pid>/fd
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut socket_inodes = Vec::new();
    
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let link_path = format!("/proc/{}/fd/{}", pid, entry.file_name().to_string_lossy());
                if let Ok(link) = fs::read_link(&link_path) {
                    let link_str = link.to_string_lossy();
                    // Socket links look like "socket:[12345]"
                    if link_str.starts_with("socket:[") && link_str.ends_with("]") {
                        if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix("]")) {
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                socket_inodes.push(inode);
                            }
                        }
                    }
                }
            }
        }
    }
    
    if socket_inodes.is_empty() {
        return connections;
    }
    
    // Read /proc/net/tcp
    if let Ok(file) = fs::File::open("/proc/net/tcp") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1) { // Skip header
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    // Parse inode (last field)
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        if socket_inodes.contains(&inode) {
                            // Parse remote address (field 2: "IP:PORT" in hex)
                            if let Some(remote_addr) = parse_tcp_address(parts[2]) {
                                connections.push(remote_addr);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Read /proc/net/udp (similar structure)
    if let Ok(file) = fs::File::open("/proc/net/udp") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1) { // Skip header
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        if socket_inodes.contains(&inode) {
                            if let Some(remote_addr) = parse_tcp_address(parts[2]) {
                                connections.push(remote_addr);
                            }
                        }
                    }
                }
            }
        }
    }
    
    connections
}

#[cfg(not(target_os = "linux"))]
fn get_process_connections(_pid: u32) -> Vec<(String, u16)> {
    Vec::new()
}

// Parse TCP/UDP address from /proc/net format: "AABBCCDD:PORT" (hex)
#[cfg(target_os = "linux")]
fn parse_tcp_address(addr_str: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    
    // Parse IP (hex format: AABBCCDD = DD.CC.BB.AA)
    let ip_hex = parts[0];
    if ip_hex.len() != 8 {
        return None;
    }
    
    // Convert hex to IP address
    let ip_bytes: Vec<u8> = (0..4)
        .map(|i| {
            let start = (3 - i) * 2;
            u8::from_str_radix(&ip_hex[start..start + 2], 16).unwrap_or(0)
        })
        .collect();
    
    let ip = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    
    // Parse port (hex)
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    
    Some((ip, port))
}
