use std::process;
use std::collections::HashMap;
use std::sync::Arc;
use arrayvec::ArrayVec;
use yara_x::{Scanner, Rules};
use sysinfo::{System, Pid, Process, Uid, Users};
use hex;
use rayon::prelude::*;

// Linux-specific I/O imports
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::fs;

// Hashing imports
use md5;
use sha1::Sha1;
use sha2::{Sha256, Digest};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, FALSE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(target_os = "windows")]
use std::ffi::c_void;

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};

use crate::{ScanConfig, GenMatch, C2IOC, check_c2_match, FilenameIOC, HashIOCCollections, find_hash_ioc};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::unified_logger::{UnifiedLogger, MatchReason, LogLevel};
use crate::helpers::throttler::{init_thread_throttler, throttle_start, throttle_end};
use crate::helpers::interrupt::ScanState;

use crate::modules::{ScanModule, ScanContext, ModuleResult};

pub struct ProcessCheckModule;

impl ScanModule for ProcessCheckModule {
    fn name(&self) -> &'static str {
        "ProcessCheck"
    }

    fn run(&self, context: &ScanContext) -> ModuleResult {
        scan_processes(
            context.compiled_rules,
            context.scan_config,
            context.c2_iocs,
            context.filename_iocs,
            context.hash_collections,
            context.logger,
            context.scan_state.as_ref()
        )
    }
}

// Scan process memory of all processes
pub fn scan_processes(
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    c2_iocs: &[C2IOC], 
    filename_iocs: &Vec<FilenameIOC>,
    hash_collections: &HashIOCCollections,
    logger: &UnifiedLogger, 
    scan_state: Option<&Arc<ScanState>>
) -> (usize, usize, usize, usize, usize) {
    
    // Warn if platform is not fully supported for memory scanning
    if cfg!(target_os = "macos") {
        logger.warning("Process memory scanning is not supported on macOS due to system protections.");
    }

    let cpu_limit = scan_config.cpu_limit;
    let own_pid = process::id();

    // Refresh the process information
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Create user map
    let users = Users::new_with_refreshed_list();
    let mut user_map: HashMap<Uid, String> = HashMap::new();
    for user in &users {
        user_map.insert(user.id().clone(), user.name().to_string());
    }
    
    // Process in parallel
    let (processes_scanned, processes_matched, alert_count, warning_count, notice_count) = sys.processes()
        .par_iter()
        .filter(|(pid, _)| pid.as_u32() != own_pid)
        .map(|(pid, process)| {
            init_thread_throttler(cpu_limit);
            throttle_start();
            let result = process_single_process(
                pid, 
                process, 
                &user_map,
                compiled_rules, 
                scan_config, 
                c2_iocs, 
                filename_iocs,
                hash_collections,
                logger,
                scan_state
            );
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
    user_map: &HashMap<Uid, String>,
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    c2_iocs: &[C2IOC], 
    filename_iocs: &Vec<FilenameIOC>,
    hash_collections: &HashIOCCollections,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>
) -> (usize, usize, usize, usize, usize) {
    let mut processes_scanned = 0;
    let mut processes_matched = 0;
    let mut alert_count = 0;
    let mut warning_count = 0;
    let mut notice_count = 0;

    let pid_u32 = pid.as_u32();
    let proc_name = process.name();
    
    // Convert process name to string for logging
    let proc_name_str = proc_name.to_string_lossy().to_string();

    // Check interrupt state
    if let Some(state) = scan_state {
        if state.should_stop() {
            return (0, 0, 0, 0, 0);
        }
        state.wait_for_resume(); // Wait if menu is active
        if state.should_stop() {
            return (0, 0, 0, 0, 0);
        }
        state.set_current_element(format!("Process: {} (PID: {})", proc_name_str, pid_u32));
        state.increment_processes();
    }
    
    // Gather process details

    let cmd_line = process.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ");
    let user_id = process.user_id();
    let username = user_id.and_then(|uid| user_map.get(uid)).map(|s| s.as_str()).unwrap_or("unknown");
    let ppid = process.parent().map(|p| p.as_u32().to_string()).unwrap_or("0".to_string());
    let status = format!("{:?}", process.status());
    
    // Extended Metadata
    let start_time = Some(process.start_time() as i64); // seconds since epoch
    let run_time_secs = process.run_time(); // seconds
    let run_time_str = format_runtime(run_time_secs);
    let memory_bytes = process.memory();
    let cpu_usage = process.cpu_usage();
    
    // Network info
    let (connections, listening_ports) = get_process_network_info(pid_u32);
    let connection_count = connections.len();
    
    // Compute hashes (if executable is readable)
    let mut md5_hash = None;
    let mut sha1_hash = None;
    let mut sha256_hash = None;
    
    if let Some(exe_path) = process.exe() {
        if exe_path.exists() && exe_path.is_file() {
            // Best effort read
            if let Ok(data) = std::fs::read(exe_path) {
                md5_hash = Some(format!("{:x}", md5::compute(&data)));
                sha1_hash = Some(hex::encode(Sha1::new().chain_update(&data).finalize()));
                sha256_hash = Some(hex::encode(Sha256::new().chain_update(&data).finalize()));
            }
        }
    }

    // Log detailed process info at INFO level using structured context
    // Console output will apply colors; JSONL/PlainText will be clean
    let cmd_display = if cmd_line.len() > 100 { format!("{}...", &cmd_line[..97]) } else { cmd_line.clone() };
    let mem_display = format!("{:.2} MB", memory_bytes as f64 / 1024.0 / 1024.0);
    let cpu_display = format!("{:.2}%", cpu_usage);
    let start_display = start_time.map(|t| t.to_string()).unwrap_or_else(|| "?".to_string());
    let ports_display = if listening_ports.is_empty() { 
        "none".to_string() 
    } else {
        let mut p_str = listening_ports.iter().take(20).map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        if listening_ports.len() > 20 { p_str.push_str(", [...]"); }
        p_str
    };
    
    // Build context for structured logging
    let mut context: Vec<(&str, String)> = vec![
        ("PID", pid_u32.to_string()),
        ("PPID", ppid.clone()),
        ("USER", username.to_string()),
        ("STATUS", status.clone()),
        ("CMD", cmd_display),
        ("RUNTIME", run_time_str.clone()),
        ("START", start_display),
        ("MEM", mem_display),
        ("CPU", cpu_display),
    ];
    
    if let Some(h) = &md5_hash { context.push(("MD5", h.clone())); }
    if let Some(h) = &sha1_hash { context.push(("SHA1", h.clone())); }
    if let Some(h) = &sha256_hash { context.push(("SHA256", h.clone())); }
    context.push(("CONN", connection_count.to_string()));
    context.push(("LISTEN", ports_display));
    
    // Convert to the format expected by info_w
    let context_refs: Vec<(&str, &str)> = context.iter().map(|(k, v)| (*k, v.as_str())).collect();
    
    logger.info_w(&format!("ANALYZED: {}", proc_name_str), &context_refs);

    // Debug output
    logger.debug(&format!("Trying to scan process PID: {} PROC_NAME: {}", pid_u32, proc_name_str));
    
    // Count this as a process we attempted to scan
    processes_scanned += 1;
    
    // ------------------------------------------------------------
    // Matches (all types)
    let mut proc_matches = ArrayVec::<GenMatch, 100>::new();
    // ------------------------------------------------------------
    
    // 1. Filename IOCs (Command Line & Executable Path)
    if !proc_matches.is_full() {
        let exe_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        let cmd_line = process.cmd().iter().map(|x| x.to_string_lossy()).collect::<Vec<_>>().join(" ");
        
        for fioc in filename_iocs {
            if proc_matches.is_full() { break; }
            
            let mut matched = false;
            let mut match_source = "";
            
            // Check exe path
            if !exe_path.is_empty() && fioc.regex.is_match(&exe_path) {
                matched = true;
                match_source = "Executable Path";
            }
            // Check command line
            else if !cmd_line.is_empty() && fioc.regex.is_match(&cmd_line) {
                matched = true;
                match_source = "Command Line";
            }
            
            if matched {
                // Check false positive regex
                let is_fp = if let Some(ref fp_regex) = fioc.regex_fp {
                    ( !exe_path.is_empty() && fp_regex.is_match(&exe_path) ) || 
                    ( !cmd_line.is_empty() && fp_regex.is_match(&cmd_line) )
                } else {
                    false
                };
                
                if !is_fp {
                    let match_message = format!("Filename IOC matched in {} PATTERN: {}", match_source, fioc.pattern);
                    proc_matches.insert(
                        proc_matches.len(),
                        GenMatch { 
                            message: match_message, 
                            score: fioc.score,
                            description: Some(fioc.description.clone()),
                            author: None,
                            matched_strings: None,
                        }
                    );
                }
            }
        }
    }

    // 2. Hash IOCs (Executable File)
    if !proc_matches.is_full() {
        // Use pre-calculated hashes
        let mut hash_match = None;
        
        if let Some(val) = &md5_hash {
            if let Some(ioc) = find_hash_ioc(val, &hash_collections.md5_iocs) { hash_match = Some(ioc); }
        }
        if hash_match.is_none() {
            if let Some(val) = &sha1_hash {
                if let Some(ioc) = find_hash_ioc(val, &hash_collections.sha1_iocs) { hash_match = Some(ioc); }
            }
        }
        if hash_match.is_none() {
            if let Some(val) = &sha256_hash {
                if let Some(ioc) = find_hash_ioc(val, &hash_collections.sha256_iocs) { hash_match = Some(ioc); }
            }
        }
        
        if let Some(ioc) = hash_match {
            let match_message = format!("Process Executable Hash Match HASH: {}", ioc.hash_value);
            proc_matches.insert(
                proc_matches.len(),
                GenMatch { 
                    message: match_message, 
                    score: ioc.score,
                    description: Some(ioc.description.clone()),
                    author: None,
                    matched_strings: None,
                }
            );
        }
    }

    // 3. YARA scanning (Memory)
    // YARA-X: Create scanner and scan process memory
    let mut scanner = Scanner::new(compiled_rules);
    scanner.set_timeout(std::time::Duration::from_secs(30));
    
    // Read process memory
    let mem_data = read_process_memory(pid_u32);

    if !mem_data.is_empty() {
        if let Ok(scan_results) = scanner.scan(&mem_data) {
            logger.debug(&format!("YARA-X scan result for PID: {} PROC_NAME: {} RESULT: {:?}", pid_u32, proc_name_str, scan_results));
            
            for matching_rule in scan_results.matching_rules() {
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
                            
                            let value_str = if data.iter().all(|&b: &_| b.is_ascii() && (b >= 32 || b == 9 || b == 10 || b == 13)) {
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
                    
                    let match_message = format!("YARA-X match with rule {}", rule_id);
                    
                    proc_matches.insert(
                        proc_matches.len(), 
                        GenMatch { 
                            message: match_message, 
                            score,
                            description: if description.is_empty() { None } else { Some(description) },
                            author: if author.is_empty() { None } else { Some(author) },
                            matched_strings: if matched_strings.is_empty() { None } else { Some(matched_strings) },
                        }
                    );
                }
            }
        }
    }
    
    // ------------------------------------------------------------
    // 4. C2 IOC Matching - Check process network connections
    if !proc_matches.is_full() {
        // reuse connections from earlier
        for (remote_ip, remote_port) in &connections {
            if let Some(c2_ioc) = check_c2_match(remote_ip, c2_iocs) {
                let match_message = format!("C2 IOC match in remote address IP: {} PORT: {}", remote_ip, remote_port);
                proc_matches.insert(
                    proc_matches.len(),
                    GenMatch {
                        message: match_message,
                        score: c2_ioc.score,
                        description: Some(c2_ioc.description.clone()),
                        author: None,
                        matched_strings: None,
                    }
                );
                logger.debug(&format!("C2 IOC match found PID: {} PROC_NAME: {} REMOTE: {}:{}", 
                    pid_u32, proc_name_str, remote_ip, remote_port));
            }
        }
    }

    // Show matches on process
    if !proc_matches.is_empty() {
        processes_matched += 1;
        
        let sub_scores: Vec<i16> = proc_matches.iter().map(|m| m.score).collect();
        let total_score = calculate_weighted_score(&sub_scores);
        
        let log_level = if total_score >= scan_config.alert_threshold as f64 {
            alert_count += 1;
            if let Some(state) = scan_state { state.add_alerts(1); }
            LogLevel::Alert
        } else if total_score >= scan_config.warning_threshold as f64 {
            warning_count += 1;
            if let Some(state) = scan_state { state.add_warnings(1); }
            LogLevel::Warning
        } else if total_score >= scan_config.notice_threshold as f64 {
            notice_count += 1;
            if let Some(state) = scan_state { state.add_notices(1); }
            LogLevel::Notice
        } else {
            logger.debug(&format!("Process match below notice threshold PID: {} SCORE: {:.2}", pid_u32, total_score));
            return (processes_scanned, 0, 0, 0, 0);
        };
        
        let reasons_to_show = std::cmp::min(proc_matches.len(), scan_config.max_reasons);
        let shown_reasons: Vec<MatchReason> = proc_matches.iter().take(reasons_to_show)
            .map(|r| MatchReason { 
                message: r.message.clone(), 
                score: r.score,
                description: r.description.clone(),
                author: r.author.clone(),
                matched_strings: r.matched_strings.clone(),
            })
            .collect();
        
        // Unified Logging call
        logger.process_match(
            log_level,
            pid_u32,
            &proc_name_str,
            total_score,
            shown_reasons,
            // Extended metadata
            (md5_hash, sha1_hash, sha256_hash),
            start_time,
            Some(run_time_str),
            Some(memory_bytes),
            Some(cpu_usage),
            Some(connection_count),
            Some(listening_ports)
        );
    }
    
    // Clear current element from status
    if let Some(state) = scan_state {
        state.clear_current_element();
    }

    (processes_scanned, processes_matched, alert_count, warning_count, notice_count)
}

// Helper to get process network info (connections and listening ports)
fn get_process_network_info(pid: u32) -> (Vec<(String, u16)>, Vec<u16>) {
    let mut connections = Vec::new();
    let mut listening_ports = Vec::new();
    
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    
    if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
        for socket in sockets {
            if socket.associated_pids.contains(&pid) {
                match socket.protocol_socket_info {
                    netstat2::ProtocolSocketInfo::Tcp(tcp_info) => {
                        if tcp_info.state == netstat2::TcpState::Listen {
                            listening_ports.push(tcp_info.local_port);
                        } else {
                            // Remote connection
                            let remote_ip = tcp_info.remote_addr.to_string();
                            // Skip localhost and 0.0.0.0
                            if remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" && remote_ip != "::1" && remote_ip != "::" {
                                connections.push((remote_ip, tcp_info.remote_port));
                            }
                        }
                    },
                    netstat2::ProtocolSocketInfo::Udp(_udp_info) => {
                         // Skip UDP for connections
                    }
                }
            }
        }
    }
    
    listening_ports.sort();
    listening_ports.dedup();
    
    (connections, listening_ports)
}

// Platform-specific memory reading
#[cfg(target_os = "windows")]
fn read_process_memory(pid: u32) -> Vec<u8> {
    let mut buffer = Vec::new();
    let max_buffer_size = 100 * 1024 * 1024; // 100 MB limit
    
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
            FALSE, 
            pid
        );
        
        if let Ok(handle) = handle {
            if handle.is_invalid() {
                return buffer;
            }

            let mut address: usize = 0;
            let mut mem_info = MEMORY_BASIC_INFORMATION::default();
            
            while VirtualQueryEx(
                handle, 
                Some(address as *const c_void), 
                &mut mem_info, 
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            ) != 0 {
                // Check if we hit the limit
                if buffer.len() >= max_buffer_size {
                    break;
                }
                
                // Only read committed memory
                if mem_info.State == MEM_COMMIT && 
                   (mem_info.Protect.0 & windows::Win32::System::Memory::PAGE_NOACCESS.0) == 0 &&
                   (mem_info.Protect.0 & windows::Win32::System::Memory::PAGE_GUARD.0) == 0 {
                    
                    let mut chunk = vec![0u8; mem_info.RegionSize];
                    let mut bytes_read: usize = 0;
                    
                    if ReadProcessMemory(
                        handle, 
                        mem_info.BaseAddress, 
                        chunk.as_mut_ptr() as *mut c_void, 
                        mem_info.RegionSize, 
                        Some(&mut bytes_read)
                    ).is_ok() {
                        chunk.truncate(bytes_read);
                        
                        // Enforce remaining limit
                        let remaining = max_buffer_size - buffer.len();
                        if chunk.len() > remaining {
                            chunk.truncate(remaining);
                        }
                        
                        buffer.extend_from_slice(&chunk);
                    }
                }
                
                address = (mem_info.BaseAddress as usize) + mem_info.RegionSize;
            }
            
            let _ = CloseHandle(handle);
        }
    }
    
    buffer
}

#[cfg(target_os = "linux")]
fn read_process_memory(pid: u32) -> Vec<u8> {
    let mut buffer = Vec::new();
    let max_buffer_size = 100 * 1024 * 1024; // 100 MB limit
    
    // Parse /proc/{pid}/maps to find readable regions
    let maps_path = format!("/proc/{}/maps", pid);
    let mem_path = format!("/proc/{}/mem", pid);
    
    let maps_content = match fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return buffer,
    };
    
    let mut mem_file = match fs::File::open(&mem_path) {
        Ok(f) => f,
        Err(_) => return buffer,
    };
    
    for line in maps_content.lines() {
        if buffer.len() >= max_buffer_size {
            break;
        }
        
        // Line format: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 { continue; }
        
        let range_str = parts[0];
        let perms = parts[1];
        
        // Only read readable regions
        if !perms.contains('r') { continue; }
        // Skip shared memory or devices often causing I/O errors?
        // Usually heap/stack are rw-p. Code is r-xp.
        // We read everything readable.
        
        let ranges: Vec<&str> = range_str.split('-').collect();
        if ranges.len() != 2 { continue; }
        
        let start_addr = match u64::from_str_radix(ranges[0], 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let end_addr = match u64::from_str_radix(ranges[1], 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        
        let size = end_addr - start_addr;
        if size == 0 { continue; }
        
        // Limit chunk size to avoid huge allocations
        let read_size = std::cmp::min(size, (max_buffer_size - buffer.len()) as u64) as usize;
        if read_size == 0 { break; }
        
        let mut chunk = vec![0u8; read_size];
        
        if mem_file.seek(SeekFrom::Start(start_addr)).is_ok() {
            if let Ok(bytes_read) = mem_file.read(&mut chunk) {
                chunk.truncate(bytes_read);
                buffer.extend_from_slice(&chunk);
            }
        }
    }
    
    buffer
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn read_process_memory(_pid: u32) -> Vec<u8> {
    Vec::new()
}

// Helper to format runtime in d:h:m:s
fn format_runtime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{}d:{}h:{}m:{}s", days, hours, minutes, secs)
}
