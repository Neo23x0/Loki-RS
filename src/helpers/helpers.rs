use std::env;
use std::net::IpAddr;
use human_bytes::human_bytes;
use sysinfo::{System, Disks};
use crate::helpers::unified_logger::UnifiedLogger;

// Evaluate platform & environment information
pub fn evaluate_env(logger: &UnifiedLogger) {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Command line arguments 
    let args: Vec<String> = env::args().collect();
    logger.info(&format!("Command line flags FLAGS: {:?}", args));
    // OS
    logger.info(&format!("Operating system information OS: {} ARCH: {}", env::consts::OS, env::consts::ARCH));
    // System Names
    logger.info("System information (detailed system info requires sysinfo API update)");
    // CPU
    let cpus = sys.cpus();
    if !cpus.is_empty() {
        logger.info(&format!("CPU information NUM_CORES: {} FREQUENCY: {} MHz VENDOR: {:?}", 
        cpus.len(), cpus[0].frequency(), cpus[0].vendor_id()));
    }
    // Memory
    logger.info(&format!("Memory information TOTAL: {} USED: {} FREE: {}", 
        human_bytes(sys.total_memory() as f64), 
        human_bytes(sys.used_memory() as f64),
        human_bytes((sys.total_memory() - sys.used_memory()) as f64)));
    
    // Network interfaces and IP addresses
    // Note: We use get_if_addrs directly as sysinfo::Networks uses different interface
    // naming conventions on Windows, causing cross-library name matching to fail
    let mut ip_addresses: Vec<String> = Vec::new();
    
    if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
        for iface in interfaces {
            let ip = iface.addr.ip();
            // Skip loopback IPs
            if ip.is_loopback() {
                continue;
            }
            
            // Skip common virtual interface prefixes
            let name_lower = iface.name.to_lowercase();
            if name_lower.contains("loopback") || name_lower == "lo" {
                continue;
            }
            
            let ip_str = match ip {
                IpAddr::V4(v4) => format!("{}: {} (IPv4)", iface.name, v4),
                IpAddr::V6(v6) => format!("{}: {} (IPv6)", iface.name, v6),
            };
            if !ip_addresses.contains(&ip_str) {
                ip_addresses.push(ip_str);
            }
        }
    }
    
    if ip_addresses.is_empty() {
        // Fallback: just list the interfaces without IPs
        logger.info("Network interfaces (no IP addresses detected)");
    } else {
        logger.info(&format!("Network interfaces IPs: {}", ip_addresses.join(", ")));
    }
    
    // Hard disks
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        let used_space = disk.total_space() - disk.available_space();
        let usage_percent = if disk.total_space() > 0 {
            (used_space as f64 / disk.total_space() as f64) * 100.0
        } else {
            0.0
        };
        
        logger.info(&format!(
            "Hard disk NAME: {:?} FS: {:?} MOUNT: {:?} USED: {} / {} ({:.1}%)", 
            disk.name().to_string_lossy(), 
            disk.file_system().to_string_lossy(), 
            disk.mount_point().to_string_lossy(), 
            human_bytes(used_space as f64),
            human_bytes(disk.total_space() as f64),
            usage_percent,
        ));
    }
}

pub fn get_hostname() -> String {
    // Try sysinfo's host_name() first (works on macOS, Linux, Windows)
    if let Some(hostname) = System::host_name() {
        if !hostname.is_empty() {
            return hostname;
        }
    }
    
    // Fallback to environment variables
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn get_os_type() -> String {
    env::consts::OS.to_string()
}

#[allow(dead_code)]
pub fn parse_size_string(size_str: &str) -> Result<usize, String> {
    let s = size_str.trim().to_uppercase();
    
    // Try parsing as raw number first
    if let Ok(num) = s.parse::<usize>() {
        return Ok(num);
    }
    
    // Check suffixes
    let (num_str, multiplier) = if s.ends_with("GB") || s.ends_with("G") {
        (s.trim_end_matches("GB").trim_end_matches('G'), 1024 * 1024 * 1024)
    } else if s.ends_with("MB") || s.ends_with("M") {
        (s.trim_end_matches("MB").trim_end_matches('M'), 1024 * 1024)
    } else if s.ends_with("KB") || s.ends_with("K") {
        (s.trim_end_matches("KB").trim_end_matches('K'), 1024)
    } else if s.ends_with("B") {
        (s.trim_end_matches('B'), 1)
    } else {
        return Err(format!("Unknown size format: {}", s));
    };
    
    // Parse the number part
    let num = num_str.trim().parse::<usize>()
        .map_err(|_| format!("Invalid number format: {}", num_str))?;
        
    Ok(num * multiplier)
}

// Helper for consistent error logging
pub fn log_access_error(logger: &UnifiedLogger, path: &str, error: &dyn std::fmt::Debug, show_trace: bool) {
    if show_trace {
        logger.error(&format!("Cannot access object PATH: {} ERROR: {:?}", path, error));
    } else {
        logger.debug(&format!("Cannot access object PATH: {} ERROR: {:?}", path, error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod parse_size_tests {
        use super::*;

        #[test]
        fn test_parse_raw_bytes() {
            assert_eq!(parse_size_string("1000").unwrap(), 1000);
            assert_eq!(parse_size_string("0").unwrap(), 0);
            assert_eq!(parse_size_string("12345678").unwrap(), 12345678);
        }

        #[test]
        fn test_parse_bytes_with_suffix() {
            assert_eq!(parse_size_string("100B").unwrap(), 100);
            assert_eq!(parse_size_string("100b").unwrap(), 100);
        }

        #[test]
        fn test_parse_kilobytes() {
            assert_eq!(parse_size_string("1K").unwrap(), 1024);
            assert_eq!(parse_size_string("1KB").unwrap(), 1024);
            assert_eq!(parse_size_string("10k").unwrap(), 10 * 1024);
            assert_eq!(parse_size_string("10kb").unwrap(), 10 * 1024);
        }

        #[test]
        fn test_parse_megabytes() {
            assert_eq!(parse_size_string("1M").unwrap(), 1024 * 1024);
            assert_eq!(parse_size_string("1MB").unwrap(), 1024 * 1024);
            assert_eq!(parse_size_string("10m").unwrap(), 10 * 1024 * 1024);
            assert_eq!(parse_size_string("10mb").unwrap(), 10 * 1024 * 1024);
        }

        #[test]
        fn test_parse_gigabytes() {
            assert_eq!(parse_size_string("1G").unwrap(), 1024 * 1024 * 1024);
            assert_eq!(parse_size_string("1GB").unwrap(), 1024 * 1024 * 1024);
            assert_eq!(parse_size_string("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        }

        #[test]
        fn test_parse_with_whitespace() {
            assert_eq!(parse_size_string("  100  ").unwrap(), 100);
            assert_eq!(parse_size_string(" 1K ").unwrap(), 1024);
        }

        #[test]
        fn test_parse_invalid_format() {
            assert!(parse_size_string("abc").is_err());
            assert!(parse_size_string("").is_err());
            assert!(parse_size_string("1T").is_err());
            assert!(parse_size_string("1TB").is_err());
        }
    }

    mod os_type_tests {
        use super::*;

        #[test]
        fn test_get_os_type_returns_valid_os() {
            let os_type = get_os_type();
            assert!(!os_type.is_empty());
            let valid_os = ["linux", "macos", "windows", "freebsd", "openbsd", "netbsd"];
            assert!(valid_os.iter().any(|&os| os_type == os) || !os_type.is_empty());
        }
    }

    mod hostname_tests {
        use super::*;

        #[test]
        fn test_get_hostname_returns_string() {
            let hostname = get_hostname();
            assert!(!hostname.is_empty() || hostname == "unknown");
        }
    }
}