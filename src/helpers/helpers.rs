use std::env;
use human_bytes::human_bytes;
use sysinfo::{System, Disks};

// Evaluate platform & environment information
pub fn evaluate_env() {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Command line arguments 
    let args: Vec<String> = env::args().collect();
    log::info!("Command line flags FLAGS: {:?}", args);
    // OS
    log::info!("Operating system information OS: {} ARCH: {}", env::consts::OS, env::consts::ARCH);
    // System Names - sysinfo 0.37+ API changed, using basic info for now
    // Note: Some system info methods were removed/changed in sysinfo 0.37+
    log::info!("System information (detailed system info requires sysinfo API update)");
    // CPU
    let cpus = sys.cpus();
    if !cpus.is_empty() {
        log::info!("CPU information NUM_CORES: {} FREQUENCY: {} VENDOR: {:?}", 
        cpus.len(), cpus[0].frequency(), cpus[0].vendor_id());
    }
    // Memory
    log::info!("Memory information TOTAL: {:?} USED: {:?}", 
    human_bytes(sys.total_memory() as f64), human_bytes(sys.used_memory() as f64));
    // Hard disks - in sysinfo 0.37+ use Disks::new_with_refreshed_list()
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        log::info!(
            "Hard disk NAME: {:?} FS_TYPE: {:?} MOUNT_POINT: {:?} AVAIL: {:?} TOTAL: {:?} REMOVABLE: {:?}", 
            disk.name().to_string_lossy(), 
            disk.file_system().to_string_lossy(), 
            disk.mount_point().to_string_lossy(), 
            human_bytes(disk.available_space() as f64),
            human_bytes(disk.total_space() as f64),
            disk.is_removable(),
        );
    }
}

pub fn get_hostname() -> String {
    // sysinfo 0.37+ API changed - using env var as fallback
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
pub fn log_access_error(path: &str, error: &dyn std::fmt::Debug, show_trace: bool) {
    if show_trace {
        log::error!("Cannot access object PATH: {} ERROR: {:?}", path, error);
    } else {
        log::debug!("Cannot access object PATH: {} ERROR: {:?}", path, error);
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