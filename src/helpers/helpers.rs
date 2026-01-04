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