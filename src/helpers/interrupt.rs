use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use std::io::{self, Write};
use colored::Colorize;
use rayon::current_thread_index;

pub struct ScanState {
    pub current_elements: DashMap<usize, String>,
    pub files_scanned: AtomicUsize,
    pub processes_scanned: AtomicUsize,
    pub alerts: AtomicUsize,
    pub warnings: AtomicUsize,
    pub notices: AtomicUsize,
    pub errors: AtomicUsize,
    pub start_time: Instant,
    pub should_exit: AtomicBool,
    pub menu_active: AtomicBool,
}

impl ScanState {
    pub fn new() -> Self {
        Self {
            current_elements: DashMap::new(),
            files_scanned: AtomicUsize::new(0),
            processes_scanned: AtomicUsize::new(0),
            alerts: AtomicUsize::new(0),
            warnings: AtomicUsize::new(0),
            notices: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            start_time: Instant::now(),
            should_exit: AtomicBool::new(false),
            menu_active: AtomicBool::new(false),
        }
    }

    pub fn set_current_element(&self, element: String) {
        if let Some(idx) = current_thread_index() {
            self.current_elements.insert(idx, element);
        }
    }

    pub fn clear_current_element(&self) {
        if let Some(idx) = current_thread_index() {
            self.current_elements.remove(&idx);
        }
    }

    pub fn increment_files(&self) {
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_processes(&self) {
        self.processes_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_alerts(&self, count: usize) {
        self.alerts.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_warnings(&self, count: usize) {
        self.warnings.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_notices(&self, count: usize) {
        self.notices.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn should_stop(&self) -> bool {
        self.should_exit.load(Ordering::Relaxed)
    }

    pub fn wait_for_resume(&self) {
        while self.menu_active.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn format_number(n: usize) -> String {
        let s = n.to_string();
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut result = String::with_capacity(len + (len - 1) / 3);
        
        for (i, b) in bytes.iter().enumerate() {
            result.push(*b as char);
            if (len - i - 1) % 3 == 0 && i != len - 1 {
                result.push('.');
            }
        }
        result
    }

    fn truncate_middle(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            return s.to_string();
        }
        
        let keep_len = (max_len - 3) / 2;
        let start = &s[..keep_len];
        let end = &s[s.len() - keep_len..];
        
        format!("{}...{}", start, end)
    }

    pub fn display_menu(&self) {
        // Set menu active to pause output from other threads if possible
        self.menu_active.store(true, Ordering::SeqCst);
        
        // Clear line to prevent mess
        print!("\r");
        
        let duration = self.start_time.elapsed();
        let files = self.files_scanned.load(Ordering::Relaxed);
        let procs = self.processes_scanned.load(Ordering::Relaxed);
        let alerts = self.alerts.load(Ordering::Relaxed);
        let warnings = self.warnings.load(Ordering::Relaxed);
        let notices = self.notices.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        
        println!("{}", "                                                        ");
        println!("{}", "                                                        ".on_green());
        println!("{}", "                  LOKI INTERRUPT MENU                   ".black().on_green().bold());
        println!("{}", "                                                        ".on_green());
        
        println!("\nSCAN STATISTICS:");
        println!("  Duration:          {:02}:{:02}:{:02}", 
            duration.as_secs() / 3600,
            (duration.as_secs() % 3600) / 60,
            duration.as_secs() % 60);
        println!("  Files scanned:     {}", Self::format_number(files));
        println!("  Processes scanned: {}", Self::format_number(procs));
        println!("  Alerts:            {}", Self::format_number(alerts).red().bold());
        println!("  Warnings:          {}", Self::format_number(warnings).yellow().bold());
        println!("  Notices:           {}", Self::format_number(notices).cyan());
        println!("  Errors:            {}", Self::format_number(errors).purple());
        
        println!("\nCURRENTLY SCANNING ({} threads active):", self.current_elements.len());
        
        // Collect and sort entries by thread ID for consistent display
        let mut entries: Vec<_> = self.current_elements.iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect();
        entries.sort_by_key(|k| k.0);
        
        if entries.is_empty() {
             println!("  (No active scans)");
        } else {
            for (thread_id, element) in entries {
                let display_element = Self::truncate_middle(&element, 75);
                println!("  [{}] {}", thread_id, display_element);
            }
        }
        
        println!("\n{}", "-".repeat(60).bright_black());
        println!("  [E] Exit gracefully    [X] Exit immediately    [C] Continue scan");
        println!("{}", "-".repeat(60).bright_black());
        
        print!("> ");
        io::stdout().flush().unwrap();
        
        // Simple input loop
        loop {
            let mut input = String::new();
            match io::stdin().read_line(&mut input) {
                Ok(_) => {
                    let cmd = input.trim().to_uppercase();
                    match cmd.as_str() {
                        "E" | "EXIT" => {
                            println!("Exiting gracefully... (please wait)");
                            self.should_exit.store(true, Ordering::SeqCst);
                            break;
                        },
                        "X" | "KILL" | "QUIT" => {
                            println!("Exiting immediately...");
                            std::process::exit(0);
                        },
                        "C" | "CONTINUE" => {
                            println!("Resuming scan...");
                            break;
                        },
                        _ => {
                            print!("Invalid option. [E]xit, [X] immediate or [C]ontinue > ");
                            io::stdout().flush().unwrap();
                        }
                    }
                },
                Err(_) => {
                    // If reading stdin fails, default to exit
                    self.should_exit.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        
        self.menu_active.store(false, Ordering::SeqCst);
    }
}
