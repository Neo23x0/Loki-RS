use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpStream, UdpSocket, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::collections::BTreeMap;
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Serialize, Serializer};
use crate::helpers::helpers::get_hostname;

// --- Enums & Structs ---

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub enum LogLevel {
    Alert,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Serialize for LogLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            LogLevel::Alert => serializer.serialize_str("ALERT"),
            LogLevel::Warning => serializer.serialize_str("WARNING"),
            LogLevel::Notice => serializer.serialize_str("NOTICE"),
            LogLevel::Info => serializer.serialize_str("INFO"),
            LogLevel::Error => serializer.serialize_str("ERROR"),
            LogLevel::Debug => serializer.serialize_str("DEBUG"),
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Alert => write!(f, "ALERT"),
            LogLevel::Warning => write!(f, "WARNING"),
            LogLevel::Notice => write!(f, "NOTICE"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ScanStart,
    ScanEnd,
    FileMatch,
    ProcessMatch,
    Info,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchReason {
    pub message: String,
    pub score: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_strings: Option<Vec<String>>,
}

fn serialize_dt<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = date.to_rfc3339();
    serializer.serialize_str(&s)
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    #[serde(serialize_with = "serialize_dt")]
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub event_type: EventType,
    pub hostname: String,
    pub message: String,
    
    // Structured context
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    
    // File timestamps (RFC3339 format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_accessed: Option<String>,
    
    // Process-specific extended metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_usage: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listening_ports: Option<Vec<u16>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<MatchReason>>,
}

// --- TUI Messages (defined here to avoid circular imports) ---

#[derive(Debug, Clone)]
pub enum TuiMessage {
    Log(LogEvent),
    ScanComplete,
    /// Progress message during initialization (e.g., "Loading YARA rules...")
    InitProgress(String),
    /// Initialization complete with final counts (yara_rules_count, ioc_count)
    InitComplete { yara_rules_count: usize, ioc_count: usize },
}

// --- Output Trait ---

pub trait LogOutput: Send + Sync {
    fn write(&self, event: &LogEvent) -> Result<(), std::io::Error>;
}

// --- Console Output ---

pub struct ConsoleOutput;

impl LogOutput for ConsoleOutput {
    fn write(&self, event: &LogEvent) -> Result<(), std::io::Error> {
        // Only log operational info/errors to console if explicitly provided
        // or matches. We mimic the old behavior:
        // - Matches: Alert/Warn/Notice colors
        // - Info/Error: Standard logging colors
        
        let level_str = match event.level {
            LogLevel::Alert => "[ALERT]".black().on_red().to_string(),
            LogLevel::Warning => "[WARNING]".black().on_yellow().to_string(),
            LogLevel::Notice => "[NOTICE]".black().on_cyan().to_string(),
            LogLevel::Info => "[INFO]".black().on_green().to_string(),
            LogLevel::Error => "[ERROR]".black().on_purple().to_string(),
            LogLevel::Debug => "[DEBUG]".black().on_white().to_string(),
        };

        match event.event_type {
            EventType::FileMatch | EventType::ProcessMatch => {
                // Multi-line detailed output for matches
                let path_or_proc = event.file_path.as_deref()
                    .or(event.process_name.as_deref())
                    .unwrap_or("unknown");
                
                println!("{} Match found: {}", level_str, path_or_proc.white());
                
                if let Some(score) = event.score {
                    println!("      SCORE: {}", (score.round() as i16).to_string().white());
                }
                if let Some(reasons) = &event.reasons {
                    for (i, r) in reasons.iter().enumerate() {
                        // Format reason with structured fields for console display
                        let mut reason_display = r.message.clone();
                        if let Some(desc) = &r.description {
                            reason_display.push_str(&format!("\n         DESC: {}", desc));
                        }
                        if let Some(author) = &r.author {
                            reason_display.push_str(&format!("\n         AUTHOR: {}", author));
                        }
                        if let Some(strings) = &r.matched_strings {
                            if !strings.is_empty() {
                                let display_strings: Vec<&str> = strings.iter().take(3).map(|s| s.as_str()).collect();
                                reason_display.push_str(&format!("\n         STRINGS: {}", display_strings.join(" ")));
                                if strings.len() > 3 {
                                    reason_display.push_str(&format!(" (and {} more)", strings.len() - 3));
                                }
                            }
                        }
                        println!("      REASON_{}: {} (Score: {})", i+1, reason_display.white(), r.score);
                    }
                }
                // Print hashes if available
                if let Some(md5) = &event.md5 { println!("      MD5: {}", md5.white()); }
                if let Some(sha1) = &event.sha1 { println!("      SHA1: {}", sha1.white()); }
                if let Some(sha256) = &event.sha256 { println!("      SHA256: {}", sha256.white()); }
                
                // Print structured context if available
                for (key, value) in &event.context {
                    println!("      {}: {}", key.green(), value.white());
                }
            },
            _ => {
                // Check if this is an "ANALYZED" message (process info) - display multi-line
                if event.message.starts_with("ANALYZED:") && !event.context.is_empty() {
                    // Extract process name from message
                    let proc_name = event.message.strip_prefix("ANALYZED: ").unwrap_or(&event.message);
                    println!("{}: {}", "ANALYZED".green(), proc_name.white());
                    
                    // Display context in a structured multi-line format with colors
                    // Group related fields for better readability
                    let basic_fields = ["PID", "PPID", "USER", "STATUS"];
                    let hash_fields = ["MD5", "SHA1", "SHA256"];
                    
                    // Print basic process info on one line
                    let mut basic_line = String::from("      ");
                    for field in basic_fields.iter() {
                        if let Some(value) = event.context.get(*field) {
                            basic_line.push_str(&format!("{}: {} ", field.green(), value.white()));
                        }
                    }
                    println!("{}", basic_line.trim_end());
                    
                    // Print CMD on its own line (can be long)
                    if let Some(cmd) = event.context.get("CMD") {
                        println!("      {}: {}", "CMD".green(), cmd.white());
                    }
                    
                    // Print runtime/start info
                    let mut runtime_line = String::from("      ");
                    if let Some(rt) = event.context.get("RUNTIME") {
                        runtime_line.push_str(&format!("{}: {} ", "RUNTIME".green(), rt.white()));
                    }
                    if let Some(st) = event.context.get("START") {
                        runtime_line.push_str(&format!("{}: {}", "START".green(), st.white()));
                    }
                    if runtime_line.len() > 6 {
                        println!("{}", runtime_line.trim_end());
                    }
                    
                    // Print memory/CPU info
                    let mut mem_line = String::from("      ");
                    if let Some(mem) = event.context.get("MEM") {
                        mem_line.push_str(&format!("{}: {} ", "MEM".green(), mem.white()));
                    }
                    if let Some(cpu) = event.context.get("CPU") {
                        mem_line.push_str(&format!("{}: {}", "CPU".green(), cpu.white()));
                    }
                    if mem_line.len() > 6 {
                        println!("{}", mem_line.trim_end());
                    }
                    
                    // Print hashes
                    for field in hash_fields.iter() {
                        if let Some(value) = event.context.get(*field) {
                            println!("      {}: {}", field.green(), value.white());
                        }
                    }
                    
                    // Print network info
                    let mut net_line = String::from("      ");
                    if let Some(conn) = event.context.get("CONN") {
                        net_line.push_str(&format!("{}: {} ", "CONN".green(), conn.white()));
                    }
                    if let Some(listen) = event.context.get("LISTEN") {
                        net_line.push_str(&format!("{}: {}", "LISTEN".green(), listen.white()));
                    }
                    if net_line.len() > 6 {
                        println!("{}", net_line.trim_end());
                    }
                } else {
                    // Standard single line for other info messages
                    print!(" {} {}", level_str, event.message);
                    
                    // Print structured context inline
                    for (key, value) in &event.context {
                        print!(" {}: {}", key.green(), value.white());
                    }
                    println!();
                }
            }
        }
        Ok(())
    }
}

// Helper to strip ANSI codes
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
            continue;
        }
        result.push(c);
    }
    result
}

// --- Plain Text File Output ---

pub struct PlainTextFileOutput {
    file: Mutex<File>,
}

impl PlainTextFileOutput {
    pub fn new(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl LogOutput for PlainTextFileOutput {
    fn write(&self, event: &LogEvent) -> io::Result<()> {
        let mut file = self.file.lock().unwrap();
        
        // Format: Timestamp HOSTNAME LEVEL Message
        let timestamp = event.timestamp.format("%Y-%m-%dT%H:%M:%SZ");
        let level = event.level;
        
        let mut message = match event.event_type {
            EventType::FileMatch | EventType::ProcessMatch => {
                // Construct detailed message for matches
                let target = event.file_path.as_deref()
                    .or(event.process_name.as_deref())
                    .unwrap_or("unknown");
                let score = event.score.unwrap_or(0.0);
                
                let mut reasons_str = String::new();
                if let Some(reasons) = &event.reasons {
                    let r_msgs: Vec<String> = reasons.iter().map(|r| {
                        let mut reason_text = r.message.clone();
                        if let Some(desc) = &r.description {
                            reason_text.push_str(&format!(" DESC: {}", desc));
                        }
                        if let Some(author) = &r.author {
                            reason_text.push_str(&format!(" AUTHOR: {}", author));
                        }
                        reason_text
                    }).collect();
                    reasons_str = r_msgs.join("; ");
                }
                
                format!("Match: {} SCORE: {} REASONS: [{}]", target, score.round() as i16, reasons_str)
            },
            _ => {
                event.message.clone()
            }
        };

        // Append structured context if present
        if !event.context.is_empty() {
            let mut context_parts = Vec::new();
            for (k, v) in &event.context {
                context_parts.push(format!("{}={}", k, v));
            }
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&context_parts.join(" "));
        }

        // Strip newlines and ANSI codes for single-line log
        let clean_msg = strip_ansi(&message).replace('\n', " ").replace('\r', "");
        
        writeln!(file, "{} {} {} {}", timestamp, event.hostname, level, clean_msg)?;
        file.flush()?;
        Ok(())
    }
}

// --- JSONL File Output ---

pub struct JsonlFileOutput {
    file: Mutex<File>,
}

impl JsonlFileOutput {
    pub fn new(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl LogOutput for JsonlFileOutput {
    fn write(&self, event: &LogEvent) -> io::Result<()> {
        let mut file = self.file.lock().unwrap();
        
        // Create a clone of the event and strip ANSI codes from all string fields
        let mut clean_event = event.clone(); 
        
        // Strip ANSI from message
        clean_event.message = strip_ansi(&clean_event.message);
        
        // Strip ANSI from context values
        clean_event.context = clean_event.context.into_iter()
            .map(|(k, v)| (k, strip_ansi(&v)))
            .collect();
        
        // Strip ANSI from reasons
        if let Some(reasons) = &mut clean_event.reasons {
            for reason in reasons.iter_mut() {
                reason.message = strip_ansi(&reason.message);
            }
        }
        
        let json = serde_json::to_string(&clean_event)?;
        writeln!(file, "{}", json)?;
        file.flush()?;
        Ok(())
    }
}

// --- Remote Output ---

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RemoteProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RemoteFormat {
    Syslog,
    Json,
}

pub struct RemoteOutput {
    host: String,
    port: u16,
    protocol: RemoteProtocol,
    format: RemoteFormat,
    udp_socket: Option<UdpSocket>,
    // TCP stream is harder to keep persistent simply due to disconnects, 
    // we might reconnect on demand or keep a mutex'd stream. 
    // For simplicity/robustness in this plan, we'll try to connect-send-close for TCP 
    // or keep a cached connection with retry. Let's try connect-send-close for now to be safe against timeouts,
    // or better: a Mutex<Option<TcpStream>> with reconnect logic.
    tcp_stream: Mutex<Option<TcpStream>>,
}

impl RemoteOutput {
    pub fn new(host: &str, port: u16, protocol: RemoteProtocol, format: RemoteFormat) -> io::Result<Self> {
        let udp_socket = if protocol == RemoteProtocol::Udp {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.connect(format!("{}:{}", host, port))?;
            Some(socket)
        } else {
            None
        };

        Ok(Self {
            host: host.to_string(),
            port,
            protocol,
            format,
            udp_socket,
            tcp_stream: Mutex::new(None),
        })
    }

    fn format_event(&self, event: &LogEvent) -> String {
        match self.format {
            RemoteFormat::Json => {
                // Clone and strip ANSI for JSON format
                let mut clean_event = event.clone();
                clean_event.message = strip_ansi(&clean_event.message);
                serde_json::to_string(&clean_event).unwrap_or_default()
            },
            RemoteFormat::Syslog => {
                // RFC 5424 compliant-ish or simple syslog: <PRI>TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
                // We'll use a simpler BSD format <PRI>Timestamp Hostname Message for compatibility
                // PRI: Facility(1=user) * 8 + Severity
                let severity = match event.level {
                    LogLevel::Alert => 1,
                    LogLevel::Error => 3,
                    LogLevel::Warning => 4,
                    LogLevel::Notice => 5,
                    LogLevel::Info => 6,
                    LogLevel::Debug => 7,
                };
                let facility = 1; // user-level
                let pri = facility * 8 + severity;
                let timestamp = event.timestamp.format("%b %d %H:%M:%S"); // Local or UTC? Syslog usually local. 
                // Let's use the event timestamp which is UTC, but format it cleanly.
                
                let mut message = if event.message.is_empty() {
                    // Reconstruct message same as PlainText
                     let target = event.file_path.as_deref()
                        .or(event.process_name.as_deref())
                        .unwrap_or("unknown");
                    format!("Loki-RS Match: {} Score: {:?}", target, event.score.unwrap_or(0.0))
                } else {
                    event.message.clone()
                };

                // Append structured context if present
                if !event.context.is_empty() {
                    let mut context_parts = Vec::new();
                    for (k, v) in &event.context {
                        context_parts.push(format!("{}={}", k, v));
                    }
                    if !message.is_empty() {
                        message.push(' ');
                    }
                    message.push_str(&context_parts.join(" "));
                }
                
                // Strip ANSI codes for syslog
                let clean_msg = strip_ansi(&message).replace('\n', " ");
                
                format!("<{}>{} {} Loki-RS: {}", pri, timestamp, event.hostname, clean_msg)
            }
        }
    }
}

impl LogOutput for RemoteOutput {
    fn write(&self, event: &LogEvent) -> io::Result<()> {
        let payload = self.format_event(event);
        let bytes = payload.as_bytes();

        match self.protocol {
            RemoteProtocol::Udp => {
                if let Some(socket) = &self.udp_socket {
                    // Ignore errors to not block scanning
                    let _ = socket.send(bytes);
                }
            }
            RemoteProtocol::Tcp => {
                let mut stream_guard = self.tcp_stream.lock().unwrap();
                
                // Helper to try writing
                let mut write_success = false;
                
                if let Some(stream) = stream_guard.as_mut() {
                     if stream.write_all(bytes).is_ok() {
                         let _ = stream.write_all(b"\n"); // Framed by newline usually
                         write_success = true;
                     }
                }

                if !write_success {
                    // Reconnect - resolve hostname to socket addresses
                    let addr_str = format!("{}:{}", self.host, self.port);
                    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                        if let Some(addr) = addrs.next() {
                            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                                let _ = stream.write_all(bytes);
                                let _ = stream.write_all(b"\n");
                                *stream_guard = Some(stream);
                            } else {
                                // Failed to connect, drop connection
                                *stream_guard = None;
                            }
                        }
                    } else {
                        // Failed to resolve, drop connection
                        *stream_guard = None;
                    }
                }
            }
        }
        Ok(())
    }
}

// --- TUI Output (sends events to TUI via channel) ---

pub struct TuiLogOutput {
    sender: Sender<TuiMessage>,
}

impl TuiLogOutput {
    pub fn new(sender: Sender<TuiMessage>) -> Self {
        Self { sender }
    }
}

impl LogOutput for TuiLogOutput {
    fn write(&self, event: &LogEvent) -> io::Result<()> {
        // Send log event to TUI - ignore errors if receiver dropped
        let _ = self.sender.send(TuiMessage::Log(event.clone()));
        Ok(())
    }
}

// --- Configuration ---

pub struct RemoteConfig {
    pub host: String,
    pub port: u16,
    pub protocol: RemoteProtocol,
    pub format: RemoteFormat,
}

pub struct LoggerConfig {
    pub console: bool,
    pub log_level: LogLevel,
    pub log_file: Option<String>,
    pub jsonl_file: Option<String>,
    pub remote: Option<RemoteConfig>,
    pub tui_sender: Option<Sender<TuiMessage>>,
}

// --- Unified Logger ---

pub struct UnifiedLogger {
    outputs: Vec<Box<dyn LogOutput>>,
    hostname: String,
    log_level: LogLevel,
}

impl UnifiedLogger {
    pub fn new(config: LoggerConfig) -> io::Result<Self> {
        let mut outputs: Vec<Box<dyn LogOutput>> = Vec::new();
        let hostname = get_hostname();

        // Add TUI output if enabled (takes precedence over console)
        if let Some(sender) = config.tui_sender {
            outputs.push(Box::new(TuiLogOutput::new(sender)));
        } else if config.console {
            // Only add console output if TUI is not enabled
            outputs.push(Box::new(ConsoleOutput));
        }

        if let Some(path) = config.log_file {
            outputs.push(Box::new(PlainTextFileOutput::new(&path)?));
        }

        if let Some(path) = config.jsonl_file {
            outputs.push(Box::new(JsonlFileOutput::new(&path)?));
        }

        if let Some(remote) = config.remote {
            match RemoteOutput::new(&remote.host, remote.port, remote.protocol, remote.format) {
                Ok(ro) => outputs.push(Box::new(ro)),
                Err(e) => eprintln!("Warning: Failed to initialize remote logging: {}", e),
            }
        }

        Ok(Self { outputs, hostname, log_level: config.log_level })
    }

    pub fn log(&self, mut event: LogEvent) {
        if event.level > self.log_level {
            return;
        }

        // Ensure hostname is set if not already
        if event.hostname.is_empty() {
            event.hostname = self.hostname.clone();
        }

        for output in &self.outputs {
            if let Err(e) = output.write(&event) {
                // We fallback to stderr if logging fails, but try to avoid spamming
                eprintln!("Logging failed: {}", e);
            }
        }
    }

    // --- Convenience Methods ---

    pub fn scan_start(&self, version: &str) {
        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            event_type: EventType::ScanStart,
            hostname: self.hostname.clone(),
            message: format!("Loki-RS scan started VERSION: {}", version),
            context: BTreeMap::new(),
            // Defaults
            file_path: None, pid: None, process_name: None, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    pub fn scan_end(&self, summary: &str, duration_msg: &str) {
        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            event_type: EventType::ScanEnd,
            hostname: self.hostname.clone(),
            message: format!("Loki-RS scan finished. {}. {}", summary, duration_msg),
            context: BTreeMap::new(),
            file_path: None, pid: None, process_name: None, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    pub fn info(&self, msg: &str) {
        self.info_w(msg, &[]);
    }

    pub fn info_w(&self, msg: &str, context: &[(&str, &str)]) {
        let mut context_map = BTreeMap::new();
        for (k, v) in context {
            context_map.insert(k.to_string(), v.to_string());
        }

        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            event_type: EventType::Info,
            hostname: self.hostname.clone(),
            message: msg.to_string(),
            context: context_map,
            file_path: None, pid: None, process_name: None, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    pub fn warning(&self, msg: &str) {
        self.warning_w(msg, &[]);
    }

    pub fn warning_w(&self, msg: &str, context: &[(&str, &str)]) {
        let mut context_map = BTreeMap::new();
        for (k, v) in context {
            context_map.insert(k.to_string(), v.to_string());
        }

        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Warning,
            event_type: EventType::Info, // Operational warning
            hostname: self.hostname.clone(),
            message: msg.to_string(),
            context: context_map,
            file_path: None, pid: None, process_name: None, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }
    
    pub fn error(&self, msg: &str) {
        self.error_w(msg, &[]);
    }

    pub fn error_w(&self, msg: &str, context: &[(&str, &str)]) {
        let mut context_map = BTreeMap::new();
        for (k, v) in context {
            context_map.insert(k.to_string(), v.to_string());
        }

        self.error_with_target(msg, context_map, None, None, None);
    }

    pub fn file_error(&self, msg: &str, path: &str) {
        self.error_with_target(
            msg,
            BTreeMap::new(),
            Some(path.to_string()),
            None,
            None,
        );
    }

    pub fn process_error(&self, msg: &str, pid: u32, process_name: &str) {
        self.error_with_target(
            msg,
            BTreeMap::new(),
            None,
            Some(pid),
            Some(process_name.to_string()),
        );
    }

    fn error_with_target(
        &self,
        msg: &str,
        context: BTreeMap<String, String>,
        file_path: Option<String>,
        pid: Option<u32>,
        process_name: Option<String>,
    ) {
        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Error,
            event_type: EventType::Error,
            hostname: self.hostname.clone(),
            message: msg.to_string(),
            context,
            file_path, pid, process_name, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    pub fn debug(&self, msg: &str) {
        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Debug,
            event_type: EventType::Info,
            hostname: self.hostname.clone(),
            message: msg.to_string(),
            context: BTreeMap::new(),
            file_path: None, pid: None, process_name: None, score: None,
            file_type: None, file_size: None, md5: None, sha1: None, sha256: None, reasons: None,
            file_created: None, file_modified: None, file_accessed: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn file_match(
        &self,
        level: LogLevel,
        path: &str,
        score: f64,
        file_type: &str,
        file_size: u64,
        md5: &str,
        sha1: &str,
        sha256: &str,
        reasons: Vec<MatchReason>,
        // File timestamps (created, modified, accessed) - RFC3339 strings
        timestamps: Option<(Option<String>, Option<String>, Option<String>)>,
    ) {
        let (file_created, file_modified, file_accessed) = timestamps.unwrap_or((None, None, None));
        self.log(LogEvent {
            timestamp: Utc::now(),
            level,
            event_type: EventType::FileMatch,
            hostname: self.hostname.clone(),
            message: "File Match".to_string(),
            context: BTreeMap::new(),
            file_path: Some(path.to_string()),
            score: Some(score),
            file_type: Some(file_type.to_string()),
            file_size: Some(file_size),
            md5: Some(md5.to_string()),
            sha1: Some(sha1.to_string()),
            sha256: Some(sha256.to_string()),
            file_created,
            file_modified,
            file_accessed,
            reasons: Some(reasons),
            // Defaults
            pid: None, process_name: None,
            start_time: None, run_time: None, memory_bytes: None, cpu_usage: None, connection_count: None, listening_ports: None,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_match(
        &self,
        level: LogLevel,
        pid: u32,
        process_name: &str,
        score: f64,
        reasons: Vec<MatchReason>,
        // Extended metadata
        hashes: (Option<String>, Option<String>, Option<String>), // md5, sha1, sha256
        start_time: Option<i64>,
        run_time: Option<String>,
        memory_bytes: Option<u64>,
        cpu_usage: Option<f32>,
        connection_count: Option<usize>,
        listening_ports: Option<Vec<u16>>,
    ) {
        self.log(LogEvent {
            timestamp: Utc::now(),
            level,
            event_type: EventType::ProcessMatch,
            hostname: self.hostname.clone(),
            message: "Process Match".to_string(),
            context: BTreeMap::new(),
            pid: Some(pid),
            process_name: Some(process_name.to_string()),
            score: Some(score),
            reasons: Some(reasons),
            
            md5: hashes.0,
            sha1: hashes.1,
            sha256: hashes.2,
            start_time,
            run_time,
            memory_bytes,
            cpu_usage,
            connection_count,
            listening_ports,

            // Defaults
            file_path: None, file_type: None, file_size: None,
            file_created: None, file_modified: None, file_accessed: None,
        });
    }
}

// =========================================================================
// Test Module 2: SIEM Integration Tests
// Tests RemoteOutput::format_event() for syslog and JSON formats
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Create a test LogEvent with configurable parameters
    fn create_test_event(level: LogLevel, message: &str) -> LogEvent {
        let mut context = BTreeMap::new();
        context.insert("test_key".to_string(), "test_value".to_string());
        
        LogEvent {
            timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            level,
            event_type: EventType::Info,
            hostname: "test-host".to_string(),
            message: message.to_string(),
            context,
            file_path: None,
            pid: None,
            process_name: None,
            score: None,
            file_type: None,
            file_size: None,
            md5: None,
            sha1: None,
            sha256: None,
            file_created: None,
            file_modified: None,
            file_accessed: None,
            start_time: None,
            run_time: None,
            memory_bytes: None,
            cpu_usage: None,
            connection_count: None,
            listening_ports: None,
            reasons: None,
        }
    }

    // --- Syslog Format Tests ---
    
    mod syslog_format_tests {
        use super::*;

        fn create_remote_output_syslog() -> RemoteOutput {
            // Create a RemoteOutput configured for syslog format
            // Note: We can't actually connect, but we can test format_event
            RemoteOutput {
                host: "127.0.0.1".to_string(),
                port: 514,
                protocol: RemoteProtocol::Udp,
                format: RemoteFormat::Syslog,
                udp_socket: None,
                tcp_stream: std::sync::Mutex::new(None),
            }
        }

        #[test]
        fn test_syslog_format_structure() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Warning, "Test warning message");
            
            let formatted = output.format_event(&event);
            
            // Should start with <PRI>
            assert!(formatted.starts_with('<'), "Syslog should start with <PRI>");
            
            // Should contain hostname
            assert!(formatted.contains("test-host"), "Should contain hostname");
            
            // Should contain Loki-RS identifier
            assert!(formatted.contains("Loki-RS:"), "Should contain Loki-RS identifier");
            
            // Should contain the message
            assert!(formatted.contains("Test warning message"), "Should contain message");
        }

        #[test]
        fn test_syslog_severity_mapping_alert() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Alert, "Alert message");
            
            let formatted = output.format_event(&event);
            
            // Alert = severity 1, facility 1 → PRI = 1*8 + 1 = 9
            assert!(formatted.starts_with("<9>"), "Alert should have PRI=9");
        }

        #[test]
        fn test_syslog_severity_mapping_error() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Error, "Error message");
            
            let formatted = output.format_event(&event);
            
            // Error = severity 3, facility 1 → PRI = 1*8 + 3 = 11
            assert!(formatted.starts_with("<11>"), "Error should have PRI=11");
        }

        #[test]
        fn test_syslog_severity_mapping_warning() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Warning, "Warning message");
            
            let formatted = output.format_event(&event);
            
            // Warning = severity 4, facility 1 → PRI = 1*8 + 4 = 12
            assert!(formatted.starts_with("<12>"), "Warning should have PRI=12");
        }

        #[test]
        fn test_syslog_severity_mapping_notice() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Notice, "Notice message");
            
            let formatted = output.format_event(&event);
            
            // Notice = severity 5, facility 1 → PRI = 1*8 + 5 = 13
            assert!(formatted.starts_with("<13>"), "Notice should have PRI=13");
        }

        #[test]
        fn test_syslog_severity_mapping_info() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Info, "Info message");
            
            let formatted = output.format_event(&event);
            
            // Info = severity 6, facility 1 → PRI = 1*8 + 6 = 14
            assert!(formatted.starts_with("<14>"), "Info should have PRI=14");
        }

        #[test]
        fn test_syslog_severity_mapping_debug() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Debug, "Debug message");
            
            let formatted = output.format_event(&event);
            
            // Debug = severity 7, facility 1 → PRI = 1*8 + 7 = 15
            assert!(formatted.starts_with("<15>"), "Debug should have PRI=15");
        }

        #[test]
        fn test_syslog_pri_calculation() {
            // Verify PRI = facility * 8 + severity
            // Using facility = 1 (user-level)
            let facility = 1;
            
            let test_cases = vec![
                (LogLevel::Alert, 1, facility * 8 + 1),
                (LogLevel::Error, 3, facility * 8 + 3),
                (LogLevel::Warning, 4, facility * 8 + 4),
                (LogLevel::Notice, 5, facility * 8 + 5),
                (LogLevel::Info, 6, facility * 8 + 6),
                (LogLevel::Debug, 7, facility * 8 + 7),
            ];

            let output = create_remote_output_syslog();
            
            for (level, severity, expected_pri) in test_cases {
                let event = create_test_event(level, "test");
                let formatted = output.format_event(&event);
                
                let expected_start = format!("<{}>", expected_pri);
                assert!(
                    formatted.starts_with(&expected_start),
                    "Level {:?} (severity {}) should have PRI={}, got: {}",
                    level, severity, expected_pri, &formatted[..20.min(formatted.len())]
                );
            }
        }

        #[test]
        fn test_syslog_context_appended() {
            let output = create_remote_output_syslog();
            let event = create_test_event(LogLevel::Info, "Test message");
            
            let formatted = output.format_event(&event);
            
            // Context should be appended as key=value pairs
            assert!(formatted.contains("test_key=test_value"), 
                "Context should be appended in syslog: {}", formatted);
        }

        #[test]
        fn test_syslog_newlines_replaced() {
            let output = create_remote_output_syslog();
            let mut event = create_test_event(LogLevel::Info, "Line1\nLine2\nLine3");
            event.context.clear();
            
            let formatted = output.format_event(&event);
            
            // Newlines should be replaced with spaces
            assert!(!formatted.contains('\n'), 
                "Newlines should be replaced in syslog: {}", formatted);
            assert!(formatted.contains("Line1 Line2 Line3"), 
                "Message should be on single line: {}", formatted);
        }
    }

    // --- JSON Format Tests ---
    
    mod json_format_tests {
        use super::*;

        fn create_remote_output_json() -> RemoteOutput {
            RemoteOutput {
                host: "127.0.0.1".to_string(),
                port: 514,
                protocol: RemoteProtocol::Udp,
                format: RemoteFormat::Json,
                udp_socket: None,
                tcp_stream: std::sync::Mutex::new(None),
            }
        }

        #[test]
        fn test_json_format_valid() {
            let output = create_remote_output_json();
            let event = create_test_event(LogLevel::Warning, "Test message");
            
            let formatted = output.format_event(&event);
            
            // Should be valid JSON
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&formatted);
            assert!(parsed.is_ok(), "Should produce valid JSON: {}", formatted);
        }

        #[test]
        fn test_json_contains_all_fields() {
            let output = create_remote_output_json();
            let event = create_test_event(LogLevel::Warning, "Test message");
            
            let formatted = output.format_event(&event);
            let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            
            // Check required fields
            assert!(parsed.get("timestamp").is_some(), "Should have timestamp");
            assert!(parsed.get("level").is_some(), "Should have level");
            assert!(parsed.get("event_type").is_some(), "Should have event_type");
            assert!(parsed.get("hostname").is_some(), "Should have hostname");
            assert!(parsed.get("message").is_some(), "Should have message");
        }

        #[test]
        fn test_json_level_values() {
            let output = create_remote_output_json();
            
            let test_cases = vec![
                (LogLevel::Alert, "ALERT"),
                (LogLevel::Error, "ERROR"),
                (LogLevel::Warning, "WARNING"),
                (LogLevel::Notice, "NOTICE"),
                (LogLevel::Info, "INFO"),
                (LogLevel::Debug, "DEBUG"),
            ];

            for (level, expected_str) in test_cases {
                let event = create_test_event(level, "test");
                let formatted = output.format_event(&event);
                let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
                
                assert_eq!(
                    parsed.get("level").unwrap().as_str().unwrap(),
                    expected_str,
                    "Level {:?} should serialize to '{}'",
                    level, expected_str
                );
            }
        }

        #[test]
        fn test_json_ansi_stripped() {
            let output = create_remote_output_json();
            let event = create_test_event(LogLevel::Info, "\x1b[31mRed text\x1b[0m");
            
            let formatted = output.format_event(&event);
            
            // ANSI codes should be stripped
            assert!(!formatted.contains("\x1b"), "ANSI codes should be stripped");
            assert!(formatted.contains("Red text"), "Message content should remain");
        }

        #[test]
        fn test_json_context_included() {
            let output = create_remote_output_json();
            let event = create_test_event(LogLevel::Info, "Test message");
            
            let formatted = output.format_event(&event);
            let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
            
            let context = parsed.get("context").unwrap();
            assert_eq!(
                context.get("test_key").unwrap().as_str().unwrap(),
                "test_value"
            );
        }
    }

    // --- Multi-Sink Routing Tests ---
    
    mod multi_sink_tests {
        use super::*;
        use std::sync::Arc;

        /// A test LogOutput implementation that collects events
        struct CollectingOutput {
            events: std::sync::Mutex<Vec<LogEvent>>,
            write_count: AtomicUsize,
        }

        impl CollectingOutput {
            fn new() -> Self {
                Self {
                    events: std::sync::Mutex::new(Vec::new()),
                    write_count: AtomicUsize::new(0),
                }
            }

            fn event_count(&self) -> usize {
                self.events.lock().unwrap().len()
            }

            fn get_events(&self) -> Vec<LogEvent> {
                self.events.lock().unwrap().clone()
            }
        }

        impl LogOutput for CollectingOutput {
            fn write(&self, event: &LogEvent) -> Result<(), std::io::Error> {
                self.events.lock().unwrap().push(event.clone());
                self.write_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        /// Wrapper to make CollectingOutput work with UnifiedLogger
        struct TestableLogger {
            outputs: Vec<Arc<CollectingOutput>>,
            hostname: String,
            log_level: LogLevel,
        }

        impl TestableLogger {
            fn new(num_sinks: usize, log_level: LogLevel) -> Self {
                let outputs: Vec<Arc<CollectingOutput>> = (0..num_sinks)
                    .map(|_| Arc::new(CollectingOutput::new()))
                    .collect();
                
                Self {
                    outputs,
                    hostname: "test-host".to_string(),
                    log_level,
                }
            }

            fn log(&self, mut event: LogEvent) {
                if event.level > self.log_level {
                    return;
                }

                if event.hostname.is_empty() {
                    event.hostname = self.hostname.clone();
                }

                for output in &self.outputs {
                    let _ = output.write(&event);
                }
            }

            fn get_sink_event_counts(&self) -> Vec<usize> {
                self.outputs.iter().map(|o| o.event_count()).collect()
            }
        }

        #[test]
        fn test_event_routed_to_all_sinks() {
            let logger = TestableLogger::new(3, LogLevel::Debug);
            
            let event = create_test_event(LogLevel::Warning, "Test message");
            logger.log(event);
            
            let counts = logger.get_sink_event_counts();
            
            // All 3 sinks should receive the event
            assert_eq!(counts, vec![1, 1, 1], "All sinks should receive the event");
        }

        #[test]
        fn test_multiple_events_routed_to_all_sinks() {
            let logger = TestableLogger::new(2, LogLevel::Debug);
            
            // Log 5 events
            for i in 0..5 {
                let event = create_test_event(LogLevel::Info, &format!("Message {}", i));
                logger.log(event);
            }
            
            let counts = logger.get_sink_event_counts();
            
            // Both sinks should receive all 5 events
            assert_eq!(counts, vec![5, 5], "Both sinks should receive all events");
        }

        #[test]
        fn test_filtered_events_not_routed() {
            let logger = TestableLogger::new(2, LogLevel::Warning);
            
            // Log events at different levels
            logger.log(create_test_event(LogLevel::Alert, "Alert"));   // Should pass
            logger.log(create_test_event(LogLevel::Warning, "Warn"));  // Should pass
            logger.log(create_test_event(LogLevel::Notice, "Notice")); // Should be filtered
            logger.log(create_test_event(LogLevel::Info, "Info"));     // Should be filtered
            logger.log(create_test_event(LogLevel::Debug, "Debug"));   // Should be filtered
            
            let counts = logger.get_sink_event_counts();
            
            // Only 2 events should pass (Alert and Warning)
            assert_eq!(counts, vec![2, 2], "Only Warning+ events should pass");
        }

        #[test]
        fn test_event_content_same_across_sinks() {
            let logger = TestableLogger::new(2, LogLevel::Debug);
            
            let event = create_test_event(LogLevel::Info, "Same content test");
            logger.log(event);
            
            let sink1_events = logger.outputs[0].get_events();
            let sink2_events = logger.outputs[1].get_events();
            
            assert_eq!(sink1_events.len(), 1);
            assert_eq!(sink2_events.len(), 1);
            
            // Both should have same message
            assert_eq!(sink1_events[0].message, sink2_events[0].message);
            assert_eq!(sink1_events[0].message, "Same content test");
        }
    }

    // --- ANSI Stripping Tests ---
    
    mod ansi_strip_tests {
        use super::*;

        #[test]
        fn test_strip_basic_colors() {
            let input = "\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m";
            let output = strip_ansi(input);
            assert_eq!(output, "Red Green");
        }

        #[test]
        fn test_strip_bold_and_underline() {
            let input = "\x1b[1mBold\x1b[0m \x1b[4mUnderline\x1b[0m";
            let output = strip_ansi(input);
            assert_eq!(output, "Bold Underline");
        }

        #[test]
        fn test_strip_256_colors() {
            let input = "\x1b[38;5;196mBright Red\x1b[0m";
            let output = strip_ansi(input);
            assert_eq!(output, "Bright Red");
        }

        #[test]
        fn test_no_ansi_unchanged() {
            let input = "Plain text without ANSI";
            let output = strip_ansi(input);
            assert_eq!(output, input);
        }

        #[test]
        fn test_empty_string() {
            let input = "";
            let output = strip_ansi(input);
            assert_eq!(output, "");
        }

        #[test]
        fn test_mixed_content() {
            let input = "Start \x1b[31mcolored\x1b[0m middle \x1b[32mmore\x1b[0m end";
            let output = strip_ansi(input);
            assert_eq!(output, "Start colored middle more end");
        }
    }

    // --- LogLevel Tests ---
    
    mod log_level_tests {
        use super::*;

        #[test]
        fn test_log_level_display() {
            assert_eq!(format!("{}", LogLevel::Alert), "ALERT");
            assert_eq!(format!("{}", LogLevel::Warning), "WARNING");
            assert_eq!(format!("{}", LogLevel::Notice), "NOTICE");
            assert_eq!(format!("{}", LogLevel::Info), "INFO");
            assert_eq!(format!("{}", LogLevel::Error), "ERROR");
            assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        }

        #[test]
        fn test_log_level_ordering() {
            // Verify enum ordering (Alert is highest priority = smallest value)
            assert!(LogLevel::Alert < LogLevel::Error);
            assert!(LogLevel::Error < LogLevel::Warning);
            assert!(LogLevel::Warning < LogLevel::Notice);
            assert!(LogLevel::Notice < LogLevel::Info);
            assert!(LogLevel::Info < LogLevel::Debug);
        }

        #[test]
        fn test_log_level_serialization() {
            let json = serde_json::to_string(&LogLevel::Alert).unwrap();
            assert_eq!(json, "\"ALERT\"");
            
            let json = serde_json::to_string(&LogLevel::Warning).unwrap();
            assert_eq!(json, "\"WARNING\"");
        }
    }
}
