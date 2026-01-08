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
                    println!("      SCORE: {}", score.to_string().white());
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
                
                format!("Match: {} SCORE: {:.2} REASONS: [{}]", target, score, reasons_str)
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

        self.log(LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Error,
            event_type: EventType::Error,
            hostname: self.hostname.clone(),
            message: msg.to_string(),
            context: context_map,
            file_path: None, pid: None, process_name: None, score: None,
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