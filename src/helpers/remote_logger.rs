#![allow(dead_code)]

use std::net::{TcpStream, UdpSocket};
use std::sync::{Mutex, Arc};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use chrono::Utc;
use serde_json::json;
use crate::helpers::jsonl_logger::MatchReason;
use crate::helpers::helpers::get_hostname;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone)]
pub struct RemoteLogTarget {
    pub hostname: String,
    pub port: u16,
    pub protocol: LogProtocol,
    pub format: LogFormat,
}

// Thread-safe remote logger
pub struct RemoteLogger {
    target: RemoteLogTarget,
    tcp_stream: Option<Arc<Mutex<TcpStream>>>,
    udp_socket: Option<UdpSocket>, // UdpSocket is cloneable but we'll wrap access if needed or just recreate/bind? UdpSocket needs a local bind.
                                   // Actually UdpSocket::send_to doesn't require connection state in the same way, but creating one for reuse is better.
    message_count: Arc<AtomicUsize>,
    local_hostname: String,
}

impl RemoteLogger {
    pub fn new(target: RemoteLogTarget) -> Result<Self, std::io::Error> {
        let mut tcp_stream = None;
        let mut udp_socket = None;
        let local_hostname = get_hostname();

        match target.protocol {
            LogProtocol::Tcp => {
                let address = format!("{}:{}", target.hostname, target.port);
                log::info!("Connecting to remote log target (TCP): {}", address);
                let stream = TcpStream::connect(&address)?;
                tcp_stream = Some(Arc::new(Mutex::new(stream)));
            },
            LogProtocol::Udp => {
                // Bind to any local port
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                // We don't "connect" in UDP strictly speaking, but we can store the target address
                // We'll use send_to with the target address later
                udp_socket = Some(socket);
                log::info!("Initialized remote log target (UDP): {}:{}", target.hostname, target.port);
            }
        }

        Ok(RemoteLogger {
            target,
            tcp_stream,
            udp_socket,
            message_count: Arc::new(AtomicUsize::new(0)),
            local_hostname,
        })
    }

    pub fn get_message_count(&self) -> usize {
        self.message_count.load(Ordering::Relaxed)
    }
    
    pub fn get_target_info(&self) -> String {
        format!("{}:{} ({:?}/{:?})", 
            self.target.hostname, 
            self.target.port, 
            self.target.protocol, 
            self.target.format
        )
    }

    fn send_message(&self, message: String) {
        let result = match self.target.protocol {
            LogProtocol::Tcp => {
                if let Some(mutex) = &self.tcp_stream {
                    if let Ok(mut stream) = mutex.lock() {
                        // Ensure message ends with newline for TCP
                        let msg_to_send = if message.ends_with('\n') {
                            message
                        } else {
                            format!("{}\n", message)
                        };
                        stream.write_all(msg_to_send.as_bytes())
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to lock TCP stream"))
                    }
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "TCP stream not initialized"))
                }
            },
            LogProtocol::Udp => {
                if let Some(socket) = &self.udp_socket {
                    let addr = format!("{}:{}", self.target.hostname, self.target.port);
                    socket.send_to(message.as_bytes(), addr).map(|_| ())
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "UDP socket not initialized"))
                }
            }
        };

        match result {
            Ok(_) => {
                self.message_count.fetch_add(1, Ordering::Relaxed);
            },
            Err(e) => {
                // Log failure locally only if verbose to avoid loop/spam
                log::debug!("Failed to send remote log: {}", e);
            }
        }
    }

    fn format_plain(&self, level: &str, msg_type: &str, details: &str) -> String {
        // Syslog-like format: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
        // We'll simplify: TIMESTAMP HOSTNAME loki: [LEVEL] [TYPE] DETAILS
        format!("{} {} loki: [{}] [{}] {}", 
            Utc::now().to_rfc3339(),
            self.local_hostname,
            level,
            msg_type,
            details
        )
    }

    pub fn log_file_match(
        &self,
        level: &str,
        file_path: &str,
        score: f64,
        file_type: &str,
        reasons: &[MatchReason],
    ) {
        let msg = match self.target.format {
            LogFormat::Json => {
                let reasons_json: Vec<serde_json::Value> = reasons.iter()
                    .map(|r| json!({"message": r.message, "score": r.score}))
                    .collect();

                json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "hostname": self.local_hostname,
                    "level": level,
                    "event_type": "file_match",
                    "file_path": file_path,
                    "score": score,
                    "file_type": file_type,
                    "reasons": reasons_json
                }).to_string()
            },
            LogFormat::Plain => {
                let reasons_str: Vec<String> = reasons.iter()
                    .map(|r| format!("{} (score={})", r.message, r.score))
                    .collect();
                
                let details = format!("FILE: {} SCORE: {} TYPE: {} REASONS: {}", 
                    file_path, score, file_type, reasons_str.join(", "));
                
                self.format_plain(level, "FILE_MATCH", &details)
            }
        };
        
        self.send_message(msg);
    }

    pub fn log_process_match(
        &self,
        level: &str,
        pid: u32,
        process_name: &str,
        score: f64,
        reasons: &[MatchReason],
    ) {
        let msg = match self.target.format {
            LogFormat::Json => {
                let reasons_json: Vec<serde_json::Value> = reasons.iter()
                    .map(|r| json!({"message": r.message, "score": r.score}))
                    .collect();

                json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "hostname": self.local_hostname,
                    "level": level,
                    "event_type": "process_match",
                    "pid": pid,
                    "process_name": process_name,
                    "score": score,
                    "reasons": reasons_json
                }).to_string()
            },
            LogFormat::Plain => {
                let reasons_str: Vec<String> = reasons.iter()
                    .map(|r| format!("{} (score={})", r.message, r.score))
                    .collect();
                
                let details = format!("PID: {} NAME: {} SCORE: {} REASONS: {}", 
                    pid, process_name, score, reasons_str.join(", "));
                
                self.format_plain(level, "PROCESS_MATCH", &details)
            }
        };
        
        self.send_message(msg);
    }
}
