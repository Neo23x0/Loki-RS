use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use chrono::Utc;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonlLogEntry {
    pub timestamp: String,
    pub level: String,
    pub event_type: String,  // "file_match", "process_match", "info", etc.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<MatchReason>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReason {
    pub message: String,
    pub score: i16,
}

pub struct JsonlLogger {
    file: Mutex<std::fs::File>,
}

impl JsonlLogger {
    pub fn new(log_file: &str) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        Ok(JsonlLogger {
            file: Mutex::new(file),
        })
    }

    pub fn log(&self, entry: JsonlLogEntry) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(&entry)?;
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json)?;
        file.flush()?;
        Ok(())
    }

    pub fn log_file_match(
        &self,
        level: &str,
        file_path: &str,
        score: f64,
        file_type: &str,
        file_size: u64,
        md5: &str,
        sha1: &str,
        sha256: &str,
        reasons: Vec<MatchReason>,
    ) -> Result<(), std::io::Error> {
        let entry = JsonlLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_string(),
            event_type: "file_match".to_string(),
            file_path: Some(file_path.to_string()),
            pid: None,
            process_name: None,
            score: Some(score),
            file_type: Some(file_type.to_string()),
            file_size: Some(file_size),
            md5: Some(md5.to_string()),
            sha1: Some(sha1.to_string()),
            sha256: Some(sha256.to_string()),
            reasons: Some(reasons),
            message: None,
        };
        self.log(entry)
    }

    pub fn log_process_match(
        &self,
        level: &str,
        pid: u32,
        process_name: &str,
        score: f64,
        reasons: Vec<MatchReason>,
    ) -> Result<(), std::io::Error> {
        let entry = JsonlLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: level.to_string(),
            event_type: "process_match".to_string(),
            file_path: None,
            pid: Some(pid),
            process_name: Some(process_name.to_string()),
            score: Some(score),
            file_type: None,
            file_size: None,
            md5: None,
            sha1: None,
            sha256: None,
            reasons: Some(reasons),
            message: None,
        };
        self.log(entry)
    }

    #[allow(dead_code)]
    pub fn log_info(&self, message: &str) -> Result<(), std::io::Error> {
        let entry = JsonlLogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: "INFO".to_string(),
            event_type: "info".to_string(),
            file_path: None,
            pid: None,
            process_name: None,
            score: None,
            file_type: None,
            file_size: None,
            md5: None,
            sha1: None,
            sha256: None,
            reasons: None,
            message: Some(message.to_string()),
        };
        self.log(entry)
    }
}

