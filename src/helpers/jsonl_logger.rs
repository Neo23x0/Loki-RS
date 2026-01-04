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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    mod match_reason_tests {
        use super::*;

        #[test]
        fn test_match_reason_creation() {
            let reason = MatchReason {
                message: "Test reason".to_string(),
                score: 75,
            };

            assert_eq!(reason.message, "Test reason");
            assert_eq!(reason.score, 75);
        }

        #[test]
        fn test_match_reason_serialization() {
            let reason = MatchReason {
                message: "YARA match".to_string(),
                score: 80,
            };

            let json = serde_json::to_string(&reason).unwrap();
            assert!(json.contains("YARA match"));
            assert!(json.contains("80"));
        }
    }

    mod jsonl_log_entry_tests {
        use super::*;

        #[test]
        fn test_log_entry_file_match() {
            let entry = JsonlLogEntry {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                level: "ALERT".to_string(),
                event_type: "file_match".to_string(),
                file_path: Some("/path/to/file.exe".to_string()),
                pid: None,
                process_name: None,
                score: Some(85.0),
                file_type: Some("Windows Executable".to_string()),
                file_size: Some(1024),
                md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
                sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
                sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
                reasons: Some(vec![MatchReason { message: "Test".to_string(), score: 85 }]),
                message: None,
            };

            let json = serde_json::to_string(&entry).unwrap();
            assert!(json.contains("file_match"));
            assert!(json.contains("/path/to/file.exe"));
            assert!(!json.contains("pid"));
        }

        #[test]
        fn test_log_entry_process_match() {
            let entry = JsonlLogEntry {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                level: "WARNING".to_string(),
                event_type: "process_match".to_string(),
                file_path: None,
                pid: Some(1234),
                process_name: Some("malware.exe".to_string()),
                score: Some(70.0),
                file_type: None,
                file_size: None,
                md5: None,
                sha1: None,
                sha256: None,
                reasons: Some(vec![MatchReason { message: "Suspicious".to_string(), score: 70 }]),
                message: None,
            };

            let json = serde_json::to_string(&entry).unwrap();
            assert!(json.contains("process_match"));
            assert!(json.contains("1234"));
            assert!(json.contains("malware.exe"));
            assert!(!json.contains("file_path"));
        }
    }

    mod jsonl_logger_tests {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        fn unique_temp_file() -> String {
            let count = COUNTER.fetch_add(1, Ordering::SeqCst);
            format!("/tmp/loki_test_{}_{}.jsonl", std::process::id(), count)
        }

        #[test]
        fn test_logger_creation() {
            let log_file = unique_temp_file();
            let logger = JsonlLogger::new(&log_file);
            assert!(logger.is_ok());
            let _ = fs::remove_file(&log_file);
        }

        #[test]
        fn test_logger_log_file_match() {
            let log_file = unique_temp_file();
            let logger = JsonlLogger::new(&log_file).unwrap();

            let reasons = vec![
                MatchReason { message: "YARA match".to_string(), score: 80 },
            ];

            let result = logger.log_file_match(
                "ALERT",
                "/path/to/malware.exe",
                85.0,
                "Windows Executable",
                2048,
                "d41d8cd98f00b204e9800998ecf8427e",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                reasons,
            );

            assert!(result.is_ok());
            drop(logger);

            let mut contents = String::new();
            fs::File::open(&log_file).unwrap().read_to_string(&mut contents).unwrap();
            assert!(contents.contains("file_match"));
            assert!(contents.contains("malware.exe"));

            let _ = fs::remove_file(&log_file);
        }

        #[test]
        fn test_logger_log_process_match() {
            let log_file = unique_temp_file();
            let logger = JsonlLogger::new(&log_file).unwrap();

            let reasons = vec![
                MatchReason { message: "C2 connection".to_string(), score: 75 },
            ];

            let result = logger.log_process_match(
                "WARNING",
                1234,
                "suspicious.exe",
                75.0,
                reasons,
            );

            assert!(result.is_ok());
            drop(logger);

            let mut contents = String::new();
            fs::File::open(&log_file).unwrap().read_to_string(&mut contents).unwrap();
            assert!(contents.contains("process_match"));
            assert!(contents.contains("1234"));

            let _ = fs::remove_file(&log_file);
        }

        #[test]
        fn test_logger_multiple_entries() {
            let log_file = unique_temp_file();
            let logger = JsonlLogger::new(&log_file).unwrap();

            for i in 0..3 {
                let reasons = vec![
                    MatchReason { message: format!("Reason {}", i), score: 75 },
                ];
                let _ = logger.log_file_match(
                    "NOTICE",
                    &format!("/path/to/file{}.exe", i),
                    50.0,
                    "Unknown",
                    1024,
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    reasons,
                );
            }
            drop(logger);

            let mut contents = String::new();
            fs::File::open(&log_file).unwrap().read_to_string(&mut contents).unwrap();
            let lines: Vec<&str> = contents.lines().collect();
            assert_eq!(lines.len(), 3);

            let _ = fs::remove_file(&log_file);
        }
    }
}

