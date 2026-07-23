use yara_x::ScanError;

use crate::helpers::unified_logger::UnifiedLogger;

#[derive(Clone, Copy, Debug)]
pub enum YaraScanTarget<'a> {
    File(&'a str),
    Process { pid: u32, process_name: &'a str },
}

/// Log YARA scan failures consistently without turning operational failures
/// into detection findings.
pub fn log_yara_scan_error(
    logger: &UnifiedLogger,
    error: &ScanError,
    target: YaraScanTarget<'_>,
    report_non_timeout_errors: bool,
) {
    let is_timeout = matches!(error, ScanError::Timeout);

    match target {
        YaraScanTarget::File(path) => {
            let message = if is_timeout {
                format!(
                    "YARA scan timeout while scanning FILE: {} - skipping and continuing",
                    path
                )
            } else {
                format!("YARA-X scan error FILE: {} ERROR: {}", path, error)
            };

            if is_timeout || report_non_timeout_errors {
                logger.file_error(&message, path);
            } else {
                logger.debug(&message);
            }
        }
        YaraScanTarget::Process { pid, process_name } => {
            let message = if is_timeout {
                format!(
                    "YARA scan timeout while scanning process memory PID: {} PROC_NAME: {} - skipping and continuing",
                    pid, process_name
                )
            } else {
                format!(
                    "YARA-X process-memory scan error PID: {} PROC_NAME: {} ERROR: {}",
                    pid, process_name, error
                )
            };

            if is_timeout || report_non_timeout_errors {
                logger.process_error(&message, pid, process_name);
            } else {
                logger.debug(&message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::unified_logger::{
        EventType, LogLevel, LoggerConfig, TuiMessage, UnifiedLogger,
    };
    use std::sync::mpsc::{self, Receiver};

    fn test_logger() -> (UnifiedLogger, Receiver<TuiMessage>) {
        let (sender, receiver) = mpsc::channel();
        let logger = UnifiedLogger::new(LoggerConfig {
            console: false,
            log_level: LogLevel::Debug,
            log_file: None,
            jsonl_file: None,
            remote: None,
            tui_sender: Some(sender),
        })
        .expect("create test logger");
        (logger, receiver)
    }

    fn receive_event(receiver: &Receiver<TuiMessage>) -> crate::helpers::unified_logger::LogEvent {
        match receiver.recv().expect("receive log event") {
            TuiMessage::Log(event) => event,
            message => panic!("expected log event, got {:?}", message),
        }
    }

    #[test]
    fn file_timeout_is_a_structured_operational_error() {
        let (logger, receiver) = test_logger();

        log_yara_scan_error(
            &logger,
            &ScanError::Timeout,
            YaraScanTarget::File("sample.bin"),
            false,
        );

        let event = receive_event(&receiver);
        assert_eq!(event.level, LogLevel::Error);
        assert_eq!(event.event_type, EventType::Error);
        assert_eq!(event.file_path.as_deref(), Some("sample.bin"));
        assert!(event.pid.is_none());
        assert!(event.message.contains("YARA scan timeout"));
    }

    #[test]
    fn process_timeout_is_a_structured_operational_error() {
        let (logger, receiver) = test_logger();

        log_yara_scan_error(
            &logger,
            &ScanError::Timeout,
            YaraScanTarget::Process {
                pid: 42,
                process_name: "sample",
            },
            false,
        );

        let event = receive_event(&receiver);
        assert_eq!(event.level, LogLevel::Error);
        assert_eq!(event.event_type, EventType::Error);
        assert_eq!(event.pid, Some(42));
        assert_eq!(event.process_name.as_deref(), Some("sample"));
        assert!(event.file_path.is_none());
        assert!(event.message.contains("YARA scan timeout"));
    }

    #[test]
    fn non_timeout_scan_errors_are_debug_only_by_default() {
        let (logger, receiver) = test_logger();
        let error = ScanError::UnknownModule {
            module: "test".to_string(),
        };

        log_yara_scan_error(&logger, &error, YaraScanTarget::File("sample.bin"), false);

        let event = receive_event(&receiver);
        assert_eq!(event.level, LogLevel::Debug);
        assert_eq!(event.event_type, EventType::Info);
        assert!(event.message.contains("unknown module"));
    }

    #[test]
    fn verbose_scan_errors_are_structured_errors() {
        let (logger, receiver) = test_logger();
        let error = ScanError::UnknownModule {
            module: "test".to_string(),
        };

        log_yara_scan_error(
            &logger,
            &error,
            YaraScanTarget::Process {
                pid: 42,
                process_name: "sample",
            },
            true,
        );

        let event = receive_event(&receiver);
        assert_eq!(event.level, LogLevel::Error);
        assert_eq!(event.event_type, EventType::Error);
        assert_eq!(event.pid, Some(42));
        assert_eq!(event.process_name.as_deref(), Some("sample"));
    }
}
