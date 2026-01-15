//! HTML Report Generation from JSONL files for loki-util
//! 
//! Provides functionality to generate HTML reports from single or multiple JSONL files,
//! reusing the existing HTML rendering pipeline from loki.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::collections::BTreeMap;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

// Duplicate types from helpers/html_report.rs since loki-util is a separate binary
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub event_type: String,
    pub hostname: String,
    pub message: String,
    #[serde(default)]
    pub context: BTreeMap<String, String>,
    pub file_path: Option<String>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub score: Option<f64>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub file_created: Option<String>,
    pub file_modified: Option<String>,
    pub file_accessed: Option<String>,
    pub reasons: Option<Vec<MatchReason>>,
    pub start_time: Option<i64>,
    pub run_time: Option<String>,
    pub memory_bytes: Option<u64>,
    pub cpu_usage: Option<f32>,
    pub connection_count: Option<usize>,
    pub listening_ports: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MatchReason {
    pub message: String,
    pub score: i16,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
    pub matched_strings: Option<Vec<String>>,
}

pub struct ReportData {
    pub scan_start: Option<LogEvent>,
    pub scan_end: Option<LogEvent>,
    pub info_events: Vec<LogEvent>,
    pub findings: Vec<LogEvent>,
}

// ScanConfig duplicate (simplified for loki-util)
// Some fields are kept for API compatibility but not all are used in simplified renderer
#[allow(dead_code)]
pub struct ScanConfig {
    pub max_file_size: usize,
    pub show_access_errors: bool,
    pub scan_all_types: bool,
    pub scan_hard_drives: bool,
    pub scan_all_drives: bool,
    pub scan_archives: bool,
    pub alert_threshold: i16,
    pub warning_threshold: i16,
    pub notice_threshold: i16,
    pub max_reasons: usize,
    pub threads: usize,
    pub cpu_limit: u8,
    pub exclusion_count: usize,
    pub yara_rules_count: usize,
    pub ioc_count: usize,
    pub program_dir: Option<String>,
}

/// Parse JSONL file into ReportData
pub fn parse_jsonl(path: &str) -> Result<ReportData, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open JSONL file: {}", e))?;
    let reader = BufReader::new(file);
    
    let mut scan_start = None;
    let mut scan_end = None;
    let mut info_events = Vec::new();
    let mut findings = Vec::new();
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        if line.trim().is_empty() {
            continue;
        }
        
        let event: LogEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue, // Skip malformed lines
        };
        
        match event.event_type.as_str() {
            "scan_start" => scan_start = Some(event),
            "scan_end" => scan_end = Some(event),
            "file_match" | "process_match" => findings.push(event),
            "info" => info_events.push(event),
            _ => {}
        }
    }
    
    // Sort findings by score descending
    findings.sort_by(|a, b| {
        let score_a = a.score.unwrap_or(0.0);
        let score_b = b.score.unwrap_or(0.0);
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    Ok(ReportData {
        scan_start,
        scan_end,
        info_events,
        findings,
    })
}

/// Metadata extracted from a JSONL file
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SourceMetadata {
    pub hostname: String,
    pub scan_start: Option<DateTime<Utc>>,
    pub scan_end: Option<DateTime<Utc>>,
    pub version: Option<String>,
    pub filename: String,
    pub os_info: Option<String>,
    pub scan_duration_seconds: Option<f64>,
}

/// Combined report data from multiple JSONL files
pub struct CombinedReportData {
    pub sources: Vec<SourceMetadata>,
    #[allow(dead_code)] // Kept for backward compatibility
    pub findings_by_source: BTreeMap<String, Vec<LogEvent>>,
    pub all_findings: Vec<LogEvent>,
    pub findings_by_hostname: BTreeMap<String, Vec<LogEvent>>,
    pub total_findings: usize,
    #[allow(dead_code)] // Kept for backward compatibility
    pub total_by_severity: BTreeMap<String, usize>,
    pub os_statistics: BTreeMap<String, usize>,
    pub version_statistics: BTreeMap<String, usize>,
    pub error_count_by_host: BTreeMap<String, usize>,
}

/// Extract metadata from a parsed ReportData
pub fn extract_metadata(data: &ReportData, filename: &str) -> SourceMetadata {
    let hostname = data.scan_start.as_ref()
        .map(|e| e.hostname.clone())
        .unwrap_or_else(|| {
            // Try to extract from filename (loki_hostname_date.jsonl)
            Path::new(filename)
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s: &str| s.strip_prefix("loki_"))
                .and_then(|s: &str| s.split('_').next())
                .map(|s: &str| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        });
    
    let scan_start = data.scan_start.as_ref().map(|e| e.timestamp);
    let scan_end = data.scan_end.as_ref().map(|e| e.timestamp);
    
    // Calculate scan duration
    let scan_duration_seconds = scan_start.and_then(|start| {
        scan_end.map(|end| {
            let duration = end.signed_duration_since(start);
            duration.num_seconds() as f64 + duration.num_milliseconds() as f64 / 1000.0
        })
    });
    
    // Extract version from scan_start message
    let version = data.scan_start.as_ref()
        .and_then(|e| {
            let re = Regex::new(r"VERSION:\s*([^\s]+)").ok()?;
            re.captures(&e.message)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
        });
    
    // Extract OS information from info events
    let os_info = data.info_events.iter()
        .find(|e| e.message.contains("Operating system"))
        .map(|e| e.message.clone());
    
    SourceMetadata {
        hostname,
        scan_start,
        scan_end,
        version,
        filename: filename.to_string(),
        os_info,
        scan_duration_seconds,
    }
}

/// Synthesize a ScanConfig from extracted metadata and info events
pub fn synthesize_scan_config(data: &ReportData) -> ScanConfig {
    // Default values
    let mut alert_threshold = 80;
    let mut warning_threshold = 60;
    let mut notice_threshold = 40;
    let mut max_file_size = 64_000_000;
    let mut threads = 0;
    let mut cpu_limit = 100;
    let mut yara_rules_count = 0;
    let mut ioc_count = 0;
    
    // Try to extract from info events
    for event in &data.info_events {
        // Extract thresholds from context
        if let Some(threshold_str) = event.context.get("ALERT_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                alert_threshold = val;
            }
        }
        if let Some(threshold_str) = event.context.get("WARNING_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                warning_threshold = val;
            }
        }
        if let Some(threshold_str) = event.context.get("NOTICE_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                notice_threshold = val;
            }
        }
        
        // Extract max_file_size from "Scan limits" message
        if event.message.contains("MAX_FILE_SIZE") {
            if let Some(size_str) = event.context.get("MAX_FILE_SIZE") {
                // Format: "64000000 bytes (64.0 MB)"
                if let Some(bytes_part) = size_str.split_whitespace().next() {
                    if let Ok(val) = bytes_part.parse::<usize>() {
                        max_file_size = val;
                    }
                }
            }
        }
        
        // Extract thread count
        if event.message.contains("Thread pool") || event.message.contains("THREADS:") {
            let re = Regex::new(r"THREADS:\s*(\d+)").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(thread_str) = caps.get(1) {
                        if let Ok(val) = thread_str.as_str().parse::<usize>() {
                            threads = val;
                        }
                    }
                }
            }
        }
        
        // Extract CPU limit
        if event.message.contains("CPU") && event.message.contains("%") {
            let re = Regex::new(r"CPU[:\s]+(\d+)%").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(cpu_str) = caps.get(1) {
                        if let Ok(val) = cpu_str.as_str().parse::<u8>() {
                            cpu_limit = val;
                        }
                    }
                }
            }
        }
        
        // Extract YARA rules count
        if event.message.contains("YARA rules") || event.message.contains("rules loaded") {
            let re = Regex::new(r"(\d+)\s+rules").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(count_str) = caps.get(1) {
                        if let Ok(val) = count_str.as_str().parse::<usize>() {
                            yara_rules_count = val;
                        }
                    }
                }
            }
        }
        
        // Extract IOC count
        if event.message.contains("IOC") || event.message.contains("indicators loaded") {
            let re = Regex::new(r"(\d+)\s+indicators").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(count_str) = caps.get(1) {
                        if let Ok(val) = count_str.as_str().parse::<usize>() {
                            ioc_count = val;
                        }
                    }
                }
            }
        }
    }
    
    ScanConfig {
        max_file_size,
        show_access_errors: false,
        scan_all_types: false,
        scan_hard_drives: false,
        scan_all_drives: false,
        scan_archives: true,
        alert_threshold,
        warning_threshold,
        notice_threshold,
        max_reasons: 2,
        threads,
        cpu_limit,
        exclusion_count: 0,
        yara_rules_count,
        ioc_count,
        program_dir: None,
    }
}

/// Parse multiple JSONL files and combine them
pub fn parse_multiple_jsonl_files(paths: &[String]) -> Result<CombinedReportData, String> {
    let mut sources = Vec::new();
    let mut findings_by_source = BTreeMap::new();
    let mut all_findings = Vec::new();
    let mut findings_by_hostname: BTreeMap<String, Vec<LogEvent>> = BTreeMap::new();
    let mut total_by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut os_statistics: BTreeMap<String, usize> = BTreeMap::new();
    let mut version_statistics: BTreeMap<String, usize> = BTreeMap::new();
    let mut error_count_by_host: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_findings = 0;
    
    for path in paths {
        let report_data = parse_jsonl(path)?;
        let metadata = extract_metadata(&report_data, path);
        
        // Count findings by severity
        for finding in &report_data.findings {
            let severity = finding.level.to_uppercase();
            *total_by_severity.entry(severity.clone()).or_insert(0) += 1;
            
            // Count errors
            if severity == "ERROR" {
                *error_count_by_host.entry(metadata.hostname.clone()).or_insert(0) += 1;
            }
        }
        
        total_findings += report_data.findings.len();
        
        // Store findings by source (use filename as key if hostname conflicts)
        let key = format!("{} ({})", metadata.hostname, metadata.filename);
        findings_by_source.insert(key.clone(), report_data.findings.clone());
        
        // Store findings by hostname for filtering
        findings_by_hostname
            .entry(metadata.hostname.clone())
            .or_insert_with(Vec::new)
            .extend(report_data.findings.clone());
        
        // Add all findings to merged list (will sort later)
        all_findings.extend(report_data.findings);
        
        // Update OS statistics
        if let Some(ref os) = metadata.os_info {
            // Extract OS name from message (e.g., "Operating system information OS: linux ARCH: x86_64")
            let os_name = if let Some(os_part) = os.split("OS:").nth(1) {
                os_part.split_whitespace().next().unwrap_or("unknown").to_string()
            } else {
                "unknown".to_string()
            };
            *os_statistics.entry(os_name).or_insert(0) += 1;
        }
        
        // Update version statistics
        if let Some(ref ver) = metadata.version {
            *version_statistics.entry(ver.clone()).or_insert(0) += 1;
        }
        
        // Update metadata with the key used
        let mut meta = metadata;
        meta.filename = key;
        sources.push(meta);
    }
    
    // Sort all findings by score descending
    all_findings.sort_by(|a, b| {
        let score_a = a.score.unwrap_or(0.0);
        let score_b = b.score.unwrap_or(0.0);
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    Ok(CombinedReportData {
        sources,
        findings_by_source,
        all_findings,
        findings_by_hostname,
        total_findings,
        total_by_severity,
        os_statistics,
        version_statistics,
        error_count_by_host,
    })
}

/// Extract version from scan_start message or use binary version
pub fn extract_version(data: &ReportData, fallback_version: &str) -> String {
    data.scan_start.as_ref()
        .and_then(|e| {
            let re = Regex::new(r"VERSION:\s*([^\s]+)").ok()?;
            re.captures(&e.message)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_else(|| fallback_version.to_string())
}

/// Generate HTML report from a single JSONL file
pub fn generate_single_report(
    input_path: &str,
    output_path: Option<&str>,
    title_override: Option<&str>,
    host_override: Option<&str>,
) -> Result<String, String> {
    // Parse JSONL
    let report_data = parse_jsonl(input_path)?;
    
    // Extract metadata
    let metadata = extract_metadata(&report_data, input_path);
    let _hostname = host_override.unwrap_or(&metadata.hostname).to_string();
    let version = extract_version(&report_data, LOKI_UTIL_VERSION);
    
    // Synthesize scan config
    let scan_config = synthesize_scan_config(&report_data);
    
    // Determine output path
    let html_path = output_path.unwrap_or_else(|| {
        // Default: same as input but with .html extension
        if input_path.ends_with(".jsonl") {
            &input_path[..input_path.len() - 6]
        } else {
            input_path
        }
    });
    let html_path = if html_path.ends_with(".html") {
        html_path.to_string()
    } else {
        format!("{}.html", html_path)
    };
    
    // Generate HTML using simplified renderer
    // Note: For full feature parity, we'd need to import render_html from helpers/html_report.rs
    // For now, we use a simplified version that produces similar output
    let html_content = render_html_simplified(&report_data, &scan_config, &version, input_path, title_override);
    
    // Write HTML file
    let mut file = File::create(&html_path)
        .map_err(|e| format!("Failed to create HTML file: {}", e))?;
    file.write_all(html_content.as_bytes())
        .map_err(|e| format!("Failed to write HTML file: {}", e))?;
    
    Ok(html_path)
}

/// Render combined HTML report from multiple sources
pub fn render_combined_html(
    data: &CombinedReportData,
    _version: &str,
    output_path: &str,
) -> Result<String, String> {
    let mut html = String::new();
    
    // Calculate scan duration range
    let scan_durations: Vec<f64> = data.sources.iter()
        .filter_map(|s| s.scan_duration_seconds)
        .collect();
    let min_duration = scan_durations.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_duration = scan_durations.iter().fold(0.0f64, |a, &b| a.max(b));
    let avg_duration = if !scan_durations.is_empty() {
        scan_durations.iter().sum::<f64>() / scan_durations.len() as f64
    } else {
        0.0
    };
    
    // Build OS distribution string
    let os_distribution: Vec<String> = data.os_statistics.iter()
        .map(|(os, count)| format!("{}x {}", count, os))
        .collect();
    let os_dist_str = if os_distribution.is_empty() {
        "Unknown".to_string()
    } else {
        os_distribution.join(", ")
    };
    
    // Build version distribution string
    let version_distribution: Vec<String> = data.version_statistics.iter()
        .map(|(ver, count)| format!("{}x v{}", count, ver))
        .collect();
    let version_dist_str = if version_distribution.is_empty() {
        "Unknown".to_string()
    } else {
        version_distribution.join(", ")
    };
    
    // Build statistics table data
    let mut stats_rows = Vec::new();
    for source in &data.sources {
        let findings = data.findings_by_hostname.get(&source.hostname).map(|v| v.as_slice()).unwrap_or(&[]);
        let alerts = findings.iter().filter(|f| f.level.to_uppercase() == "ALERT").count();
        let warnings = findings.iter().filter(|f| f.level.to_uppercase() == "WARNING").count();
        let notices = findings.iter().filter(|f| f.level.to_uppercase() == "NOTICE").count();
        let errors = data.error_count_by_host.get(&source.hostname).copied().unwrap_or(0);
        
        stats_rows.push((source.hostname.clone(), alerts, warnings, notices, errors));
    }
    
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("    <title>Loki-RS Combined Scan Report</title>\n");
    html.push_str("    <style>\n");
    html.push_str(r##"        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #3fb950;
            --alert-bg: #f85149;
            --warning-bg: #d29922;
            --notice-bg: #3fb950;
            --error-bg: #f85149;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 20px;
        }
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }
        .header h1 { margin-bottom: 10px; }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-card h3 {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        .stat-card p {
            font-size: 14px;
            color: var(--text-primary);
        }
        .stats-table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .stats-table-container h2 { margin-bottom: 16px; }
        .filter-state {
            margin-bottom: 12px;
            padding: 8px 12px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 13px;
        }
        .filter-state span { color: var(--accent); font-weight: 600; }
        .clear-filters-btn {
            margin-left: 12px;
            padding: 4px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-primary);
            cursor: pointer;
            font-size: 12px;
        }
        .clear-filters-btn:hover { background: var(--border-color); }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background: var(--bg-tertiary);
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }
        th:hover { background: var(--border-color); }
        .clickable-cell {
            cursor: pointer;
            transition: background 0.2s;
        }
        .clickable-cell:hover {
            background: var(--bg-tertiary);
        }
        .active-filter {
            background: var(--accent) !important;
            color: #fff !important;
        }
        .findings-section {
            margin-top: 20px;
        }
        .findings-section h2 { margin-bottom: 16px; }
        .finding-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
            transition: opacity 0.2s;
        }
        .finding-card.hidden {
            display: none;
        }
        .finding-card.alert { border-left: 4px solid var(--alert-bg); }
        .finding-card.warning { border-left: 4px solid var(--warning-bg); }
        .finding-card.notice { border-left: 4px solid var(--notice-bg); }
        .finding-card.error { border-left: 4px solid var(--error-bg); }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .finding-title {
            font-size: 16px;
            font-weight: 600;
        }
        .finding-score {
            font-size: 18px;
            font-weight: 700;
            padding: 4px 12px;
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        .hostname-badge {
            display: inline-block;
            padding: 2px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 11px;
            color: var(--text-secondary);
            margin-left: 8px;
        }
        .finding-path {
            font-family: monospace;
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 12px;
            word-break: break-all;
        }
        .detail-item {
            margin: 8px 0;
            font-size: 13px;
        }
        .detail-label {
            color: var(--text-secondary);
            font-weight: 600;
        }
        .detail-value {
            color: var(--text-primary);
        }
        .reasons-section {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        .reason-item {
            background: var(--bg-tertiary);
            padding: 8px 12px;
            border-radius: 4px;
            margin: 8px 0;
        }
        .no-findings {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        .filter-panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .filter-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            cursor: pointer;
            user-select: none;
        }
        .filter-panel-header h3 {
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .filter-count {
            background: var(--accent);
            color: #fff;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .filter-panel-actions {
            display: flex;
            gap: 8px;
        }
        .filter-panel-btn {
            padding: 4px 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .filter-panel-btn:hover {
            color: var(--accent);
            border-color: var(--accent);
        }
        .filter-panel-btn.danger:hover {
            color: var(--alert-bg);
            border-color: var(--alert-bg);
        }
        .filter-panel-content {
            padding: 16px;
            display: none;
        }
        .filter-panel.open .filter-panel-content {
            display: block;
        }
        .filter-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .filter-chip {
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 4px 8px 4px 12px;
            font-size: 12px;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }
        .filter-chip-text {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .filter-chip-remove {
            width: 18px;
            height: 18px;
            border: none;
            background: var(--bg-primary);
            color: var(--text-secondary);
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .filter-chip-remove:hover {
            background: var(--alert-bg);
            color: #fff;
        }
        .filter-empty {
            color: var(--text-secondary);
            font-size: 13px;
            font-style: italic;
        }
        .filter-icon-hint {
            display: inline-block;
            color: #ff6b6b;
            font-style: normal;
            font-weight: bold;
        }
        .hidden-input {
            display: none;
        }
        .context-menu {
            position: fixed;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 4px;
            z-index: 10000;
            display: none;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .context-menu.visible {
            display: block;
        }
        .context-menu-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            cursor: pointer;
            font-size: 13px;
            border-radius: 4px;
        }
        .context-menu-item:hover {
            background: var(--bg-tertiary);
        }
        .context-menu-item .icon {
            font-size: 14px;
        }
        .filter-btn-inline {
            display: inline-block;
            margin-left: 8px;
            padding: 2px 6px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 11px;
            transition: all 0.2s;
        }
        .filter-btn-inline:hover {
            background: var(--alert-bg);
            color: #fff;
            border-color: var(--alert-bg);
        }
    "##);
    html.push_str("    </style>\n");
    html.push_str("</head>\n<body>\n");
    
    // Header
    html.push_str("    <div class=\"header\">\n");
    html.push_str("        <h1>Loki-RS Combined Scan Report</h1>\n");
    html.push_str(&format!("        <p>Generated: {} | Total Hosts: {} | Total Findings: {}</p>\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        data.sources.len(),
        data.total_findings
    ));
    html.push_str("    </div>\n");
    
    // Summary statistics
    html.push_str("    <div class=\"summary-stats\">\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Operating Systems</h3>\n");
    html.push_str(&format!("            <p>{}</p>\n", html_escape(&os_dist_str)));
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Loki Versions</h3>\n");
    html.push_str(&format!("            <p>{}</p>\n", html_escape(&version_dist_str)));
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Scan Duration</h3>\n");
    if min_duration != f64::INFINITY {
        html.push_str(&format!("            <p>Range: {:.1}s - {:.1}s<br>Avg: {:.1}s</p>\n",
            min_duration, max_duration, avg_duration));
    } else {
        html.push_str("            <p>N/A</p>\n");
    }
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    
    // Filter Panel
    html.push_str("    <div class=\"filter-panel\" id=\"filterPanel\">\n");
    html.push_str("        <div class=\"filter-panel-header\" onclick=\"toggleFilterPanel()\">\n");
    html.push_str("            <h3>\n");
    html.push_str("                <span>🔍 Active Filters</span>\n");
    html.push_str("                <span class=\"filter-count\" id=\"filterCount\">0</span>\n");
    html.push_str("            </h3>\n");
    html.push_str("            <div class=\"filter-panel-actions\">\n");
    html.push_str("                <button class=\"filter-panel-btn\" onclick=\"event.stopPropagation(); exportFilters()\">Export</button>\n");
    html.push_str("                <button class=\"filter-panel-btn\" onclick=\"event.stopPropagation(); document.getElementById('importInput').click()\">Import</button>\n");
    html.push_str("                <button class=\"filter-panel-btn danger\" onclick=\"event.stopPropagation(); clearAllFilters()\">Clear All</button>\n");
    html.push_str("            </div>\n");
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"filter-panel-content\">\n");
    html.push_str("            <div class=\"filter-list\" id=\"filterList\">\n");
    html.push_str("                <span class=\"filter-empty\">Click the <span class=\"filter-icon-hint\">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>\n");
    html.push_str("            </div>\n");
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    html.push_str("    <input type=\"file\" id=\"importInput\" class=\"hidden-input\" accept=\".json\" onchange=\"importFilters(event)\">\n");
    
    // Interactive statistics table
    html.push_str("    <div class=\"stats-table-container\">\n");
    html.push_str("        <h2>Host Statistics</h2>\n");
    html.push_str("        <div class=\"filter-state\" id=\"filterState\">\n");
    html.push_str("            <span>Showing:</span> All findings\n");
    html.push_str("            <button class=\"clear-filters-btn\" onclick=\"clearHostnameSeverityFilters()\" style=\"display:none;\" id=\"clearFiltersBtn\">Clear Host/Severity Filters</button>\n");
    html.push_str("        </div>\n");
    html.push_str("        <table id=\"statsTable\">\n");
    html.push_str("            <thead>\n");
    html.push_str("                <tr>\n");
    html.push_str("                    <th onclick=\"filterBySeverity('')\">Hostname</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('ALERT')\" data-severity=\"ALERT\">Alerts</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('WARNING')\" data-severity=\"WARNING\">Warnings</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('NOTICE')\" data-severity=\"NOTICE\">Notices</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('ERROR')\" data-severity=\"ERROR\">Errors</th>\n");
    html.push_str("                </tr>\n");
    html.push_str("            </thead>\n");
    html.push_str("            <tbody>\n");
    
    for (hostname, alerts, warnings, notices, errors) in &stats_rows {
        let hostname_escaped = html_escape(hostname);
        html.push_str(&format!(
            "                <tr>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostname('{}')\" data-hostname=\"{}\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'ALERT')\" data-hostname=\"{}\" data-severity=\"ALERT\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'WARNING')\" data-hostname=\"{}\" data-severity=\"WARNING\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'NOTICE')\" data-hostname=\"{}\" data-severity=\"NOTICE\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'ERROR')\" data-hostname=\"{}\" data-severity=\"ERROR\">{}</td>\n                </tr>\n",
            hostname_escaped, hostname_escaped, hostname_escaped,
            hostname_escaped, hostname_escaped, alerts,
            hostname_escaped, hostname_escaped, warnings,
            hostname_escaped, hostname_escaped, notices,
            hostname_escaped, hostname_escaped, errors
        ));
    }
    
    html.push_str("            </tbody>\n");
    html.push_str("        </table>\n");
    html.push_str("    </div>\n");
    
    // Merged findings list
    html.push_str("    <div class=\"findings-section\">\n");
    html.push_str("        <h2>All Findings (Sorted by Score)</h2>\n");
    
    if data.all_findings.is_empty() {
        html.push_str("        <div class=\"no-findings\">\n");
        html.push_str("            <h3>✓ No Findings</h3>\n");
        html.push_str("            <p>The combined scan completed without detecting any threats above the configured thresholds.</p>\n");
        html.push_str("        </div>\n");
    } else {
        for finding in &data.all_findings {
            html.push_str(&render_finding_with_hostname(finding));
        }
    }
    
    html.push_str("    </div>\n");
    
    // Context Menu
    html.push_str("    <!-- Context Menu -->\n");
    html.push_str("    <div class=\"context-menu\" id=\"contextMenu\">\n");
    html.push_str("        <div class=\"context-menu-item\" onclick=\"filterOutSelection()\">\n");
    html.push_str("            <span class=\"icon\">✖</span>\n");
    html.push_str("            <span>Filter out</span>\n");
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"context-menu-item\" onclick=\"searchOnGoogle()\">\n");
    html.push_str("            <span class=\"icon\">🔍</span>\n");
    html.push_str("            <span>Search on Google</span>\n");
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    
    // JavaScript for filtering
    html.push_str("    <script>\n");
    html.push_str(r##"        // =====================================================
        // FILTER STATE MANAGEMENT (Exclusion Filters)
        // =====================================================
        const STORAGE_KEY = 'loki_combined_filters_' + new Date().toISOString().slice(0, 10).replace(/-/g, '_');
        let filterList = [];
        let selectedText = '';
        
        // Load filters from localStorage on page load
        function loadFilters() {
            try {
                const stored = localStorage.getItem(STORAGE_KEY);
                if (stored) {
                    const data = JSON.parse(stored);
                    filterList = data.filters || [];
                }
            } catch (e) {
                console.warn('Failed to load filters:', e);
                filterList = [];
            }
            updateFilterUI();
            applyAllFilters();
        }
        
        // Save filters to localStorage
        function saveFilters() {
            try {
                const data = {
                    filters: filterList,
                    savedAt: new Date().toISOString()
                };
                localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
            } catch (e) {
                console.warn('Failed to save filters:', e);
            }
        }
        
        // =====================================================
        // FILTER UI
        // =====================================================
        function updateFilterUI() {
            const list = document.getElementById('filterList');
            const count = document.getElementById('filterCount');
            
            count.textContent = filterList.length;
            
            if (filterList.length === 0) {
                list.innerHTML = '<span class="filter-empty">Click the <span class="filter-icon-hint">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>';
            } else {
                list.innerHTML = filterList.map((f, i) => `
                    <div class="filter-chip">
                        <span class="filter-chip-text" title="${escapeHtml(f)}">${escapeHtml(truncateText(f, 40))}</span>
                        <button class="filter-chip-remove" onclick="removeFilter(${i})" title="Remove filter">×</button>
                    </div>
                `).join('');
            }
        }
        
        function toggleFilterPanel() {
            const panel = document.getElementById('filterPanel');
            panel.classList.toggle('open');
        }
        
        function addFilter(text) {
            if (!text || filterList.includes(text)) return;
            filterList.push(text);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        function removeFilter(index) {
            filterList.splice(index, 1);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        function clearAllFilters() {
            if (filterList.length === 0) return;
            if (!confirm('Clear all ' + filterList.length + ' exclusion filters?')) return;
            filterList = [];
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        // =====================================================
        // EXPORT / IMPORT
        // =====================================================
        function exportFilters() {
            if (filterList.length === 0) {
                alert('No filters to export');
                return;
            }
            const data = {
                filters: filterList,
                exportedAt: new Date().toISOString(),
                source: document.title
            };
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'loki-combined-filters-' + new Date().toISOString().slice(0, 10) + '.json';
            a.click();
            URL.revokeObjectURL(url);
        }
        
        function importFilters(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const data = JSON.parse(e.target.result);
                    if (Array.isArray(data.filters)) {
                        const newFilters = data.filters.filter(f => typeof f === 'string' && !filterList.includes(f));
                        filterList = filterList.concat(newFilters);
                        saveFilters();
                        updateFilterUI();
                        applyAllFilters();
                        alert('Imported ' + newFilters.length + ' new filters');
                    } else {
                        alert('Invalid filter file format');
                    }
                } catch (err) {
                    alert('Failed to parse filter file: ' + err.message);
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }
        
        // =====================================================
        // CONTEXT MENU
        // =====================================================
        const contextMenu = document.getElementById('contextMenu');
        
        document.addEventListener('contextmenu', function(e) {
            const selection = window.getSelection().toString().trim();
            if (selection) {
                e.preventDefault();
                selectedText = selection;
                contextMenu.style.left = e.clientX + 'px';
                contextMenu.style.top = e.clientY + 'px';
                contextMenu.classList.add('visible');
            }
        });
        
        document.addEventListener('click', function(e) {
            if (!contextMenu.contains(e.target)) {
                contextMenu.classList.remove('visible');
            }
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                contextMenu.classList.remove('visible');
            }
        });
        
        function filterOutSelection() {
            if (selectedText) {
                addFilter(selectedText);
                contextMenu.classList.remove('visible');
                window.getSelection().removeAllRanges();
            }
        }
        
        function searchOnGoogle() {
            if (selectedText) {
                window.open('https://www.google.com/search?q=' + encodeURIComponent(selectedText), '_blank');
                contextMenu.classList.remove('visible');
            }
        }
        
        // Inline filter button handler
        function filterValue(text, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            if (text) {
                addFilter(text.trim());
            }
        }
        
        // =====================================================
        // HOSTNAME/SEVERITY FILTERING
        // =====================================================
        let activeHostname = null;
        let activeSeverity = null;
        
        function updateFilterState() {
            const stateEl = document.getElementById('filterState');
            const clearBtn = document.getElementById('clearFiltersBtn');
            let stateText = '<span>Showing:</span> ';
            
            if (activeHostname && activeSeverity) {
                stateText += `${activeHostname} - ${activeSeverity}`;
            } else if (activeHostname) {
                stateText += activeHostname;
            } else if (activeSeverity) {
                stateText += activeSeverity;
            } else {
                stateText += 'All findings';
            }
            
            stateEl.innerHTML = stateText;
            if (activeHostname || activeSeverity) {
                clearBtn.style.display = 'inline-block';
            } else {
                clearBtn.style.display = 'none';
            }
            
            // Update active filter indicators in table
            document.querySelectorAll('#statsTable th, #statsTable td').forEach(cell => {
                cell.classList.remove('active-filter');
            });
            
            if (activeHostname) {
                document.querySelectorAll(`[data-hostname="${activeHostname}"]`).forEach(cell => {
                    if (!activeSeverity || cell.dataset.severity === activeSeverity) {
                        cell.classList.add('active-filter');
                    }
                });
            }
            
            if (activeSeverity) {
                document.querySelectorAll(`[data-severity="${activeSeverity}"]`).forEach(cell => {
                    if (!activeHostname || cell.dataset.hostname === activeHostname) {
                        cell.classList.add('active-filter');
                    }
                });
            }
        }
        
        function filterByHostname(hostname) {
            if (activeHostname === hostname) {
                activeHostname = null;
            } else {
                activeHostname = hostname;
            }
            activeSeverity = null; // Clear severity filter when selecting host
            applyFilters();
            updateFilterState();
        }
        
        function filterBySeverity(severity) {
            if (!severity) {
                activeSeverity = null;
            } else if (activeSeverity === severity) {
                activeSeverity = null;
            } else {
                activeSeverity = severity;
            }
            activeHostname = null; // Clear hostname filter when selecting severity
            applyFilters();
            updateFilterState();
        }
        
        function filterByHostnameAndSeverity(hostname, severity) {
            if (activeHostname === hostname && activeSeverity === severity) {
                activeHostname = null;
                activeSeverity = null;
            } else {
                activeHostname = hostname;
                activeSeverity = severity;
            }
            applyFilters();
            updateFilterState();
        }
        
        function clearHostnameSeverityFilters() {
            activeHostname = null;
            activeSeverity = null;
            applyAllFilters();
            updateFilterState();
        }
        
        function applyFilters() {
            applyAllFilters();
        }
        
        function applyAllFilters() {
            document.querySelectorAll('.finding-card').forEach(card => {
                const cardHostname = card.dataset.hostname;
                const cardSeverity = card.dataset.severity;
                const cardText = card.textContent;
                
                let show = true;
                
                // Check hostname/severity filters
                if (activeHostname && cardHostname !== activeHostname) {
                    show = false;
                }
                
                if (activeSeverity && cardSeverity !== activeSeverity) {
                    show = false;
                }
                
                // Check exclusion filters (exact match)
                if (show && filterList.some(f => cardText.includes(f))) {
                    show = false;
                }
                
                if (show) {
                    card.classList.remove('hidden');
                } else {
                    card.classList.add('hidden');
                }
            });
        }
        
        // =====================================================
        // UTILITY FUNCTIONS
        // =====================================================
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function truncateText(text, maxLen) {
            if (text.length <= maxLen) return text;
            return text.substring(0, maxLen) + '...';
        }
        
        // Initialize
        loadFilters();
        updateFilterState();
    "##);
    html.push_str("    </script>\n");
    html.push_str("</body>\n</html>\n");
    
    // Write HTML file
    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create HTML file: {}", e))?;
    file.write_all(html.as_bytes())
        .map_err(|e| format!("Failed to write HTML file: {}", e))?;
    
    Ok(output_path.to_string())
}

/// Simple finding renderer for combined reports (kept for backward compatibility)
#[allow(dead_code)]
fn render_finding_simple(finding: &LogEvent, severity_class: &str) -> String {
    let path_or_name = finding.file_path.as_deref()
        .or(finding.process_name.as_deref())
        .unwrap_or("Unknown");
    let score = finding.score.unwrap_or(0.0).round() as i16;
    
    format!(
        "        <div class=\"finding {}\">\n            <strong>{}</strong> (Score: {})<br>\n            Path: {}<br>\n        </div>\n",
        severity_class, finding.level, score, path_or_name
    )
}

/// Render finding with hostname and data attributes for filtering
fn render_finding_with_hostname(finding: &LogEvent) -> String {
    let level = finding.level.to_uppercase();
    let level_class = match level.as_str() {
        "ALERT" => "alert",
        "WARNING" => "warning",
        "ERROR" => "error",
        _ => "notice",
    };
    
    let hostname = &finding.hostname;
    let hostname_escaped = html_escape(hostname);
    let score = finding.score.unwrap_or(0.0).round() as i16;
    let path_or_name = finding.file_path.as_deref()
        .or(finding.process_name.as_deref())
        .unwrap_or("Unknown");
    let path_escaped = html_escape(path_or_name);
    
    // Escape hostname for JavaScript
    let hostname_js = hostname.replace('\\', "\\\\").replace('\'', "\\'");
    
    let mut details_html = String::new();
    
    if let Some(size) = finding.file_size {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Size:</span> <span class="detail-value">{}</span></div>"#,
            format_size(size as usize)
        ));
    }
    
    if let Some(ref md5) = finding.md5 {
        let md5_js = md5.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">MD5:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(md5), md5_js
        ));
    }
    
    if let Some(ref sha1) = finding.sha1 {
        let sha1_js = sha1.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA1:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(sha1), sha1_js
        ));
    }
    
    if let Some(ref sha256) = finding.sha256 {
        let sha256_js = sha256.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA256:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(sha256), sha256_js
        ));
    }
    
    let reasons_html = if let Some(ref reasons) = finding.reasons {
        let mut reasons_str = String::from(r#"<div class="reasons-section"><h4>Match Reasons</h4>"#);
        for reason in reasons {
            // Extract rule name if it's a YARA match
            let rule_name = if reason.message.starts_with("YARA match with rule ") || reason.message.starts_with("YARA-X match with rule ") {
                reason.message.split(" rule ").nth(1).map(|s| s.to_string())
            } else {
                None
            };
            
            let filter_btn = if let Some(ref rn) = rule_name {
                let rule_js = rn.replace('\\', "\\\\").replace('\'', "\\'");
                format!(r#"<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this rule">✖</button>"#, rule_js)
            } else {
                String::new()
            };
            
            reasons_str.push_str(&format!(
                r#"<div class="reason-item"><strong>{}:</strong> {} (Score: {}){}</div>"#,
                html_escape(&reason.message),
                reason.description.as_ref().map(|d| html_escape(d)).unwrap_or_default(),
                reason.score,
                filter_btn
            ));
        }
        reasons_str.push_str("</div>");
        reasons_str
    } else {
        String::new()
    };
    
    // Escape path for JavaScript
    let path_js = path_or_name.replace('\\', "\\\\").replace('\'', "\\'");
    
    format!(
        r#"        <div class="finding-card {}" data-hostname="{}" data-severity="{}" data-score="{}">
            <div class="finding-header">
                <div class="finding-title">
                    {}<span class="hostname-badge">{}</span>
                </div>
                <div class="finding-score">Score: {}</div>
            </div>
            <div class="finding-path">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this path">✖</button></div>
            {}
            {}
        </div>
"#,
        level_class,
        hostname_js,
        level,
        score,
        html_escape(&level),
        hostname_escaped,
        score,
        path_escaped,
        path_js,
        details_html,
        reasons_html
    )
}

const LOKI_UTIL_VERSION: &str = env!("CARGO_PKG_VERSION");

// Helper functions for HTML rendering (copied from helpers/html_report.rs to maintain consistency)
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1_000;
    const MB: usize = KB * 1_000;
    const GB: usize = MB * 1_000;
    
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// Helper functions kept for potential future use
#[allow(dead_code)]
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[allow(dead_code)]
fn format_rfc3339_to_datetime(rfc3339: &str) -> String {
    // Simple formatter - just return as-is for now, or parse if needed
    rfc3339.to_string()
}

/// Simplified render_html function for loki-util
/// This produces HTML reports similar to the main loki binary
fn render_html_simplified(
    data: &ReportData,
    _scan_config: &ScanConfig,
    version: &str,
    jsonl_path: &str,
    title_override: Option<&str>,
) -> String {
    let hostname = data.scan_start.as_ref()
        .map(|e| e.hostname.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let default_title = format!("Loki-RS Scan Report - {}", hostname);
    let title = title_override.unwrap_or(&default_title);
    
    let scan_start_time = data.scan_start.as_ref()
        .map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let scan_end_time = data.scan_end.as_ref()
        .map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    // Extract metadata from info events (not used in simplified version but kept for future use)
    let _cmd_flags = data.info_events.iter()
        .find(|e| e.message.contains("Command line flags"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    let _os_info = data.info_events.iter()
        .find(|e| e.message.contains("Operating system"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Count findings by level
    let alert_count = data.findings.iter().filter(|f| f.level.to_uppercase() == "ALERT").count();
    let warning_count = data.findings.iter().filter(|f| f.level.to_uppercase() == "WARNING").count();
    let notice_count = data.findings.iter().filter(|f| f.level.to_uppercase() == "NOTICE").count();
    
    let jsonl_filename = Path::new(jsonl_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| jsonl_path.to_string());
    
    let findings_html = render_findings_simplified(&data.findings);
    
    // Generate simplified HTML (matching the structure of the full version)
    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #3fb950;
            --alert-bg: #f85149;
            --warning-bg: #d29922;
            --notice-bg: #3fb950;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 20px;
        }}
        header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        .logo-text {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 10px;
        }}
        .logo-text span {{ color: var(--accent); }}
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }}
        .info-card {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px 16px;
        }}
        .info-card h3 {{
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }}
        .info-card p {{
            font-size: 14px;
            color: var(--text-primary);
            word-break: break-all;
        }}
        .stats-bar {{
            display: flex;
            gap: 24px;
            margin-bottom: 20px;
            padding: 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .stat-item {{
            text-align: center;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: 700;
            color: var(--accent);
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .finding {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }}
        .finding.alert {{ border-left: 4px solid var(--alert-bg); }}
        .finding.warning {{ border-left: 4px solid var(--warning-bg); }}
        .finding.notice {{ border-left: 4px solid var(--notice-bg); }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        .finding-score {{
            font-size: 18px;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 4px;
            background: var(--bg-tertiary);
        }}
        .finding-path {{
            font-family: monospace;
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 12px;
            word-break: break-all;
        }}
        .detail-item {{
            margin: 8px 0;
            font-size: 13px;
        }}
        .detail-label {{
            color: var(--text-secondary);
            font-weight: 600;
        }}
        .detail-value {{
            color: var(--text-primary);
        }}
        .reasons-section {{
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }}
        .reason-item {{
            background: var(--bg-tertiary);
            padding: 8px 12px;
            border-radius: 4px;
            margin: 8px 0;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: var(--accent);
        }}
    </style>
</head>
<body>
    <header>
        <div class="logo-text">Loki<span>-RS</span> <span class="version">v{}</span></div>
        <div class="scan-info">
            <div class="info-card">
                <h3>Hostname</h3>
                <p>{}</p>
            </div>
            <div class="info-card">
                <h3>Scan Start</h3>
                <p>{}</p>
            </div>
            <div class="info-card">
                <h3>Scan End</h3>
                <p>{}</p>
            </div>
            <div class="info-card">
                <h3>JSONL File</h3>
                <p>{}</p>
            </div>
        </div>
    </header>
    <main>
        <div class="stats-bar">
            <div class="stat-item">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" style="color: var(--alert-bg);">{}</div>
                <div class="stat-label">Alerts</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" style="color: var(--warning-bg);">{}</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" style="color: var(--notice-bg);">{}</div>
                <div class="stat-label">Notices</div>
            </div>
        </div>
        {}
    </main>
</body>
</html>"##,
        html_escape(title),
        html_escape(version),
        html_escape(&hostname),
        html_escape(&scan_start_time),
        html_escape(&scan_end_time),
        html_escape(&jsonl_filename),
        data.findings.len(),
        alert_count,
        warning_count,
        notice_count,
        findings_html
    )
}

fn render_findings_simplified(findings: &[LogEvent]) -> String {
    if findings.is_empty() {
        return r#"<div class="no-findings">
            <h2>✓ No Findings</h2>
            <p>The scan completed without detecting any threats above the configured thresholds.</p>
        </div>"#.to_string();
    }
    
    let mut html = String::new();
    for (idx, finding) in findings.iter().enumerate() {
        html.push_str(&render_finding_card_simplified(finding, idx));
    }
    html
}

fn render_finding_card_simplified(finding: &LogEvent, _idx: usize) -> String {
    let level = finding.level.to_lowercase();
    let level_class = match level.as_str() {
        "alert" => "alert",
        "warning" => "warning",
        _ => "notice",
    };
    
    let score = finding.score.unwrap_or(0.0).round() as i16;
    let path_or_name = finding.file_path.as_deref()
        .or(finding.process_name.as_deref())
        .unwrap_or("Unknown");
    
    let mut details_html = String::new();
    
    if let Some(size) = finding.file_size {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Size:</span> <span class="detail-value">{}</span></div>"#,
            format_size(size as usize)
        ));
    }
    
    if let Some(ref md5) = finding.md5 {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">MD5:</span> <span class="detail-value">{}</span></div>"#,
            html_escape(md5)
        ));
    }
    
    if let Some(ref sha1) = finding.sha1 {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA1:</span> <span class="detail-value">{}</span></div>"#,
            html_escape(sha1)
        ));
    }
    
    if let Some(ref sha256) = finding.sha256 {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA256:</span> <span class="detail-value">{}</span></div>"#,
            html_escape(sha256)
        ));
    }
    
    let reasons_html = if let Some(ref reasons) = finding.reasons {
        let mut reasons_str = String::from(r#"<div class="reasons-section"><h4>Match Reasons</h4>"#);
        for reason in reasons {
            reasons_str.push_str(&format!(
                r#"<div class="reason-item"><strong>{}:</strong> {} (Score: {})</div>"#,
                html_escape(&reason.message),
                reason.description.as_ref().map(|d| html_escape(d)).unwrap_or_default(),
                reason.score
            ));
        }
        reasons_str.push_str("</div>");
        reasons_str
    } else {
        String::new()
    };
    
    format!(
        r#"<div class="finding {}">
            <div class="finding-header">
                <div class="finding-title">{}</div>
                <div class="finding-score">Score: {}</div>
            </div>
            <div class="finding-path">{}</div>
            {}
            {}
        </div>"#,
        level_class,
        html_escape(&finding.level),
        score,
        html_escape(path_or_name),
        details_html,
        reasons_html
    )
}
