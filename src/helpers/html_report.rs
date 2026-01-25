//! HTML Report Generator
//! 
//! Generates a styled HTML report from JSONL scan findings.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::ScanConfig;

/// Represents a log event from the JSONL file (subset of fields we need)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogEvent {
    timestamp: DateTime<Utc>,
    level: String,
    event_type: String,
    hostname: String,
    message: String,
    #[serde(default)]
    context: BTreeMap<String, String>,
    file_path: Option<String>,
    pid: Option<u32>,
    process_name: Option<String>,
    score: Option<f64>,
    file_type: Option<String>,
    file_size: Option<u64>,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    // File timestamps (RFC3339 format)
    file_created: Option<String>,
    file_modified: Option<String>,
    file_accessed: Option<String>,
    reasons: Option<Vec<MatchReason>>,
    // Process-specific fields
    start_time: Option<i64>,
    run_time: Option<String>,
    memory_bytes: Option<u64>,
    cpu_usage: Option<f32>,
    connection_count: Option<usize>,
    listening_ports: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MatchReason {
    message: String,
    score: i16,
    description: Option<String>,
    author: Option<String>,
    reference: Option<String>,
    matched_strings: Option<Vec<String>>,
}

/// Parsed report data
pub struct ReportData {
    scan_start: Option<LogEvent>,
    scan_end: Option<LogEvent>,
    info_events: Vec<LogEvent>,
    findings: Vec<LogEvent>,
}

/// Generate an HTML report from a JSONL file
/// Returns the path to the generated HTML file on success
pub fn generate_report(jsonl_path: &str, scan_config: &ScanConfig, version: &str) -> Result<String, String> {
    // Determine output path (same as JSONL but with .html extension)
    let html_path = jsonl_path.replace(".jsonl", ".html");
    
    // Read and parse JSONL
    let report_data = parse_jsonl(jsonl_path)?;
    
    // Generate HTML
    let html_content = render_html(&report_data, scan_config, version, jsonl_path);
    
    // Write HTML file
    let mut file = File::create(&html_path)
        .map_err(|e| format!("Failed to create HTML file: {}", e))?;
    file.write_all(html_content.as_bytes())
        .map_err(|e| format!("Failed to write HTML file: {}", e))?;
    
    Ok(html_path)
}

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

pub fn render_html(data: &ReportData, scan_config: &ScanConfig, version: &str, jsonl_path: &str) -> String {
    let hostname = data.scan_start.as_ref()
        .map(|e| e.hostname.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let scan_start_time = data.scan_start.as_ref()
        .map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let scan_end_time = data.scan_end.as_ref()
        .map(|e| e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    // Extract command line flags from info events
    let cmd_flags = data.info_events.iter()
        .find(|e| e.message.contains("Command line flags"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Extract OS info
    let os_info = data.info_events.iter()
        .find(|e| e.message.contains("Operating system"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Extract CPU info
    let cpu_info = data.info_events.iter()
        .find(|e| e.message.contains("CPU information"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Extract memory info
    let memory_info = data.info_events.iter()
        .find(|e| e.message.contains("Memory information"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Extract network info
    let network_info = data.info_events.iter()
        .find(|e| e.message.contains("Network interfaces"))
        .map(|e| e.message.clone())
        .unwrap_or_default();
    
    // Extract disk info - collect all disk entries
    let disk_info: Vec<String> = data.info_events.iter()
        .filter(|e| e.message.contains("Hard disk"))
        .map(|e| e.message.clone())
        .collect();
    
    // Count findings by level
    let alert_count = data.findings.iter().filter(|f| f.level == "ALERT").count();
    let warning_count = data.findings.iter().filter(|f| f.level == "WARNING").count();
    let notice_count = data.findings.iter().filter(|f| f.level == "NOTICE").count();
    
    // Get JSONL filename for display
    let jsonl_filename = Path::new(jsonl_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| jsonl_path.to_string());
    
    let findings_html = render_findings(&data.findings);
    
    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loki-RS Scan Report - {hostname}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #3fb950;
            --accent-light: #56d364;
            --alert-bg: #f85149;
            --alert-text: #ffdce0;
            --warning-bg: #d29922;
            --warning-text: #3d2a00;
            --notice-bg: #3fb950;
            --notice-text: #0d2818;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }}
        
        header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 24px;
        }}
        
        .header-content {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 20px;
        }}
        
        .logo-text {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .logo-text span {{
            color: var(--accent);
        }}
        
        .version {{
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 400;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
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
            letter-spacing: 0.5px;
        }}
        
        .info-card p {{
            font-size: 14px;
            color: var(--text-primary);
            word-break: break-all;
        }}
        
        .info-card code {{
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-size: 13px;
            background: var(--bg-primary);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        
        nav {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .nav-content {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
            justify-content: space-between;
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 6px 14px;
            border: 1px solid var(--border-color);
            border-radius: 20px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover {{
            border-color: var(--accent);
        }}
        
        .filter-btn.active {{
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }}
        
        .filter-btn .count {{
            margin-left: 6px;
            opacity: 0.8;
        }}
        
        .search-box {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .search-box input {{
            padding: 8px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 14px;
            width: 280px;
        }}
        
        .search-box input:focus {{
            outline: none;
            border-color: var(--accent);
        }}
        
        .search-box input::placeholder {{
            color: var(--text-secondary);
        }}
        
        main {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
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
        
        .stat {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .stat-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        
        .stat-dot.alert {{ background: var(--alert-bg); }}
        .stat-dot.warning {{ background: var(--warning-bg); }}
        .stat-dot.notice {{ background: var(--notice-bg); }}
        
        .stat-label {{
            font-size: 14px;
            color: var(--text-secondary);
        }}
        
        .stat-value {{
            font-size: 18px;
            font-weight: 600;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }}
        
        .no-findings h2 {{
            color: var(--notice-bg);
            margin-bottom: 8px;
        }}
        
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        
        .finding-card.hidden {{
            display: none;
        }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }}
        
        .severity-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-badge.alert {{
            background: var(--alert-bg);
            color: var(--alert-text);
        }}
        
        .severity-badge.warning {{
            background: var(--warning-bg);
            color: var(--warning-text);
        }}
        
        .severity-badge.notice {{
            background: var(--notice-bg);
            color: var(--notice-text);
        }}
        
        .score {{
            font-size: 18px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .finding-path {{
            flex: 1;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-size: 14px;
            color: var(--accent);
            word-break: break-all;
        }}
        
        .finding-type {{
            font-size: 12px;
            color: var(--text-secondary);
            background: var(--bg-primary);
            padding: 4px 8px;
            border-radius: 4px;
        }}
        
        .finding-body {{
            padding: 16px;
        }}
        
        .finding-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }}
        
        .detail-item {{
            font-size: 13px;
        }}
        
        .detail-item-hash {{
            font-size: 13px;
            grid-column: 1 / -1;
        }}
        
        .detail-label {{
            color: var(--text-secondary);
        }}
        
        .detail-value {{
            color: var(--text-primary);
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }}
        
        .hash-value {{
            cursor: pointer;
            transition: color 0.2s;
        }}
        
        .hash-value:hover {{
            color: var(--accent);
        }}
        
        .reasons-section {{
            margin: 16px 0;
        }}
        
        .reasons-section h4 {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 10px;
            letter-spacing: 0.5px;
        }}
        
        .reason {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
        }}
        
        .reason-message {{
            font-weight: 500;
            margin-bottom: 6px;
        }}
        
        .reason-meta {{
            font-size: 12px;
            color: var(--text-secondary);
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }}
        
        .matched-strings {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid var(--border-color);
        }}
        
        .matched-strings-title {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        
        .matched-string {{
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-size: 12px;
            background: var(--bg-primary);
            padding: 4px 8px;
            border-radius: 4px;
            margin: 4px 4px 4px 0;
            display: inline-block;
            word-break: break-all;
        }}
        
        .show-more-btn {{
            background: none;
            border: none;
            color: var(--accent);
            cursor: pointer;
            font-size: 12px;
            padding: 4px 0;
        }}
        
        .show-more-btn:hover {{
            text-decoration: underline;
        }}
        
        .hidden-strings {{
            display: none;
        }}
        
        .hidden-strings.visible {{
            display: block;
        }}
        
        .raw-json {{
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
        }}
        
        .raw-json-title {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .raw-json pre {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px;
            overflow-x: auto;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            font-size: 12px;
            line-height: 1.6;
        }}
        
        .json-key {{ color: #79c0ff; }}
        .json-string {{ color: #a5d6ff; }}
        .json-number {{ color: #56d4dd; }}
        .json-boolean {{ color: #ff7b72; }}
        .json-null {{ color: #8b949e; }}
        
        .copy-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
        }}
        
        .copy-btn:hover {{
            color: var(--accent);
            border-color: var(--accent);
        }}
        
        footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            font-size: 13px;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }}
        
        footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        footer a:hover {{
            text-decoration: underline;
        }}
        
        /* Collapsible sections */
        .collapsible {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-top: 16px;
            overflow: hidden;
        }}
        
        .collapsible-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }}
        
        .collapsible-header:hover {{
            background: var(--bg-secondary);
        }}
        
        .collapsible-header h3 {{
            font-size: 13px;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.5px;
            margin: 0;
        }}
        
        .collapsible-icon {{
            color: var(--text-secondary);
            font-size: 12px;
            transition: transform 0.2s;
        }}
        
        .collapsible.open .collapsible-icon {{
            transform: rotate(180deg);
        }}
        
        .collapsible-content {{
            display: none;
            padding: 16px;
            border-top: 1px solid var(--border-color);
        }}
        
        .collapsible.open .collapsible-content {{
            display: block;
        }}
        
        .raw-json-collapsible {{
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
        }}
        
        .raw-json-toggle {{
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            font-size: 12px;
            color: var(--text-secondary);
            padding: 8px 0;
            user-select: none;
        }}
        
        .raw-json-toggle:hover {{
            color: var(--accent);
        }}
        
        .raw-json-toggle .toggle-icon {{
            transition: transform 0.2s;
        }}
        
        .raw-json-toggle.open .toggle-icon {{
            transform: rotate(90deg);
        }}
        
        .raw-json-content {{
            display: none;
            margin-top: 8px;
        }}
        
        .raw-json-content.visible {{
            display: block;
        }}
        
        @media (max-width: 768px) {{
            .nav-content {{
                flex-direction: column;
                align-items: stretch;
            }}
            
            .search-box input {{
                width: 100%;
            }}
            
            .finding-header {{
                flex-wrap: wrap;
            }}
        }}
        
        /* Hash and reference links */
        .hash-link {{
            color: var(--accent);
            text-decoration: none;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
            display: inline-block;
            word-break: break-all;
            max-width: 100%;
        }}
        
        .hash-link:hover {{
            text-decoration: underline;
        }}
        
        .reference-link {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        .reference-link:hover {{
            text-decoration: underline;
        }}
        
        /* Context menu */
        .context-menu {{
            position: fixed;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 4px 0;
            min-width: 180px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            z-index: 1000;
            display: none;
        }}
        
        .context-menu.visible {{
            display: block;
        }}
        
        .context-menu-item {{
            padding: 8px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            color: var(--text-primary);
        }}
        
        .context-menu-item:hover {{
            background: var(--bg-tertiary);
        }}
        
        .context-menu-item .icon {{
            font-size: 14px;
        }}
        
        /* Filter panel */
        .filter-panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .filter-panel-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
        }}
        
        .filter-panel-header h3 {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .filter-count {{
            background: var(--accent);
            color: #fff;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
        }}
        
        .filter-panel-actions {{
            display: flex;
            gap: 8px;
        }}
        
        .filter-panel-btn {{
            padding: 4px 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 11px;
        }}
        
        .filter-panel-btn:hover {{
            color: var(--accent);
            border-color: var(--accent);
        }}
        
        .filter-panel-btn.danger:hover {{
            color: var(--alert-bg);
            border-color: var(--alert-bg);
        }}
        
        .filter-panel-content {{
            padding: 16px;
            display: none;
        }}
        
        .filter-panel.open .filter-panel-content {{
            display: block;
        }}
        
        .filter-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 12px;
        }}
        
        .filter-chip {{
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 4px 8px 4px 12px;
            font-size: 12px;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }}
        
        .filter-chip-text {{
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .filter-chip-remove {{
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
        }}
        
        .filter-chip-remove:hover {{
            background: var(--alert-bg);
            color: var(--alert-text);
        }}
        
        .filter-actions {{
            display: flex;
            gap: 8px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }}
        
        .filter-empty {{
            color: var(--text-secondary);
            font-size: 13px;
            font-style: italic;
        }}
        
        .filter-icon-hint {{
            display: inline-block;
            color: #ff6b6b;
            font-style: normal;
            font-weight: bold;
        }}
        
        /* Hidden file input for import */
        .hidden-input {{
            display: none;
        }}
        
        /* Nav right section */
        .nav-right {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        /* Compact nav filters indicator */
        .nav-filters {{
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: rgba(248, 81, 73, 0.15);
            border: 1px solid var(--alert-bg);
            border-radius: 16px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 12px;
        }}
        
        .nav-filters:hover {{
            background: rgba(248, 81, 73, 0.25);
        }}
        
        .nav-filters.hidden {{
            display: none;
        }}
        
        .nav-filters-icon {{
            font-size: 12px;
        }}
        
        .nav-filters-count {{
            background: var(--alert-bg);
            color: #fff;
            padding: 1px 6px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 11px;
        }}
        
        .nav-filters-label {{
            color: var(--text-secondary);
        }}
        
        /* Help tooltip */
        .filter-help {{
            position: relative;
            cursor: help;
        }}
        
        .help-icon {{
            display: flex;
            align-items: center;
            justify-content: center;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 600;
        }}
        
        .filter-help:hover .help-icon {{
            color: var(--accent);
            border-color: var(--accent);
        }}
        
        .help-tooltip {{
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 8px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            min-width: 280px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
            z-index: 200;
            display: none;
            font-size: 13px;
        }}
        
        .filter-help:hover .help-tooltip {{
            display: block;
        }}
        
        .help-tooltip strong {{
            display: block;
            margin-bottom: 8px;
            color: var(--accent);
        }}
        
        .help-tooltip ul {{
            margin: 0;
            padding-left: 18px;
        }}
        
        .help-tooltip li {{
            margin: 4px 0;
            color: var(--text-secondary);
        }}
        
        .help-tooltip li strong {{
            display: inline;
            color: var(--text-primary);
        }}
        
        .help-tooltip .inline-filter-btn {{
            display: inline-block;
            font-size: 11px;
        }}
        
        /* Filter panel inline help */
        .filter-help-inline {{
            position: relative;
            cursor: help;
            margin-left: 4px;
        }}
        
        .filter-help-inline .help-icon {{
            width: 18px;
            height: 18px;
            font-size: 11px;
        }}
        
        .filter-help-inline:hover .help-icon {{
            color: var(--accent);
            border-color: var(--accent);
        }}
        
        .help-tooltip-inline {{
            position: absolute;
            bottom: 100%;
            right: 0;
            margin-bottom: 8px;
            padding: 12px 16px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            min-width: 280px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
            z-index: 200;
            display: none;
            font-size: 13px;
        }}
        
        .filter-help-inline:hover .help-tooltip-inline {{
            display: block;
        }}
        
        .help-tooltip-inline strong {{
            display: block;
            margin-bottom: 8px;
            color: var(--accent);
        }}
        
        .help-tooltip-inline ul {{
            margin: 0;
            padding-left: 18px;
        }}
        
        .help-tooltip-inline li {{
            margin: 4px 0;
            color: var(--text-secondary);
        }}
        
        .help-tooltip-inline li strong {{
            display: inline;
            color: var(--text-primary);
        }}
        
        /* Inline filter button for field values */
        .filter-btn-inline {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 10px;
            opacity: 0;
            transition: all 0.15s;
            margin-left: 4px;
            vertical-align: middle;
            border-radius: 3px;
        }}
        
        .detail-item:hover .filter-btn-inline,
        .detail-item-hash:hover .filter-btn-inline,
        .reason:hover .filter-btn-inline,
        .finding-path:hover .filter-btn-inline {{
            opacity: 0.6;
        }}
        
        .filter-btn-inline:hover {{
            opacity: 1 !important;
            background: rgba(248, 81, 73, 0.2);
            color: var(--alert-bg);
        }}
        
        .matched-string {{
            position: relative;
        }}
        
        .matched-string:hover .filter-btn-inline {{
            opacity: 0.6;
        }}
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <div class="logo">
                <div class="logo-text">
                    LOKI<span>-RS</span>
                    <span class="version">v{version}</span>
                </div>
            </div>
            
            <div class="scan-info">
                <div class="info-card">
                    <h3>Hostname</h3>
                    <p><code>{hostname}</code></p>
                </div>
                <div class="info-card">
                    <h3>Scan Start</h3>
                    <p>{scan_start_time}</p>
                </div>
                <div class="info-card">
                    <h3>Scan End</h3>
                    <p>{scan_end_time}</p>
                </div>
                <div class="info-card">
                    <h3>Operating System</h3>
                    <p>{os_info}</p>
                </div>
                <div class="info-card">
                    <h3>Thresholds</h3>
                    <p>Alert: {alert_threshold} | Warning: {warning_threshold} | Notice: {notice_threshold}</p>
                </div>
                <div class="info-card">
                    <h3>Scan Settings</h3>
                    <p>Max Size: {max_file_size} | Threads: {threads} | CPU: {cpu_limit}%</p>
                </div>
                <div class="info-card">
                    <h3>YARA Rules</h3>
                    <p>{yara_rules_count} rules loaded</p>
                </div>
                <div class="info-card">
                    <h3>IOC Count</h3>
                    <p>{ioc_count} indicators loaded</p>
                </div>
            </div>
            
            <div class="scan-info" style="margin-top: 12px;">
                <div class="info-card" style="grid-column: 1 / -1;">
                    <h3>Command Line</h3>
                    <p><code>{cmd_flags}</code></p>
                </div>
            </div>
            
            <!-- Collapsible System Information -->
            <div class="collapsible" id="systemInfoCollapsible">
                <div class="collapsible-header" onclick="toggleCollapsible('systemInfoCollapsible')">
                    <h3>System Information (click to expand)</h3>
                    <span class="collapsible-icon">▼</span>
                </div>
                <div class="collapsible-content">
                    <div class="scan-info">
                        <div class="info-card">
                            <h3>CPU</h3>
                            <p>{cpu_info}</p>
                        </div>
                        <div class="info-card">
                            <h3>Memory</h3>
                            <p>{memory_info}</p>
                        </div>
                        <div class="info-card">
                            <h3>Network Interfaces</h3>
                            <p>{network_info}</p>
                        </div>
                    </div>
                    <div class="scan-info" style="margin-top: 12px;">
                        <div class="info-card" style="grid-column: 1 / -1;">
                            <h3>Disk Information</h3>
                            <p>{disk_info_html}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </header>
    
    <nav>
        <div class="nav-content">
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all">
                    All<span class="count">({total_findings})</span>
                </button>
                <button class="filter-btn" data-filter="alert">
                    Alert<span class="count">({alert_count})</span>
                </button>
                <button class="filter-btn" data-filter="warning">
                    Warning<span class="count">({warning_count})</span>
                </button>
                <button class="filter-btn" data-filter="notice">
                    Notice<span class="count">({notice_count})</span>
                </button>
            </div>
            
            <!-- Compact active filters indicator in nav -->
            <div class="nav-filters hidden" id="navFilters" onclick="scrollToFilterPanel()">
                <span class="nav-filters-icon">✖</span>
                <span class="nav-filters-count" id="navFilterCount">0</span>
                <span class="nav-filters-label">filters active</span>
            </div>
            
            <div class="nav-right">
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="Search by path, rule, or hash...">
                </div>
                <div class="filter-help" title="Select any text and right-click to filter it out">
                    <span class="help-icon">?</span>
                    <div class="help-tooltip">
                        <strong>💡 Filter Tips</strong>
                        <ul>
                            <li>Select any text and <strong>right-click</strong> to filter it out</li>
                            <li>Click the <span class="inline-filter-btn">✖</span> button next to values to exclude them</li>
                            <li>Filters persist across page reloads</li>
                            <li>Export/import filters using the panel below</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </nav>
    
    <main>
        <!-- Filter Panel -->
        <div class="filter-panel" id="filterPanel">
            <div class="filter-panel-header" onclick="toggleFilterPanel()">
                <h3>
                    <span>🔍 Active Filters</span>
                    <span class="filter-count" id="filterCount">0</span>
                </h3>
                <div class="filter-panel-actions">
                    <button class="filter-panel-btn" onclick="event.stopPropagation(); exportFilters()">Export</button>
                    <button class="filter-panel-btn" onclick="event.stopPropagation(); document.getElementById('importInput').click()">Import</button>
                    <button class="filter-panel-btn danger" onclick="event.stopPropagation(); clearAllFilters()">Clear All</button>
                </div>
            </div>
            <div class="filter-panel-content">
                <div class="filter-list" id="filterList">
                    <span class="filter-empty">Click the <span class="filter-icon-hint">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>
                </div>
            </div>
        </div>
        <input type="file" id="importInput" class="hidden-input" accept=".json" onchange="importFilters(event)">
        
        <div class="stats-bar">
            <div class="stat">
                <div class="stat-dot alert"></div>
                <span class="stat-label">Alerts:</span>
                <span class="stat-value">{alert_count}</span>
            </div>
            <div class="stat">
                <div class="stat-dot warning"></div>
                <span class="stat-label">Warnings:</span>
                <span class="stat-value">{warning_count}</span>
            </div>
            <div class="stat">
                <div class="stat-dot notice"></div>
                <span class="stat-label">Notices:</span>
                <span class="stat-value">{notice_count}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Source:</span>
                <span class="stat-value" style="font-size: 14px;">{jsonl_filename}</span>
            </div>
        </div>
        
        <section id="findings">
            {findings_html}
        </section>
    </main>
    
    <footer>
        Generated by <a href="https://github.com/Neo23x0/Loki" target="_blank">Loki-RS</a> v{version} &mdash; 
        High-Performance, Multi-threaded YARA &amp; IOC Scanner
    </footer>
    
    <!-- Context Menu -->
    <div class="context-menu" id="contextMenu">
        <div class="context-menu-item" onclick="filterOutSelection()">
            <span class="icon">✖</span>
            <span>Filter out</span>
        </div>
        <div class="context-menu-item" onclick="searchOnGoogle()">
            <span class="icon">🔍</span>
            <span>Search on Google</span>
        </div>
    </div>
    
    <script>
        // =====================================================
        // PERFORMANCE-OPTIMIZED FILTER SYSTEM
        // =====================================================
        const STORAGE_KEY = 'loki_filters_' + '{jsonl_filename}'.replace(/[^a-zA-Z0-9]/g, '_');
        let filterList = [];
        let selectedText = '';
        
        // Pre-cached card data for fast filtering
        let cardCache = null;
        let debounceTimer = null;
        const DEBOUNCE_MS = 150;
        
        // Initialize card cache on first use
        function initCardCache() {{
            if (cardCache) return;
            const cards = document.querySelectorAll('.finding-card');
            cardCache = Array.from(cards).map(card => ({{
                element: card,
                level: card.dataset.level,
                text: card.textContent,
                textLower: card.textContent.toLowerCase()
            }}));
        }}
        
        // Load filters from localStorage on page load
        function loadFilters() {{
            try {{
                const stored = localStorage.getItem(STORAGE_KEY);
                if (stored) {{
                    const data = JSON.parse(stored);
                    filterList = data.filters || [];
                }}
            }} catch (e) {{
                console.warn('Failed to load filters:', e);
                filterList = [];
            }}
            initCardCache();
            updateFilterUI();
            applyAllFilters();
        }}
        
        // Save filters to localStorage
        function saveFilters() {{
            try {{
                const data = {{
                    filters: filterList,
                    savedAt: new Date().toISOString()
                }};
                localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
            }} catch (e) {{
                console.warn('Failed to save filters:', e);
            }}
        }}
        
        // =====================================================
        // FILTER UI
        // =====================================================
        function updateFilterUI() {{
            const list = document.getElementById('filterList');
            const count = document.getElementById('filterCount');
            const navFilters = document.getElementById('navFilters');
            const navCount = document.getElementById('navFilterCount');
            
            count.textContent = filterList.length;
            navCount.textContent = filterList.length;
            
            if (filterList.length === 0) {{
                // Panel stays visible, just show empty message
                navFilters.classList.add('hidden');
                list.innerHTML = '<span class="filter-empty">Click the <span class="filter-icon-hint">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>';
            }} else {{
                navFilters.classList.remove('hidden');
                list.innerHTML = filterList.map((f, i) => `
                    <div class="filter-chip">
                        <span class="filter-chip-text" title="${{escapeHtml(f)}}">${{escapeHtml(truncateText(f, 40))}}</span>
                        <button class="filter-chip-remove" onclick="removeFilter(${{i}})" title="Remove filter">×</button>
                    </div>
                `).join('');
            }}
        }}
        
        function toggleFilterPanel() {{
            const panel = document.getElementById('filterPanel');
            panel.classList.toggle('open');
        }}
        
        function scrollToFilterPanel() {{
            const panel = document.getElementById('filterPanel');
            panel.classList.add('open');
            panel.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        }}
        
        function addFilter(text) {{
            if (!text || filterList.includes(text)) return;
            filterList.push(text);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }}
        
        function removeFilter(index) {{
            filterList.splice(index, 1);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }}
        
        function clearAllFilters() {{
            if (filterList.length === 0) return;
            if (!confirm('Clear all ' + filterList.length + ' filters?')) return;
            filterList = [];
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }}
        
        // =====================================================
        // EXPORT / IMPORT
        // =====================================================
        function exportFilters() {{
            if (filterList.length === 0) {{
                alert('No filters to export');
                return;
            }}
            const data = {{
                filters: filterList,
                exportedAt: new Date().toISOString(),
                source: document.title
            }};
            const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'loki-filters-' + new Date().toISOString().slice(0, 10) + '.json';
            a.click();
            URL.revokeObjectURL(url);
        }}
        
        function importFilters(event) {{
            const file = event.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = function(e) {{
                try {{
                    const data = JSON.parse(e.target.result);
                    if (Array.isArray(data.filters)) {{
                        const newFilters = data.filters.filter(f => typeof f === 'string' && !filterList.includes(f));
                        filterList = filterList.concat(newFilters);
                        saveFilters();
                        updateFilterUI();
                        applyAllFilters();
                        alert('Imported ' + newFilters.length + ' new filters');
                    }} else {{
                        alert('Invalid filter file format');
                    }}
                }} catch (err) {{
                    alert('Failed to parse filter file: ' + err.message);
                }}
            }};
            reader.readAsText(file);
            event.target.value = ''; // Reset input
        }}
        
        // =====================================================
        // CONTEXT MENU
        // =====================================================
        const contextMenu = document.getElementById('contextMenu');
        
        document.addEventListener('contextmenu', function(e) {{
            const selection = window.getSelection().toString().trim();
            if (selection) {{
                e.preventDefault();
                selectedText = selection;
                contextMenu.style.left = e.clientX + 'px';
                contextMenu.style.top = e.clientY + 'px';
                contextMenu.classList.add('visible');
            }}
        }});
        
        document.addEventListener('click', function(e) {{
            if (!contextMenu.contains(e.target)) {{
                contextMenu.classList.remove('visible');
            }}
        }});
        
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
                contextMenu.classList.remove('visible');
            }}
        }});
        
        function filterOutSelection() {{
            if (selectedText) {{
                addFilter(selectedText);
                contextMenu.classList.remove('visible');
                window.getSelection().removeAllRanges();
            }}
        }}
        
        function searchOnGoogle() {{
            if (selectedText) {{
                window.open('https://www.google.com/search?q=' + encodeURIComponent(selectedText), '_blank');
                contextMenu.classList.remove('visible');
            }}
        }}
        
        // Inline filter button handler
        function filterValue(text, event) {{
            if (event) {{
                event.stopPropagation();
                event.preventDefault();
            }}
            if (text) {{
                addFilter(text.trim());
            }}
        }}
        
        // =====================================================
        // COMBINED FILTER LOGIC (Performance Optimized)
        // =====================================================
        const searchInput = document.getElementById('searchInput');
        
        // Debounced search input handler
        searchInput.addEventListener('input', () => {{
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(applyAllFilters, DEBOUNCE_MS);
        }});
        
        // Filter by severity level (immediate, no debounce needed)
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                applyAllFilters();
            }});
        }});
        
        function applyAllFilters() {{
            initCardCache();
            
            const query = searchInput.value.toLowerCase();
            const activeFilter = document.querySelector('.filter-btn.active').dataset.filter;
            const hasQuery = query.length > 0;
            const hasExclusions = filterList.length > 0;
            
            // Use requestAnimationFrame for smoother UI updates
            requestAnimationFrame(() => {{
                const len = cardCache.length;
                for (let i = 0; i < len; i++) {{
                    const cached = cardCache[i];
                    
                    // Check level filter
                    if (activeFilter !== 'all' && cached.level !== activeFilter) {{
                        cached.element.classList.add('hidden');
                        continue;
                    }}
                    
                    // Check search filter
                    if (hasQuery && !cached.textLower.includes(query)) {{
                        cached.element.classList.add('hidden');
                        continue;
                    }}
                    
                    // Check exclusion filters (exact match on original text)
                    if (hasExclusions) {{
                        let excluded = false;
                        for (let j = 0; j < filterList.length; j++) {{
                            if (cached.text.includes(filterList[j])) {{
                                excluded = true;
                                break;
                            }}
                        }}
                        if (excluded) {{
                            cached.element.classList.add('hidden');
                            continue;
                        }}
                    }}
                    
                    cached.element.classList.remove('hidden');
                }}
            }});
        }}
        
        // =====================================================
        // UTILITY FUNCTIONS
        // =====================================================
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        function truncateText(text, maxLen) {{
            return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
        }}
        
        // =====================================================
        // EXISTING FUNCTIONALITY
        // =====================================================
        
        // Show more matched strings
        document.querySelectorAll('.show-more-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                const container = btn.parentElement.querySelector('.hidden-strings');
                if (container.classList.contains('visible')) {{
                    container.classList.remove('visible');
                    btn.textContent = btn.dataset.showText;
                }} else {{
                    container.classList.add('visible');
                    btn.textContent = 'Show less';
                }}
            }});
        }});
        
        // Toggle collapsible sections (header)
        function toggleCollapsible(id) {{
            const el = document.getElementById(id);
            if (el) {{
                el.classList.toggle('open');
            }}
        }}
        
        // Toggle raw JSON visibility
        document.querySelectorAll('.raw-json-toggle').forEach(toggle => {{
            toggle.addEventListener('click', () => {{
                toggle.classList.toggle('open');
                const content = toggle.nextElementSibling;
                if (content) {{
                    content.classList.toggle('visible');
                }}
            }});
        }});
        
        // Initialize on page load
        loadFilters();
    </script>
</body>
</html>"##,
        hostname = html_escape(&hostname),
        version = html_escape(version),
        scan_start_time = html_escape(&scan_start_time),
        scan_end_time = html_escape(&scan_end_time),
        os_info = html_escape(&os_info),
        cmd_flags = html_escape(&cmd_flags),
        cpu_info = html_escape(&cpu_info),
        memory_info = html_escape(&memory_info),
        network_info = if network_info.is_empty() { "Not available".to_string() } else { html_escape(&network_info) },
        disk_info_html = if disk_info.is_empty() { 
            "Not available".to_string() 
        } else { 
            disk_info.iter().map(|d| html_escape(d)).collect::<Vec<_>>().join("<br>") 
        },
        alert_threshold = scan_config.alert_threshold,
        warning_threshold = scan_config.warning_threshold,
        notice_threshold = scan_config.notice_threshold,
        max_file_size = format_size(scan_config.max_file_size),
        threads = scan_config.threads,
        cpu_limit = scan_config.cpu_limit,
        yara_rules_count = scan_config.yara_rules_count,
        ioc_count = scan_config.ioc_count,
        total_findings = data.findings.len(),
        alert_count = alert_count,
        warning_count = warning_count,
        notice_count = notice_count,
        jsonl_filename = html_escape(&jsonl_filename),
        findings_html = findings_html,
    )
}

fn render_findings(findings: &[LogEvent]) -> String {
    if findings.is_empty() {
        return r#"<div class="no-findings">
            <h2>✓ No Findings</h2>
            <p>The scan completed without detecting any threats above the configured thresholds.</p>
        </div>"#.to_string();
    }
    
    let mut html = String::new();
    
    for (idx, finding) in findings.iter().enumerate() {
        html.push_str(&render_finding_card(finding, idx));
    }
    
    html
}

fn render_finding_card(finding: &LogEvent, idx: usize) -> String {
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
    
    let finding_type = if finding.file_path.is_some() {
        finding.file_type.as_deref().unwrap_or("File")
    } else {
        "Process"
    };
    
    // Build details section
    let mut details_html = String::new();
    
    if let Some(size) = finding.file_size {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Size:</span> <span class="detail-value">{}</span></div>"#,
            format_size(size as usize)
        ));
    }
    
    // Display file created timestamp
    if let Some(ref created) = finding.file_created {
        let formatted = format_rfc3339_to_datetime(created);
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Created:</span> <span class="detail-value">{}</span></div>"#,
            html_escape(&formatted)
        ));
    }
    
    if let Some(pid) = finding.pid {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">PID:</span> <span class="detail-value">{}</span></div>"#,
            pid
        ));
    }
    
    if let Some(ref mem) = finding.memory_bytes {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Memory:</span> <span class="detail-value">{}</span></div>"#,
            format_size(*mem as usize)
        ));
    }
    
    if let Some(ref md5) = finding.md5 {
        details_html.push_str(&format!(
            r#"<div class="detail-item-hash"><span class="detail-label">MD5:</span> <a href="https://www.virustotal.com/gui/search/{}" target="_blank" class="detail-value hash-link" title="Search on VirusTotal">{}</a><button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></div>"#,
            html_escape(md5), html_escape(md5), html_escape(md5)
        ));
    }
    
    if let Some(ref sha1) = finding.sha1 {
        details_html.push_str(&format!(
            r#"<div class="detail-item-hash"><span class="detail-label">SHA1:</span> <a href="https://www.virustotal.com/gui/search/{}" target="_blank" class="detail-value hash-link" title="Search on VirusTotal">{}</a><button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></div>"#,
            html_escape(sha1), html_escape(sha1), html_escape(sha1)
        ));
    }
    
    if let Some(ref sha256) = finding.sha256 {
        details_html.push_str(&format!(
            r#"<div class="detail-item-hash"><span class="detail-label">SHA256:</span> <a href="https://www.virustotal.com/gui/search/{}" target="_blank" class="detail-value hash-link" title="Search on VirusTotal">{}</a><button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></div>"#,
            html_escape(sha256), html_escape(sha256), html_escape(sha256)
        ));
    }
    
    // Build reasons section (sorted by score descending)
    let reasons_html = if let Some(ref reasons) = finding.reasons {
        // Sort reasons by score descending
        let mut sorted_reasons: Vec<_> = reasons.iter().collect();
        sorted_reasons.sort_by(|a, b| b.score.cmp(&a.score));
        
        let mut reasons_str = String::from(r#"<div class="reasons-section"><h4>Match Reasons</h4>"#);
        
        for reason in sorted_reasons {
            // Extract rule name from message if it's a YARA match (format: "YARA match with rule RULENAME")
            let rule_name = if reason.message.starts_with("YARA match with rule ") || reason.message.starts_with("YARA-X match with rule ") {
                reason.message.split(" rule ").nth(1).map(|s| s.to_string())
            } else {
                None
            };
            
            let filter_btn = if let Some(ref rn) = rule_name {
                let escaped_rule = rn.replace('\'', "\\'");
                format!(r#"<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this rule">✖</button>"#, escaped_rule)
            } else {
                String::new()
            };
            
            reasons_str.push_str(&format!(
                r#"<div class="reason">
                    <div class="reason-message">{}{} <span style="color: var(--text-secondary);">(Score: {})</span></div>
                    <div class="reason-meta">"#,
                html_escape(&reason.message),
                filter_btn,
                reason.score
            ));
            
            if let Some(ref desc) = reason.description {
                reasons_str.push_str(&format!(
                    r#"<span><strong>Description:</strong> {}</span>"#,
                    html_escape(desc)
                ));
            }
            
            if let Some(ref author) = reason.author {
                reasons_str.push_str(&format!(
                    r#"<span><strong>Author:</strong> {}</span>"#,
                    html_escape(author)
                ));
            }
            
            if let Some(ref reference) = reason.reference {
                if !reference.is_empty() {
                    if reference.starts_with("http://") || reference.starts_with("https://") {
                        reasons_str.push_str(&format!(
                            r#"<span><strong>Reference:</strong> <a href="{}" target="_blank" class="reference-link">{}</a></span>"#,
                            html_escape(reference),
                            html_escape(&truncate_string(reference, 60))
                        ));
                    } else {
                        reasons_str.push_str(&format!(
                            r#"<span><strong>Reference:</strong> {}</span>"#,
                            html_escape(reference)
                        ));
                    }
                }
            }
            
            reasons_str.push_str("</div>");
            
            // Matched strings (truncated)
            if let Some(ref strings) = reason.matched_strings {
                if !strings.is_empty() {
                    reasons_str.push_str(r#"<div class="matched-strings"><div class="matched-strings-title">Matched Strings:</div>"#);
                    
                    let visible_count = 5.min(strings.len());
                    for s in strings.iter().take(visible_count) {
                        reasons_str.push_str(&format!(
                            r#"<span class="matched-string">{}</span>"#,
                            html_escape(&truncate_string(s, 100))
                        ));
                    }
                    
                    if strings.len() > visible_count {
                        let hidden_count = strings.len() - visible_count;
                        reasons_str.push_str(&format!(
                            r#"<button class="show-more-btn" data-show-text="Show {} more...">Show {} more...</button>
                            <div class="hidden-strings">"#,
                            hidden_count, hidden_count
                        ));
                        
                        for s in strings.iter().skip(visible_count) {
                            reasons_str.push_str(&format!(
                                r#"<span class="matched-string">{}</span>"#,
                                html_escape(&truncate_string(s, 100))
                            ));
                        }
                        
                        reasons_str.push_str("</div>");
                    }
                    
                    reasons_str.push_str("</div>");
                }
            }
            
            reasons_str.push_str("</div>");
        }
        
        reasons_str.push_str("</div>");
        reasons_str
    } else {
        String::new()
    };
    
    // Raw JSON
    let raw_json = serde_json::to_string_pretty(finding).unwrap_or_default();
    let highlighted_json = syntax_highlight_json(&raw_json);
    
    // Create a JavaScript-safe version of the path for the onclick handler
    let path_js_escaped = path_or_name.replace('\\', "\\\\").replace('\'', "\\'").replace('\n', "\\n");
    
    format!(
        r#"<div class="finding-card" data-level="{level_class}" id="finding-{idx}">
            <div class="finding-header">
                <span class="severity-badge {level_class}">{level}</span>
                <span class="score">{score}</span>
                <span class="finding-path">{path}<button class="filter-btn-inline" onclick="filterValue('{path_js}', event)" title="Filter out this path">✖</button></span>
                <span class="finding-type">{finding_type}</span>
            </div>
            <div class="finding-body">
                <div class="finding-details">
                    {details_html}
                </div>
                {reasons_html}
                <div class="raw-json-collapsible">
                    <div class="raw-json-toggle">
                        <span class="toggle-icon">▶</span>
                        <span>Show Raw Event</span>
                    </div>
                    <div class="raw-json-content">
                        <pre>{highlighted_json}</pre>
                    </div>
                </div>
            </div>
        </div>"#,
        level_class = level_class,
        idx = idx,
        level = level.to_uppercase(),
        score = score,
        path = html_escape(path_or_name),
        path_js = path_js_escaped,
        finding_type = html_escape(finding_type),
        details_html = details_html,
        reasons_html = reasons_html,
        highlighted_json = highlighted_json,
    )
}

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

fn truncate_string(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}

/// Format RFC3339 timestamp string to human-readable datetime (YYYY-MM-DD HH:MM:SS)
fn format_rfc3339_to_datetime(rfc3339: &str) -> String {
    match DateTime::parse_from_rfc3339(rfc3339) {
        Ok(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        Err(_) => rfc3339.to_string(), // Return original if parsing fails
    }
}

fn syntax_highlight_json(json: &str) -> String {
    let mut result = String::with_capacity(json.len() * 2);
    let mut chars = json.chars().peekable();
    let mut in_string = false;
    let mut is_key = false;
    let mut current_token = String::new();
    
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_string {
                    // End of string
                    current_token.push(c);
                    let escaped = html_escape(&current_token);
                    if is_key {
                        result.push_str(&format!(r#"<span class="json-key">{}</span>"#, escaped));
                    } else {
                        result.push_str(&format!(r#"<span class="json-string">{}</span>"#, escaped));
                    }
                    current_token.clear();
                    in_string = false;
                    is_key = false;
                } else {
                    // Start of string - check if it's a key
                    in_string = true;
                    // Look ahead to see if followed by colon
                    is_key = false;
                    current_token.push(c);
                }
            }
            ':' if !in_string => {
                result.push(c);
            }
            c if in_string => {
                current_token.push(c);
            }
            c if c.is_numeric() || c == '-' || c == '.' => {
                let mut num = String::new();
                num.push(c);
                while let Some(&next) = chars.peek() {
                    if next.is_numeric() || next == '.' || next == 'e' || next == 'E' || next == '+' || next == '-' {
                        num.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                result.push_str(&format!(r#"<span class="json-number">{}</span>"#, html_escape(&num)));
            }
            't' | 'f' => {
                let mut word = String::new();
                word.push(c);
                while let Some(&next) = chars.peek() {
                    if next.is_alphabetic() {
                        word.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if word == "true" || word == "false" {
                    result.push_str(&format!(r#"<span class="json-boolean">{}</span>"#, word));
                } else {
                    result.push_str(&word);
                }
            }
            'n' => {
                let mut word = String::new();
                word.push(c);
                while let Some(&next) = chars.peek() {
                    if next.is_alphabetic() {
                        word.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                if word == "null" {
                    result.push_str(&format!(r#"<span class="json-null">{}</span>"#, word));
                } else {
                    result.push_str(&word);
                }
            }
            _ => result.push(c),
        }
    }
    
    // Check if we're looking at a key (simplified: if string is followed by colon)
    result = result.replace(r#"<span class="json-string">"#, r#"<span class="json-key">"#);
    
    // Fix: properly identify keys vs strings
    // Use char_indices for proper UTF-8 handling
    let mut final_result = String::new();
    let mut in_span = false;
    let mut span_content = String::new();
    let mut i = 0;
    let span_open = r#"<span class="json-key">"#;
    let span_close = "</span>";
    
    while i < result.len() {
        // Ensure we're at a valid char boundary
        if !result.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let remaining = &result[i..];
        if remaining.starts_with(span_open) {
            in_span = true;
            span_content.clear();
            i += span_open.len();
        } else if in_span && remaining.starts_with(span_close) {
            in_span = false;
            // Check what follows
            let after_span_start = i + span_close.len();
            if after_span_start <= result.len() && result.is_char_boundary(after_span_start) {
                let after_span = &result[after_span_start..];
                let trimmed = after_span.trim_start();
                if trimmed.starts_with(':') {
                    final_result.push_str(&format!(r#"<span class="json-key">{}</span>"#, span_content));
                } else {
                    final_result.push_str(&format!(r#"<span class="json-string">{}</span>"#, span_content));
                }
            } else {
                final_result.push_str(&format!(r#"<span class="json-string">{}</span>"#, span_content));
            }
            i += span_close.len();
        } else if in_span {
            // Get the character at this position and advance by its byte length
            if let Some(c) = remaining.chars().next() {
                span_content.push(c);
                i += c.len_utf8();
            } else {
                i += 1;
            }
        } else {
            // Get the character at this position and advance by its byte length
            if let Some(c) = remaining.chars().next() {
                final_result.push(c);
                i += c.len_utf8();
            } else {
                i += 1;
            }
        }
    }
    
    final_result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape(r#"say "hello""#), "say &quot;hello&quot;");
    }
    
    #[test]
    fn test_format_size() {
        // Note: format_size uses decimal units (1000-based), not binary (1024-based)
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1000), "1.0 KB");
        assert_eq!(format_size(1500), "1.5 KB");
        assert_eq!(format_size(1_000_000), "1.0 MB");
        assert_eq!(format_size(1_000_000_000), "1.0 GB");
        assert_eq!(format_size(1_500_000_000), "1.5 GB");
    }
    
    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 5), "hello...");
    }
}

