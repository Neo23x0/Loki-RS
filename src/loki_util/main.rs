mod html_report;

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use serde_json::Value;
use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};
use glob::glob;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SIGNATURE_BASE_URL: &str = "https://github.com/Neo23x0/signature-base/archive/master.tar.gz";
const YARA_FORGE_URL: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
const LOKI_RELEASES_URL: &str = "https://api.github.com/repos/Neo23x0/Loki-RS/releases";
const SIGNATURES_DIR: &str = "./signatures";
const TEMP_DIR: &str = "./tmp";

// Enable ANSI escape code support on Windows
#[cfg(windows)]
fn enable_ansi_support() {
    use windows::Win32::System::Console::{
        GetStdHandle, SetConsoleMode, GetConsoleMode,
        STD_OUTPUT_HANDLE, STD_ERROR_HANDLE, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };
    
    unsafe {
        // Enable for stdout
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        // Enable for stderr
        if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
fn enable_ansi_support() {
    // ANSI codes work natively on Unix-like systems
}

fn main() {
    // Enable ANSI color support on Windows
    enable_ansi_support();
    
    print_banner();
    
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        // Check if running in a TTY (interactive terminal)
        // If not, print usage instead of trying interactive mode
        if atty::is(atty::Stream::Stdin) {
            if let Err(e) = interactive_mode() {
                log_error(&format!("Interactive mode error: {}", e));
                std::process::exit(1);
            }
        } else {
            // Not running in a TTY (e.g., CI/CD, pipes, etc.)
            // Print usage information instead
            print_usage();
        }
        return;
    }

    let command = &args[1];
    match command.as_str() {
        "update" => {
            log_step("Starting signature update...");
            if let Err(e) = update_signatures() {
                log_error(&format!("Error updating signatures: {}", e));
                std::process::exit(1);
            }
            log_success("Signatures updated successfully!");
        }
        "upgrade" => {
            log_step("Starting Loki-RS upgrade...");
            if let Err(e) = upgrade_loki() {
                log_error(&format!("Error upgrading Loki-RS: {}", e));
                std::process::exit(1);
            }
            log_success("Loki-RS upgraded successfully!");
        }
        "html" => {
            if let Err(e) = handle_html_command(&args[2..]) {
                log_error(&format!("Error generating HTML report: {}", e));
                std::process::exit(1);
            }
        }
        "--help" | "-h" => {
            print_usage();
        }
        _ => {
            log_error(&format!("Unknown command: {}", command));
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_banner() {
    println!("{}", "------------------------------------------------------------------------".bright_green());
    println!("{}", "   ::             x.                                                    ".bright_green());
    println!("{}", "   ;.             xX    ______ _____________ _________                  ".bright_green());
    println!("{}", "   .x            :$x    ___  / __  __ \\__  //_/___  _/                  ".bright_green());
    println!("{}", "    ++           Xx     __  /  _  / / /_  ,<   __  /                    ".bright_green());
    println!("{}", "    .X:  ..;.   ;+.     _  /___/ /_/ /_  /| | __/ /                     ".bright_green());
    println!("{}", "     :xx +XXX;+::.      /_____/\\____/ /_/ |_| /___/                     ".bright_green());
    println!("{}", "       :xx+$;.:.        High-Performance YARA & IOC Scanner             ".bright_green());
    println!("{}", "          .X+:;;                                                        ".bright_green());
    println!("           ;  :.        Version {} (Rust)                               ", VERSION);
    println!("{}", "        .    x+         Florian Roth 2026                               ".bright_green());
    println!("{}", "         :   +                                                          ".bright_green());
    println!("{}", "------------------------------------------------------------------------".bright_green());
    println!();
}

fn print_usage() {
    println!("Usage: loki-util <command>");
    println!();
    println!("Commands:");
    println!("  {}   - Update signatures (IOCs and YARA rules)", "update".green());
    println!("  {}  - Update Loki-RS program and signatures", "upgrade".green());
    println!("  {}    - Generate HTML report from JSONL file(s)", "html".green());
    println!();
    println!("HTML Report Generation:");
    println!("  loki-util html --input <file.jsonl> --output <report.html>");
    println!("  loki-util html --input \"*.jsonl\" --combine --output combined.html");
    println!();
    println!("Options:");
    println!("  --input <file|glob>  - Input JSONL file or glob pattern");
    println!("  --output <file.html> - Output HTML file (optional, defaults to input.html)");
    println!("  --combine            - Combine multiple JSONL files into one report");
    println!("  --title <str>       - Override report title");
    println!("  --host <str>         - Override hostname");
    println!();
}

fn log_info(msg: &str) {
    println!(" {} {}", "[*]".blue(), msg);
}

fn log_success(msg: &str) {
    println!(" {} {}", "[+]".green(), msg);
}

fn log_error(msg: &str) {
    eprintln!(" {} {}", "[!]".red(), msg);
}

fn log_warn(msg: &str) {
    println!(" {} {}", "[!]".yellow(), msg);
}

fn log_step(msg: &str) {
    println!(" {} {}", "[>]".cyan(), msg);
}

fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    let options = vec![
        "Update signatures",
        "Upgrade Loki-RS",
        "Exit"
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to do?")
        .default(0)
        .items(&options)
        .interact()?;

    match selection {
        0 => {
            log_step("Starting signature update...");
            update_signatures()?;
            log_success("Signatures updated successfully!");
        }
        1 => {
            log_step("Starting Loki-RS upgrade...");
            upgrade_loki()?;
            log_success("Loki-RS upgraded successfully!");
        }
        _ => {
            println!("Exiting...");
        }
    }
    
    Ok(())
}

fn update_signatures() -> Result<(), Box<dyn std::error::Error>> {
    // Create signatures directory if it doesn't exist
    fs::create_dir_all(format!("{}/iocs", SIGNATURES_DIR))?;
    fs::create_dir_all(format!("{}/yara", SIGNATURES_DIR))?;
    
    // Create temp directory
    fs::create_dir_all(TEMP_DIR)?;
    
    // Download and extract IOCs from signature-base
    log_info("Downloading IOCs from signature-base...");
    download_and_extract_iocs()?;
    
    // Download and extract YARA rules from yara-forge
    log_info("Downloading YARA rules from yara-forge...");
    download_and_extract_yara_rules()?;
    
    // Clean up temp directory
    fs::remove_dir_all(TEMP_DIR)?;
    
    Ok(())
}

fn download_file(url: &str, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resp = ureq::get(url)
        .set("User-Agent", "loki-util")
        .call()?;
    
    let mut reader = resp.into_reader();
    let mut file = fs::File::create(output_path)?;
    io::copy(&mut reader, &mut file)?;
    
    Ok(())
}

fn fetch_url_content(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let body = ureq::get(url)
        .set("User-Agent", "loki-util")
        .call()?
        .into_string()?;
    Ok(body)
}

fn download_and_extract_iocs() -> Result<(), Box<dyn std::error::Error>> {
    let tar_path = Path::new(TEMP_DIR).join("signature-base.tar.gz");
    download_file(SIGNATURE_BASE_URL, &tar_path)?;
    
    // Extract tar.gz
    let extract_dir = Path::new(TEMP_DIR).join("signature-base");
    fs::create_dir_all(&extract_dir)?;
    
    let status = Command::new("tar")
        .args(&["-xzf", tar_path.to_str().unwrap(), "-C", extract_dir.to_str().unwrap(), "--strip-components=1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    
    if !status.success() {
        return Err("Failed to extract signature-base archive".into());
    }
    
    // Copy IOCs
    let iocs_source = extract_dir.join("iocs");
    if iocs_source.exists() {
        copy_directory(&iocs_source, Path::new(SIGNATURES_DIR).join("iocs").as_path())?;
        log_success("IOCs updated from signature-base");
    }
    
    Ok(())
}

fn download_and_extract_yara_rules() -> Result<(), Box<dyn std::error::Error>> {
    let zip_path = Path::new(TEMP_DIR).join("yara-forge-rules-core.zip");
    download_file(YARA_FORGE_URL, &zip_path)?;
    
    // Extract ZIP file
    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    
    let yara_dest = Path::new(SIGNATURES_DIR).join("yara");
    fs::create_dir_all(&yara_dest)?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        
        // Skip directories
        if file.name().ends_with('/') {
            continue;
        }
        
        // Only extract .yar files
        if !file.name().ends_with(".yar") {
            continue;
        }
        
        // Get the filename from the path
        let file_path = Path::new(file.name());
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?;
        
        // Create destination path
        let dest_path = yara_dest.join(filename);
        
        // Extract file directly to signatures/yara
        let mut outfile = fs::File::create(&dest_path)?;
        io::copy(&mut file, &mut outfile)?;
    }
    
    log_success("YARA rules updated from yara-forge");
    
    Ok(())
}

fn copy_directory(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().unwrap();
        let dest_path = dst.join(file_name);
        
        if path.is_dir() {
            copy_directory(&path, &dest_path)?;
        } else {
            fs::copy(&path, &dest_path)?;
        }
    }
    
    Ok(())
}

fn get_platform_string() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    
    // Match the naming convention used in releases
    // e.g. loki-windows-x86_64.zip, loki-linux-x86_64.tar.gz
    
    let os_str = match os {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        _ => return "unknown".to_string(),
    };
    
    let arch_str = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64", // macOS M1/M2
        _ => return "unknown".to_string(),
    };
    
    format!("loki-{}-{}", os_str, arch_str)
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest_dir.join(file.mangled_name());

        if (&*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(tar_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("tar")
        .args(&["-xzf", tar_path.to_str().unwrap(), "-C", dest_dir.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    
    if !status.success() {
        return Err("Failed to extract tar.gz archive".into());
    }
    Ok(())
}

fn install_updates(source_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Find executables in source_dir (could be nested in a folder)
    let mut root_dir = source_dir.to_path_buf();
    
    // Check if there is a single directory inside
    let entries: Vec<_> = fs::read_dir(source_dir)?.collect::<Result<_, _>>()?;
    if entries.len() == 1 && entries[0].path().is_dir() {
        root_dir = entries[0].path();
    }
    
    let current_exe = std::env::current_exe()?;
    let current_dir = current_exe.parent().ok_or("Cannot get current directory")?;
    
    // Files to update
    let targets = if cfg!(windows) {
        vec!["loki.exe", "loki-util.exe"]
    } else {
        vec!["loki", "loki-util"]
    };
    
    for target in targets {
        let src = root_dir.join(target);
        if src.exists() {
            let dst = current_dir.join(target);
            
            // On Windows, we can't overwrite running executable. Rename it first.
            if dst.exists() {
                let backup = current_dir.join(format!("{}.old", target));
                // Remove old backup if exists
                if backup.exists() {
                    let _ = fs::remove_file(&backup);
                }
                
                // Rename current to backup
                match fs::rename(&dst, &backup) {
                    Ok(_) => log_info(&format!("Backup created: {}", backup.display())),
                    Err(e) => log_warn(&format!("Failed to rename {} to backup: {} (might be acceptable if we can overwrite)", target, e)),
                }
            }
            
            // Copy new file
            fs::copy(&src, &dst)?;
            log_success(&format!("Updated: {}", target));
            
            // Set executable permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&dst)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&dst, perms)?;
            }
        }
    }
    
    Ok(())
}

fn upgrade_loki_binary() -> Result<(), Box<dyn std::error::Error>> {
    let platform = get_platform_string();
    if platform == "unknown" {
        return Err("Could not determine platform (OS/Arch) for automatic update.".into());
    }
    
    log_info(&format!("Detected platform: {}", platform));
    
    // 1. Get latest release info
    log_info("Checking for updates from GitHub...");
    let json_content = fetch_latest_release_info()?;
    let releases: Value = serde_json::from_str(&json_content)?;
    
    // Get the first release from the list (latest)
    let latest_release = if releases.is_array() {
        releases.get(0).ok_or("No releases found")?
    } else if releases.is_object() && releases.get("tag_name").is_some() {
        &releases
    } else {
        return Err("Invalid response from GitHub API".into());
    };
    
    let tag_name = latest_release["tag_name"].as_str().ok_or("No tag_name in release info")?;
    log_info(&format!("Latest version available: {}", tag_name));
    
    // 2. Find matching asset
    let assets = latest_release["assets"].as_array().ok_or("No assets in release info")?;
    let mut download_url = None;
    let mut asset_name = "";
    
    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("");
        if name.contains(&platform) && (name.ends_with(".zip") || name.ends_with(".tar.gz")) {
            download_url = asset["browser_download_url"].as_str();
            asset_name = name;
            break;
        }
    }
    
    let download_url = download_url.ok_or(format!("No matching release found for platform: {}", platform))?;
    log_info(&format!("Found matching release: {}", asset_name));
    
    // Create temp directory
    fs::create_dir_all(TEMP_DIR)?;

    // 3. Download
    let archive_path = Path::new(TEMP_DIR).join(asset_name);
    log_info("Downloading release...");
    download_file(download_url, &archive_path)?;
    
    // 4. Extract
    log_info("Extracting update...");
    let extract_dir = Path::new(TEMP_DIR).join("update_extracted");
    fs::create_dir_all(&extract_dir)?;
    
    if asset_name.ends_with(".zip") {
        extract_zip(&archive_path, &extract_dir)?;
    } else { // tar.gz
        extract_tar_gz(&archive_path, &extract_dir)?;
    }
    
    // 5. Replace files
    install_updates(&extract_dir)?;
    
    // Clean up
    let _ = fs::remove_file(&archive_path);
    let _ = fs::remove_dir_all(&extract_dir);
    
    Ok(())
}

fn fetch_latest_release_info() -> Result<String, Box<dyn std::error::Error>> {
    fetch_url_content(LOKI_RELEASES_URL)
}

fn upgrade_loki() -> Result<(), Box<dyn std::error::Error>> {
    log_info("Upgrading Loki-RS via GitHub Releases...");

    // Attempt binary upgrade
    if let Err(e) = upgrade_loki_binary() {
         log_error(&format!("Automatic binary upgrade failed: {}", e));
         log_error("Please update Loki-RS manually.");
         return Err(e);
    }
    
    // Update signatures
    update_signatures()?;
    
    Ok(())
}

fn handle_html_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut combine = false;
    let mut title: Option<String> = None;
    let mut host: Option<String> = None;
    
    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                if i + 1 < args.len() {
                    input = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--input requires a value".into());
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--output requires a value".into());
                }
            }
            "--combine" | "-c" => {
                combine = true;
                i += 1;
            }
            "--title" | "-t" => {
                if i + 1 < args.len() {
                    title = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--title requires a value".into());
                }
            }
            "--host" | "-h" => {
                if i + 1 < args.len() {
                    host = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--host requires a value".into());
                }
            }
            "--help" => {
                print_usage();
                return Ok(());
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
    }
    
    let input_path = input.ok_or("--input is required")?;
    
    // Expand glob pattern if needed
    let input_files = expand_inputs(&input_path)?;
    
    if input_files.is_empty() {
        return Err(format!("No files found matching: {}", input_path).into());
    }
    
    log_step(&format!("Found {} JSONL file(s) to process", input_files.len()));
    
    if combine || input_files.len() > 1 {
        // Combined report mode
        log_step("Generating combined HTML report...");
        let combined_data = html_report::parse_multiple_jsonl_files(&input_files)?;
        
        let output_path = output.unwrap_or_else(|| "combined_report.html".to_string());
        let version = combined_data.sources.first()
            .and_then(|s| s.version.as_ref())
            .map(|v| v.clone())
            .unwrap_or_else(|| VERSION.to_string());
        
        html_report::render_combined_html(&combined_data, &version, &output_path)?;
        log_success(&format!("Combined HTML report written to: {}", output_path));
    } else {
        // Single file mode
        log_step("Generating HTML report...");
        let output_path = html_report::generate_single_report(
            &input_files[0],
            output.as_deref(),
            title.as_deref(),
            host.as_deref(),
        )?;
        log_success(&format!("HTML report written to: {}", output_path));
    }
    
    Ok(())
}

fn expand_inputs(pattern: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    
    // Check if pattern contains glob characters
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        // Use glob pattern matching
        let matches = glob(pattern)?;
        for entry in matches {
            match entry {
                Ok(path) => {
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                        files.push(path.to_string_lossy().to_string());
                    }
                }
                Err(e) => {
                    log_warn(&format!("Error matching glob pattern: {}", e));
                }
            }
        }
    } else {
        // Single file path
        let path = Path::new(pattern);
        if !path.exists() {
            return Err(format!("File not found: {}", pattern).into());
        }
        if !path.is_file() {
            return Err(format!("Path is not a file: {}", pattern).into());
        }
        files.push(pattern.to_string());
    }
    
    // Sort for consistent ordering
    files.sort();
    
    Ok(files)
}
