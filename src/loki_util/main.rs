use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use serde_json::Value;

const SIGNATURE_BASE_URL: &str = "https://github.com/Neo23x0/signature-base/archive/master.tar.gz";
const YARA_FORGE_URL: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
const LOKI_RELEASES_URL: &str = "https://api.github.com/repos/Neo23x0/Loki-RS/releases";
const SIGNATURES_DIR: &str = "./signatures";
const TEMP_DIR: &str = "./tmp";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let command = &args[1];
    match command.as_str() {
        "update" => {
            println!("[+] Updating signatures...");
            if let Err(e) = update_signatures() {
                eprintln!("[!] Error updating signatures: {}", e);
                std::process::exit(1);
            }
            println!("[✓] Signatures updated successfully!");
        }
        "upgrade" => {
            println!("[+] Upgrading Loki-RS...");
            if let Err(e) = upgrade_loki() {
                eprintln!("[!] Error upgrading Loki-RS: {}", e);
                std::process::exit(1);
            }
            println!("[✓] Loki-RS upgraded successfully!");
        }
        _ => {
            eprintln!("[!] Unknown command: {}", command);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("Loki-RS Utility Tool");
    println!();
    println!("Usage: loki-util <command>");
    println!();
    println!("Commands:");
    println!("  update   - Update signatures (IOCs and YARA rules)");
    println!("  upgrade  - Update Loki-RS program and signatures");
    println!();
}

fn update_signatures() -> Result<(), Box<dyn std::error::Error>> {
    // Create signatures directory if it doesn't exist
    fs::create_dir_all(format!("{}/iocs", SIGNATURES_DIR))?;
    fs::create_dir_all(format!("{}/yara", SIGNATURES_DIR))?;
    
    // Create temp directory
    fs::create_dir_all(TEMP_DIR)?;
    
    // Download and extract IOCs from signature-base
    println!("[+] Downloading IOCs from signature-base...");
    download_and_extract_iocs()?;
    
    // Download and extract YARA rules from yara-forge
    println!("[+] Downloading YARA rules from yara-forge...");
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
        println!("[+] IOCs updated from signature-base");
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
    
    println!("[+] YARA rules updated from yara-forge");
    
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
                    Ok(_) => println!("[+] Backup created: {}", backup.display()),
                    Err(e) => println!("[!] Failed to rename {} to backup: {} (might be acceptable if we can overwrite)", target, e),
                }
            }
            
            // Copy new file
            fs::copy(&src, &dst)?;
            println!("[+] Updated: {}", target);
            
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
    
    println!("[+] Detected platform: {}", platform);
    
    // 1. Get latest release info
    println!("[+] Checking for updates from GitHub...");
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
    println!("[+] Latest version available: {}", tag_name);
    
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
    println!("[+] Found matching release: {}", asset_name);
    
    // Create temp directory
    fs::create_dir_all(TEMP_DIR)?;

    // 3. Download
    let archive_path = Path::new(TEMP_DIR).join(asset_name);
    println!("[+] Downloading release...");
    download_file(download_url, &archive_path)?;
    
    // 4. Extract
    println!("[+] Extracting update...");
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
    println!("[+] Upgrading Loki-RS via GitHub Releases...");

    // Attempt binary upgrade
    if let Err(e) = upgrade_loki_binary() {
         eprintln!("[!] Automatic binary upgrade failed: {}", e);
         eprintln!("[!] Please update Loki-RS manually.");
         return Err(e);
    }
    
    // Update signatures
    update_signatures()?;
    
    Ok(())
}

