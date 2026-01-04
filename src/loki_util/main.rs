use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

const SIGNATURE_BASE_URL: &str = "https://github.com/Neo23x0/signature-base/archive/master.tar.gz";
const YARA_FORGE_URL: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
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
            println!("[+] Upgrading LOKI2...");
            if let Err(e) = upgrade_loki() {
                eprintln!("[!] Error upgrading LOKI2: {}", e);
                std::process::exit(1);
            }
            println!("[✓] LOKI2 upgraded successfully!");
        }
        _ => {
            eprintln!("[!] Unknown command: {}", command);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("LOKI2 Utility Tool");
    println!();
    println!("Usage: loki-util <command>");
    println!();
    println!("Commands:");
    println!("  update   - Update signatures (IOCs and YARA rules)");
    println!("  upgrade  - Update LOKI2 program and signatures");
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

fn download_and_extract_iocs() -> Result<(), Box<dyn std::error::Error>> {
    let tar_path = format!("{}/signature-base.tar.gz", TEMP_DIR);
    
    // Download using wget or curl
    if Command::new("wget")
        .args(&["-q", SIGNATURE_BASE_URL, "-O", &tar_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        // Try curl
        let status = Command::new("curl")
            .args(&["-sL", SIGNATURE_BASE_URL, "-o", &tar_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        
        if !status.success() {
            return Err("Failed to download signature-base. Please ensure wget or curl is installed.".into());
        }
    }
    
    // Extract tar.gz
    let extract_dir = format!("{}/signature-base", TEMP_DIR);
    fs::create_dir_all(&extract_dir)?;
    
    let status = Command::new("tar")
        .args(&["-xzf", &tar_path, "-C", &extract_dir, "--strip-components=1"])
        .status()?;
    
    if !status.success() {
        return Err("Failed to extract signature-base archive".into());
    }
    
    // Copy IOCs
    let iocs_source = format!("{}/iocs", extract_dir);
    if Path::new(&iocs_source).exists() {
        copy_directory(&iocs_source, &format!("{}/iocs", SIGNATURES_DIR))?;
        println!("[+] IOCs updated from signature-base");
    }
    
    Ok(())
}

fn download_and_extract_yara_rules() -> Result<(), Box<dyn std::error::Error>> {
    let zip_path = format!("{}/yara-forge-rules-core.zip", TEMP_DIR);
    
    // Download using wget or curl
    if Command::new("wget")
        .args(&["-q", YARA_FORGE_URL, "-O", &zip_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        // Try curl
        let status = Command::new("curl")
            .args(&["-sL", YARA_FORGE_URL, "-o", &zip_path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        
        if !status.success() {
            return Err("Failed to download yara-forge rules. Please ensure wget or curl is installed.".into());
        }
    }
    
    // Extract ZIP file
    let extract_dir = format!("{}/yara-forge", TEMP_DIR);
    fs::create_dir_all(&extract_dir)?;
    
    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    
    let yara_dest = format!("{}/yara", SIGNATURES_DIR);
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
        let dest_path = Path::new(&yara_dest).join(filename);
        
        // Extract file directly to signatures/yara
        let mut outfile = fs::File::create(&dest_path)?;
        io::copy(&mut file, &mut outfile)?;
    }
    
    println!("[+] YARA rules updated from yara-forge");
    
    Ok(())
}

fn copy_directory(src: &str, dst: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().unwrap();
        let dest_path = Path::new(dst).join(file_name);
        
        if path.is_dir() {
            copy_directory(path.to_str().unwrap(), dest_path.to_str().unwrap())?;
        } else {
            fs::copy(&path, &dest_path)?;
        }
    }
    
    Ok(())
}

fn upgrade_loki() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in a git repository
    let git_status = Command::new("git")
        .args(&["rev-parse", "--git-dir"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    
    if git_status.is_ok() && git_status.unwrap().success() {
        println!("[+] Updating LOKI2 from git repository...");
        
        // Fetch latest changes
        let status = Command::new("git")
            .args(&["fetch", "origin"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to fetch from git repository".into());
        }
        
        // Pull latest changes
        let status = Command::new("git")
            .args(&["pull", "origin", "master"])
            .status()?;
        
        if !status.success() {
            // Try main branch
            let status = Command::new("git")
                .args(&["pull", "origin", "main"])
                .status()?;
            
            if !status.success() {
                return Err("Failed to pull from git repository".into());
            }
        }
        
        println!("[+] LOKI2 code updated from git");
        
        // Rebuild
        println!("[+] Rebuilding LOKI2...");
        let status = Command::new("cargo")
            .args(&["build", "--release"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to rebuild LOKI2".into());
        }
        
        println!("[+] LOKI2 rebuilt successfully");
    } else {
        println!("[!] Not in a git repository. Skipping code update.");
        println!("[!] Please update LOKI2 manually if needed.");
    }
    
    // Update signatures
    update_signatures()?;
    
    Ok(())
}

