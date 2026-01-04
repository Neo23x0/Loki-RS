# Loki-RS
LOKI - Simple IOC and YARA Scanner

## Status

Work in Progress. This version is not ready for use. There's still some work to do for a first release. 

### What's already implemented

- System reconnaissance (system and hardware information for the log)
- Logging and formatting of the different log outputs
- File system walk
- File time evaluation (MAC timestamps)
- Exclusions based on file characteristics
- IOC initialization - hash values
- IOC matching on files (hashes)
- YARA rule initialization, syntax checks, and error handling
- YARA scanning of files
- YARA scanning of process memory 

### What's still to do

- IOC initialization - file patterns
- IOC initialization - C2 patterns (FQDN, IP)
- IOC matching on files (file patterns)
- C2 IOC matching (process connections)
- File system walk exceptions: network drivers, mounted drives etc.
- Custom exclusions (regex on file path)
- Release workflows (automatically build and provide as release)

# Setup Build Environment

## Requirements

See the files in the folder .github/workflows for steps to setup a build environment for 

- Linux
- macOS

## Providing Signatures 

```bash
git clone https://github.com/Neo23x0/signature-base ../signature-base/
ln -s ../signature-base/ ./signatures
```

## Build

```bash
cargo build
```

## Test Run

```bash
cargo build && ./target/debug/loki --help
```

## Usage

```
Usage: loki [OPTIONS]

LOKI YARA and IOC Scanner

Options:
  -m, --max-file-size         Maximum file size to scan (default: 10000000)
  -s, --show-access-errors    Show all file and process access errors
  -c, --scan-all-files        Scan all files regardless of their file type / extension
  -d, --debug                 Show debugging information
  -t, --trace                 Show very verbose trace output
  -n, --noprocs               Don't scan processes
  -o, --nofs                  Don't scan the file system
  -f, --folder                Folder to scan
  -h, --help                  Show this help message.
```

# Screenshots

LOKI 2 alpha version

![Screenhot of Alpha Version](/screens/screen-alpha.png)
