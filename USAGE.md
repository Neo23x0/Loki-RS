# Loki-RS Usage Guide

Loki-RS is a high-performance, multi-threaded YARA & IOC scanner written in Rust.

## Quick Start

1. **Build the project:**
   ```bash
   make build
   ```

2. **Create a complete package:**
   ```bash
   make package
   ```
   This creates a `build/` directory with:
   - The binary (`loki`)
   - Signatures directory (`signatures/`)
   - Configuration files (`config/`)
   - This usage guide

3. **Run Loki-RS:**
   ```bash
   ./build/loki --help
   ```

## Command Line Options

```
Usage: loki [OPTIONS]

Loki-RS - High-Performance, Multi-threaded YARA & IOC Scanner

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

## Basic Usage Examples

### Scan the entire file system:
```bash
./build/loki
```

### Scan a specific directory:
```bash
./build/loki -f /path/to/scan
```

### Scan with debug output:
```bash
./build/loki -d -f /path/to/scan
```

### Scan only files (skip process scanning):
```bash
./build/loki -n -f /path/to/scan
```

### Scan only processes (skip file system):
```bash
./build/loki -o
```

### Scan all file types (not just executables):
```bash
./build/loki -c -f /path/to/scan
```

## Signatures

Loki-RS uses YARA rules and IOC files for detection. Signatures are located in the `signatures/` directory:

- **YARA rules**: Place `.yar` files in `signatures/yara/`
- **Hash IOCs**: Place hash IOC files in `signatures/iocs/` (files containing "hash" in the name)
- **Filename IOCs**: Place filename IOC files in `signatures/iocs/` (files containing "filename" in the name)
- **C2 IOCs**: Place C2 IOC files in `signatures/iocs/` (files containing "c2" in the name)

### Setting up Signatures

The easiest way to set up signatures is using the included `loki-util` tool:

```bash
./loki-util update
```

This downloads:
- **YARA rules** from [YARA Forge](https://yaraforge.com/) (Core rule set)
- **IOCs** from [signature-base](https://github.com/Neo23x0/signature-base)

Alternatively, you can manually download:

1. **YARA rules** - Download from [YARA Forge releases](https://github.com/YARAHQ/yara-forge/releases):
   ```bash
   wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
   unzip yara-forge-rules-core.zip -d ./signatures/yara/
   ```

2. **IOCs** - Download from signature-base:
   ```bash
   wget https://github.com/Neo23x0/signature-base/archive/master.tar.gz
   tar -xzf master.tar.gz
   cp -r signature-base-master/iocs ./signatures/
   ```

## Configuration

### Exclusions

You can configure file path exclusions using regex patterns in `config/excludes.cfg`. Each line represents a regular expression that gets applied to the full file path during the directory walk.

Example `config/excludes.cfg`:
```
# Excluded directories
^/proc/.*
^/dev/.*
^/sys/.*
# Exclude specific file patterns
.*\.log$
.*/tmp/.*
```

## Output Levels

Loki-RS uses a scoring system to determine the severity of matches:

- **ALERT**: High severity matches (default threshold: 75)
- **WARNING**: Medium severity matches (default threshold: 50)
- **NOTICE**: Low severity matches (default threshold: 25)

Matches are scored based on YARA rule metadata and IOC scores, with weighted scoring for multiple matches.

## Logging

Loki-RS supports multiple log levels:

- **Default**: Shows ALERT, WARNING, and NOTICE messages
- **Debug** (`-d`): Shows additional debugging information
- **Trace** (`-t`): Shows very verbose trace output including all scanned files

## Troubleshooting

### "Cannot read YARA rules directory"
- Ensure the `signatures/yara/` directory exists
- Check that you have read permissions
- Verify that at least one `.yar` file is present

### "Cannot access file" errors
- Use `-s` flag to show all access errors
- Check file permissions
- Some system files may require elevated privileges

### Process scanning fails
- Process memory scanning requires appropriate permissions
- Some processes may be protected
- Use `-n` to skip process scanning if needed

## Building from Source

See `README.md` for detailed build instructions and requirements.

## License

See `LICENSE` file for license information.


