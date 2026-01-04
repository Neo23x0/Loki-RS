# Step 0: Build Sanity and Orientation

## How to Run Loki v1 (Python)

### Prerequisites
- Python 3.x
- Required packages: `yara-python`, `colorama`, `psutil`, `rfc5424-logging-handler`, `netaddr`
- On Windows: `pywin32`
- YARA library installed

### Setup
```bash
# Clone repository (includes signature-base submodule)
git clone --recursive https://github.com/Neo23x0/Loki.git

# Install dependencies
pip install -r requirements.txt

# Update signatures (if needed)
python loki-upgrader.py
```

### Basic Usage
```bash
# Scan default path (C:\ on Windows, / on Linux/Mac)
python loki.py

# Scan specific path
python loki.py -p /path/to/scan

# With debug output
python loki.py --debug

# Skip process scan
python loki.py --noprocscan

# Skip file scan
python loki.py --nofilescan

# Intense scan mode
python loki.py --intense

# Show help
python loki.py --help
```

### Entry Point
- Main file: `loki.py`
- CLI parsing: `argparse` in `main()` function (lines 1456-1528)
- Core class: `Loki` class (line 97)
- Logger: `LokiLogger` from `lib/lokilogger.py`

## How to Run Loki2 (Rust)

### Prerequisites
- Rust toolchain (cargo, rustc)
- YARA library (system dependency)

### Setup
```bash
cd Loki2

# Link signature-base (if available)
# git clone https://github.com/Neo23x0/signature-base ../signature-base/
# ln -s ../signature-base/ ./signatures

# Build
cargo build

# Build release
cargo build --release
```

### Basic Usage
```bash
# Run with default settings
./target/debug/loki

# Scan specific folder
./target/debug/loki --folder /path/to/scan

# Show help
./target/debug/loki --help

# Debug output
./target/debug/loki --debug

# Trace output
./target/debug/loki --trace

# Skip process scan
./target/debug/loki --noprocs

# Skip file system scan
./target/debug/loki --nofs
```

### Entry Point
- Main file: `src/main.rs`
- CLI parsing: `rustop::opts!` macro (lines 319-330)
- Core modules:
  - `modules/filesystem_scan.rs` - File scanning
  - `modules/process_check.rs` - Process scanning
  - `helpers/helpers.rs` - System info and utilities

## Build Status

### Loki2 Compilation
- ✅ **Status**: Builds successfully
- ⚠️ **Warnings**: 5 warnings (mostly unused variables, deprecated chrono methods)
- ✅ **Dependencies**: All resolved

### Known Issues Fixed
1. ✅ sysinfo 0.37 API changes - Updated to use new API
2. ✅ OsStr display issues - Converted to strings for logging
3. ✅ Chrono timestamp deprecation - Updated to `timestamp_opt().single()`
4. ✅ Unused variables - Prefixed with underscore or removed

### Remaining Warnings
- Unused variable `_proc_cmd` in process_check.rs (intentional)
- Deprecated `chrono::TimeZone::timestamp` - should migrate to `timestamp_opt()` (partially done)
- Unused imports (Cpu, Disk) - can be cleaned up

## Test Status

### Existing Tests
- ❌ No test files found in Loki2
- ⚠️ No test infrastructure detected

### Runtime Testing
- ⚠️ Not yet tested on real signature-base
- ⚠️ No integration tests

## Next Steps
1. Run clippy for code quality
2. Run fmt for code formatting
3. Test basic functionality with sample signatures
4. Begin feature inventory (Step 1)


