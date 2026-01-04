# Loki-RS Current State Audit

This document provides a comprehensive audit of Loki-RS's current implementation status, identifying what's implemented, partial, broken, or missing compared to Loki v1.

**Last Updated**: Based on code analysis of Loki-RS repository
**Loki-RS Version**: 2.0.1-alpha

---

## Table of Contents

1. [CLI Interface](#cli-interface)
2. [Scan Targets](#scan-targets)
3. [IOC/Signature Support](#iocsignature-support)
4. [Matching Logic](#matching-logic)
5. [Output and Reporting](#output-and-reporting)
6. [Performance and Threading](#performance-and-threading)
7. [Logging](#logging)
8. [Update Mechanisms](#update-mechanisms)
9. [Platform Specifics](#platform-specifics)
10. [Quality of Life Features](#quality-of-life-features)
11. [Exit Codes](#exit-codes)
12. [Error Handling](#error-handling)

---

## CLI Interface

### Status: **Partial**

#### Implemented Flags

| Flag | Status | Notes |
|------|--------|-------|
| `--max-file-size` (`-m`) | ✅ Implemented | Default: 10,000,000 bytes (vs v1: 5,000 KB) |
| `--show-access-errors` (`-s`) | ✅ Implemented | Maps to `show_access_errors` in ScanConfig |
| `--scan-all-files` (`-c`) | ✅ Implemented | Maps to `scan_all_types` in ScanConfig |
| `--scan-all-drives` | ✅ Implemented | Flag exists but limited implementation |
| `--debug` (`-d`) | ✅ Implemented | Sets log level to debug |
| `--trace` (`-t`) | ✅ Implemented | Sets log level to trace |
| `--noprocs` (`-n`) | ✅ Implemented | Skips process scanning |
| `--nofs` (`-o`) | ✅ Implemented | Skips file system scanning |
| `--folder` (`-f`) | ✅ Implemented | Path to scan (positional) |
| `--help` (`-h`) | ✅ Implemented | Standard rustop help |

#### Missing Flags (from Loki v1)

| Flag | Status | Impact |
|------|--------|--------|
| `-p`, `--path` | ❌ Missing | Uses `--folder` instead (different name) |
| `-s` (file size in KB) | ❌ Missing | Uses `--max-file-size` in bytes instead |
| `-l`, `--log-file` | ❌ Missing | No custom log file path |
| `--logfolder` | ❌ Missing | No log folder option |
| `--nolog` | ❌ Missing | Always writes log file |
| `-r`, `--remote-loghost` | ❌ Missing | No syslog support |
| `-t`, `--remote-syslog-port` | ❌ Missing | No syslog support |
| `--syslogtcp` | ❌ Missing | No syslog support |
| `-a`, `--alert-level` | ❌ Missing | No score thresholds |
| `-w`, `--warning-level` | ❌ Missing | No score thresholds |
| `-n`, `--notice-level` | ❌ Missing | No score thresholds |
| `--allhds` | ❌ Missing | Windows-only, not implemented |
| `--force` | ❌ Missing | Cannot override exclusions |
| `--printall` | ❌ Missing | No verbose file listing |
| `--allreasons` | ❌ Missing | Always shows all reasons |
| `--vulnchecks` | ❌ Missing | Windows-only feature |
| `--nolevcheck` | ❌ Missing | Levenshtein not implemented |
| `--scriptanalysis` | ❌ Missing | Script analysis not implemented |
| `--rootkit` | ❌ Missing | Rootkit check not implemented |
| `--noindicator` | ❌ Missing | Progress indicator not implemented |
| `--dontwait` | ❌ Missing | Exit behavior not configurable |
| `--intense` | ❌ Missing | Scan mode not implemented |
| `--csv` | ❌ Missing | CSV output not implemented |
| `--onlyrelevant` | ❌ Missing | Log filtering not implemented |
| `--update` | ❌ Missing | Signature update not implemented |
| `--maxworkingset` | ❌ Missing | Process size limit not implemented |
| `--nopesieve` | ❌ Missing | PE-Sieve not implemented |
| `--pesieveshellc` | ❌ Missing | PE-Sieve not implemented |
| `--nolisten` | ❌ Missing | C2 connection check not implemented |
| `--excludeprocess` | ❌ Missing | Process exclusion not implemented |
| `--version` | ❌ Missing | Version display not implemented |

#### Argument Validation

**Status**: ❌ **Missing**

- No validation of conflicting flags
- No validation of invalid combinations
- No early exit on invalid arguments
- Always exits with code 0 (no error codes)

**Code Location**: `src/main.rs`, lines 319-330

---

## Scan Targets

### Status: **Partial**

#### Directory Scanning

**Status**: ✅ **Implemented** (with limitations)

**Code Location**: `src/modules/filesystem_scan.rs`, lines 48-249

- ✅ Uses `walkdir::WalkDir` for recursive directory traversal
- ✅ Skips non-file entries (directories, symlinks)
- ✅ Error handling for inaccessible paths
- ❌ No `followlinks` option (always follows symlinks - different from v1)
- ❌ No platform-specific path exclusions (Linux `/proc`, `/dev`, etc.)
- ❌ No user-defined excludes from config file
- ⚠️ Limited drive exclusions (only `/Library/CloudStorage/`, `/Volumes/`)

#### File Type Handling

**Status**: ⚠️ **Partial**

**Code Location**: `src/modules/filesystem_scan.rs`, lines 17-31, 96-109

**Implemented:**
- ✅ Extension-based filtering (`REL_EXTS` constant)
- ✅ File format detection using `file-format` crate
- ✅ File type whitelist (`FILE_TYPES` constant)
- ✅ `--scan-all-files` flag support

**Missing:**
- ❌ No "evil extensions" list (different from v1's `EVIL_EXTENSIONS`)
- ❌ No script extensions list
- ❌ No file magic signature loading (v1 uses custom magic file)
- ❌ No fast scan mode (skip unknown files without evil extensions)
- ❌ No special handling for MDMP files (always scan regardless of size)

**Differences:**
- v1: 5000 KB default, v2: 10,000,000 bytes (10 MB) default
- v1: KB units, v2: bytes
- v1: Uses custom file magic, v2: Uses `file-format` crate

#### File Size Limits

**Status**: ✅ **Implemented** (with differences)

**Code Location**: `src/modules/filesystem_scan.rs`, lines 81-95

- ✅ Checks file size before scanning
- ✅ Skips files exceeding limit
- ❌ No special case for MDMP files (v1 always scans these)
- ⚠️ Size check uses `size_on_disk_fast()` which may differ from actual file size

#### Special File Handling

**Status**: ⚠️ **Partial**

**Code Location**: `src/modules/filesystem_scan.rs`, lines 70-73

- ✅ Skips non-file entries
- ❌ No check for character devices, block devices, FIFOs, sockets (Linux/Mac)
- ❌ No platform-specific file type checks

#### Archive Handling

**Status**: ❌ **Missing**

- No archive extraction
- ZIP files detected but not extracted

---

## IOC/Signature Support

### Hash IOCs

**Status**: ⚠️ **Partial**

**Code Location**: `src/main.rs`, lines 88-126

**Implemented:**
- ✅ Reads hash IOC files from `signatures/iocs/hash-iocs.txt`
- ✅ Parses semicolon-delimited format
- ✅ Detects hash type by length (MD5, SHA1, SHA256)
- ✅ Lowercases hash values
- ✅ Skips comment lines (starting with `#`)
- ✅ Hash matching in file scan

**Missing/Broken:**
- ❌ **No score parsing from IOC file** - hardcoded to 100 (line 119: `score: 100,  // TODO`)
- ❌ **No hash whitelist** - doesn't exclude empty file hashes
- ❌ **No false positive hash support** - doesn't check for false positives
- ❌ **No binary search optimization** - uses linear search (v1 uses sorted list + binary search)
- ❌ **No 3-column format support** - only handles 2 columns (hash;description)
- ❌ **No hash score dictionary** - can't store per-hash scores
- ⚠️ **Error handling**: Uses `expect()` which panics if file missing (should be graceful)

**Hash Matching:**
- ✅ Computes MD5, SHA1, SHA256 for files
- ✅ Compares against hash IOCs
- ⚠️ **Bug**: Hash match flag not reset between IOCs (line 174-192) - may cause issues
- ❌ No match level distinction (Malware vs Suspicious based on score)

### Filename IOCs

**Status**: ⚠️ **Partial** (Initialization only, no matching)

**Code Location**: `src/main.rs`, lines 140-193

**Implemented:**
- ✅ Reads filename IOC files from `signatures/iocs/filename-iocs.txt`
- ✅ Parses semicolon-delimited format
- ✅ Handles comment lines (stores as description)
- ✅ Parses score from second column
- ✅ Detects IOC type (always Regex currently)

**Missing/Broken:**
- ❌ **No filename matching** - TODO comment at line 158 in `filesystem_scan.rs`
- ❌ **No regex compilation** - patterns stored as strings, not compiled
- ❌ **No false positive regex support** - third column ignored
- ❌ **No environment variable replacement** - v1 replaces `%VAR%` / `$VAR`
- ❌ **No OS-specific transforms** - v1 transforms paths for different OS
- ❌ **Pattern lowercased** - may break case-sensitive regex (line 181)
- ❌ **No string vs regex detection** - always treated as regex (line 195-198)
- ⚠️ **Error handling**: Uses `expect()` and `unwrap()` which panic

### C2 IOCs

**Status**: ❌ **Missing**

- No C2 IOC initialization
- No C2 IOC file reading
- No C2 matching on process connections
- No network connection enumeration

### YARA Rules

**Status**: ✅ **Implemented** (with limitations)

**Code Location**: `src/main.rs`, lines 202-266

**Implemented:**
- ✅ Reads YARA rules from `signatures/yara/` directory
- ✅ Filters by `.yar` extension
- ✅ Test compiles each file individually
- ✅ Concatenates all rules and compiles together
- ✅ Defines external variables (filename, filepath, extension, filetype, owner)
- ✅ YARA scanning of files
- ✅ YARA scanning of process memory

**Missing/Broken:**
- ❌ **No multiple YARA directories** - v1 uses 3 directories (yara, iocs/yara, 3rdparty)
- ❌ **No recursive directory walk** - only reads top-level directory
- ❌ **No hidden file filtering** - v1 skips files starting with `.`, `~`, `_`
- ❌ **No `.yara` extension support** - only `.yar`
- ❌ **No YARA rule metadata extraction** - score, description, reference, author not extracted
- ❌ **Hardcoded YARA scores** - files: 60 (line 279), processes: 75 (line 50)
- ❌ **No matched strings extraction** - v1 shows matched string values
- ❌ **No memory rule flag** - v1 checks `memory` meta field for process scanning
- ❌ **No YARA timeout** - v1 has timeouts (though v2 sets 10s for file scan, line 257)
- ⚠️ **Error handling**: Uses `expect()` and `unwrap()` which panic

**YARA External Variables:**
- ✅ filename, filepath, extension, filetype, owner defined
- ❌ owner always empty string (TODO at line 218)
- ❌ No `md5` external variable (v1 legacy support)

---

## Matching Logic

### Case Sensitivity

**Status**: ⚠️ **Inconsistent**

- **Hash matching**: ✅ Case-insensitive (hashes lowercased)
- **Filename IOCs**: ❌ Lowercased during init (line 181) - breaks case-sensitive regex
- **YARA rules**: ✅ Case-sensitive (YARA engine default)
- **Path comparisons**: ⚠️ Platform-dependent (Rust default)

### Hash Algorithms

**Status**: ✅ **Implemented**

**Code Location**: `src/modules/filesystem_scan.rs`, lines 162-170

- ✅ MD5: `md5::compute()`
- ✅ SHA1: `sha1::Sha1`
- ✅ SHA256: `sha2::Sha256`
- ✅ Hexadecimal lowercase output
- ✅ Computed on full file content (memory-mapped)

### Regex Engine

**Status**: ❌ **Not Used**

- Filename IOCs stored as strings, not compiled regex
- No regex matching implemented
- Would use Rust `regex` crate if implemented

### Path Handling

**Status**: ⚠️ **Basic**

- ✅ OS-specific path separators (Rust standard library)
- ❌ No environment variable replacement
- ❌ No OS-specific path transforms
- ⚠️ Unicode handling: Uses `to_string_lossy()` which may lose information

### Score Calculation

**Status**: ⚠️ **Partial**

**Code Location**: `src/modules/filesystem_scan.rs`, lines 236-240

- ✅ Accumulative scoring (sums all match scores)
- ❌ **No score thresholds** - no alert/warning/notice levels
- ❌ **No message level determination** - always logs as WARNING
- ❌ **No filtering by score** - all matches logged regardless of score

---

## Output and Reporting

### Console Output

**Status**: ⚠️ **Partial**

**Code Location**: `src/main.rs`, lines 283-296

**Implemented:**
- ✅ Uses `flexi_logger` for console output
- ✅ Colorized output (via `nu-ansi-term` in flexi_logger)
- ✅ Log levels: INFO, DEBUG, TRACE, WARN, ERROR

**Missing:**
- ❌ **No CSV mode** - no `--csv` flag support
- ❌ **No custom colorization** - v1 has specific colors per message type
- ❌ **No message formatting** - v1 formats key-value pairs with line breaks
- ❌ **No RESULT message type** - v1 has special RESULT messages
- ❌ **No message type brackets** - v1 shows `[ALERT]`, `[WARNING]`, etc.

### Log File Output

**Status**: ✅ **Implemented** (with differences)

**Code Location**: `src/main.rs`, lines 268-281, 343-354

**Implemented:**
- ✅ Writes to log file: `loki_{hostname}.log`
- ✅ ISO 8601 timestamp format with Z suffix
- ✅ UTC timezone
- ✅ Log level included

**Missing/Differences:**
- ❌ **No timestamp in filename** - v1 uses `loki_{hostname}_{timestamp}.log`
- ❌ **No custom log file path** - no `-l` flag
- ❌ **No log folder option** - no `--logfolder` flag
- ❌ **No `--nolog` option** - always writes log file
- ❌ **No old log file removal** - v1 removes existing log at start
- ⚠️ **Append mode** - v1 removes old file, v2 appends

### Syslog Output

**Status**: ❌ **Missing**

- No syslog support
- No remote logging
- No RFC5424 format
- No UDP/TCP syslog

### Message Types

**Status**: ⚠️ **Partial**

**Implemented:**
- ✅ INFO, DEBUG, TRACE, WARN, ERROR (via log crate)

**Missing:**
- ❌ **No ALERT level** - v1 has ALERT for high scores
- ❌ **No NOTICE level** - v1 has NOTICE for medium scores
- ❌ **No RESULT level** - v1 has RESULT for final summary
- ❌ **No score-based level determination** - always WARN for matches

### Final Results Summary

**Status**: ❌ **Missing**

- No alert/warning/notice counters
- No final summary message
- No "SYSTEM SEEMS TO BE CLEAN" message
- No recommendations based on findings

---

## Performance and Threading

### Concurrency Model

**Status**: ✅ **Single-threaded** (matches v1)

- Sequential file scanning
- Sequential process scanning
- No explicit threading

### Timeouts

**Status**: ⚠️ **Partial**

- ✅ YARA file scan: 10 seconds (line 257)
- ❌ YARA process scan: 30 seconds (hardcoded, line 31) - no configurable timeout
- ❌ No timeout for hash computation (could be slow for large files)

### Limits

**Status**: ⚠️ **Partial**

- ✅ File size limit: Configurable via `--max-file-size`
- ❌ Process working set limit: Not implemented (v1: `--maxworkingset`)
- ❌ YARA matches per process: No warning for too many matches (v1 warns if > 5)

### Performance Optimizations

**Status**: ❌ **Missing**

- ❌ Hash IOCs: Linear search (v1 uses sorted list + binary search)
- ❌ No file type magic caching (v1 caches max signature length)
- ✅ YARA rules: Compiled once, reused (matches v1)

---

## Logging

### Verbosity Levels

**Status**: ✅ **Implemented**

- Normal: INFO, WARN, ERROR
- Debug: `--debug` flag adds DEBUG level
- Trace: `--trace` flag adds TRACE level

### Log Destinations

**Status**: ⚠️ **Partial**

- ✅ Console (STDOUT): Always
- ✅ Log file: Always (no `--nolog` option)
- ❌ Syslog: Not implemented

### Log Filtering

**Status**: ❌ **Missing**

- ❌ No `--onlyrelevant` flag (filter to warnings/alerts only)
- ❌ No `--printall` flag (log all scanned files)
- ❌ No `--allreasons` flag (always shows all reasons)

### Log Format Details

**Status**: ⚠️ **Basic**

- ✅ Timestamp: ISO 8601 with Z
- ✅ Hostname: Included in filename, not in message
- ✅ Module: Not explicitly tracked (v1 has "Init", "FileScan", "ProcessScan", "Results")
- ✅ Message: Free-form text

---

## Update Mechanisms

### Signature Update

**Status**: ❌ **Missing**

- No `--update` flag
- No git integration
- No signature-base submodule handling
- No auto-retrieval if signatures missing

### Signature Base Location

**Status**: ✅ **Implemented**

- Hardcoded: `./signatures` (line 26)
- Expected structure: `signatures/iocs/`, `signatures/yara/`

---

## Platform Specifics

### Windows

**Status**: ❌ **Not Implemented**

- ❌ No drive enumeration (`--allhds`, `--alldrives`)
- ❌ No WMI process enumeration
- ❌ No PE-Sieve integration
- ❌ No rootkit checks
- ❌ No vulnerability checks
- ❌ No DoublePulsar check
- ❌ No process anomaly checks
- ❌ No admin rights check
- ❌ No process priority setting

### Linux/Mac

**Status**: ⚠️ **Partial**

- ✅ Basic path handling
- ❌ No platform-specific path exclusions (`/proc`, `/dev`, etc.)
- ❌ No mount point detection
- ❌ No root check
- ❌ No special file type checks (character devices, etc.)

---

## Quality of Life Features

### Progress Indicator

**Status**: ❌ **Missing**

- No file count display
- No progress percentage
- No `--noindicator` flag

### Statistics Summary

**Status**: ❌ **Missing**

- No alert/warning/notice counters
- No final summary
- No scan statistics

### Scan Duration

**Status**: ⚠️ **Partial**

- ✅ Start time: Logged at initialization
- ✅ End time: Logged at completion
- ❌ No duration calculation
- ❌ No duration display

### Counters

**Status**: ❌ **Missing**

- No alert counter
- No warning counter
- No notice counter
- No message count

---

## Exit Codes

**Status**: ❌ **Missing**

**Code Location**: `src/main.rs` - no explicit exit codes

- Always exits with code 0 (Rust default)
- No error exit codes
- No validation error exits
- No signal handling (CTRL+C)

**Missing Exit Codes:**
- ❌ Exit 1: Invalid arguments
- ❌ Exit 1: Missing signatures
- ❌ Exit 1: YARA compilation failure
- ❌ Exit 0: `--version` flag
- ❌ Exit 0: `--update` flag
- ❌ Exit 0: CTRL+C handler

---

## Error Handling

### Status: ⚠️ **Partial** (Many panics)

#### Panic-Prone Code

**Hash IOC Initialization** (line 92):
```rust
fs::read_to_string(hash_ioc_file).expect("Unable to read hash IOC file...")
```
- ❌ Panics if file missing
- Should: Log error and continue or exit gracefully

**Filename IOC Initialization** (line 144):
```rust
fs::read_to_string(filename_ioc_file).expect("Unable to read filename IOC file...")
```
- ❌ Panics if file missing
- Should: Log error and continue or exit gracefully

**YARA Rule Compilation** (line 236):
```rust
.expect("Error parsing the composed rule set")
```
- ❌ Panics if compilation fails
- Should: Log error and exit with code 1

**File Metadata** (line 120):
```rust
let metadata = fs::metadata(entry.path()).unwrap();
```
- ❌ Panics on error
- Should: Handle error gracefully

**Memory Mapping** (line 152):
```rust
let mmap = unsafe { MmapOptions::new().map(&file_handle).unwrap() };
```
- ❌ Panics on error
- Should: Handle error gracefully

**Score Parsing** (line 184):
```rust
score: record[1].parse::<i16>().unwrap()
```
- ❌ Panics if score not a number
- Should: Use default score or skip invalid line

#### Graceful Error Handling

**File System Walk** (lines 59-66):
- ✅ Handles walk errors gracefully, continues

**File Access Errors** (lines 143-150):
- ✅ Handles file open errors, continues with next file

**YARA Scan Errors** (lines 265-269):
- ✅ Handles YARA scan errors, logs and continues

**Process Scan Errors** (lines 37-40):
- ✅ Handles process scan errors, logs and continues

### Error Message Quality

**Status**: ⚠️ **Basic**

- ✅ Error messages include context (file path, process name)
- ⚠️ Error messages use debug format (`{:?}`) which may not be user-friendly
- ❌ No error categorization (recoverable vs fatal)
- ❌ No error recovery strategies

---

## Code Quality Issues

### TODOs and Incomplete Features

1. **Filename IOC matching** (line 158 in `filesystem_scan.rs`): Not implemented
2. **Hash score parsing** (line 119 in `main.rs`): Hardcoded to 100
3. **Filename IOC type detection** (line 196 in `main.rs`): Always Regex
4. **Owner field** (line 218 in `filesystem_scan.rs`): Always empty
5. **YARA metadata extraction** (line 189, 229, 49): Hardcoded scores
6. **Match printing** (line 242 in `filesystem_scan.rs`): Not nested/formatted
7. **Process error handling** (line 42 in `process_check.rs`): Needs improvement
8. **IOC data structure limit** (line 85 in `main.rs`): Comment about 100k limit

### Architecture Issues

1. **No module structure**: All IOC initialization in `main.rs`
2. **Hardcoded paths**: Signature source hardcoded
3. **No configuration**: No config file support
4. **Limited error recovery**: Many panics instead of graceful errors
5. **No test infrastructure**: No tests found

---

## Summary by Feature Category

| Category | Status | Completeness |
|----------|--------|--------------|
| CLI Interface | ⚠️ Partial | ~25% (9/36 flags) |
| Scan Targets | ⚠️ Partial | ~60% (basic scanning works, missing exclusions) |
| Hash IOCs | ⚠️ Partial | ~70% (matching works, missing scores, false positives) |
| Filename IOCs | ❌ Missing | ~30% (init only, no matching) |
| C2 IOCs | ❌ Missing | 0% |
| YARA Rules | ✅ Implemented | ~80% (works, missing metadata) |
| Output Formats | ⚠️ Partial | ~40% (basic logging, missing CSV, syslog) |
| Score Thresholds | ❌ Missing | 0% |
| Platform Features | ❌ Missing | ~10% (basic cross-platform, no platform-specific) |
| Error Handling | ⚠️ Partial | ~50% (some graceful, many panics) |
| Exit Codes | ❌ Missing | 0% |
| Quality Features | ❌ Missing | ~10% (basic logging, no stats) |

**Overall Completeness**: ~35-40% of Loki v1 features

---

## Critical Gaps (Release Blockers)

1. **Filename IOC matching** - Core feature, marked as TODO
2. **Score thresholds** - Essential for proper alerting
3. **Exit codes** - Required for automation/scripting
4. **Error handling** - Too many panics, needs graceful failures
5. **Hash score parsing** - Currently hardcoded, breaks IOC format
6. **False positive hash support** - Important for accuracy
7. **YARA metadata extraction** - Scores, descriptions not extracted
8. **Platform-specific exclusions** - May scan system directories incorrectly

---

## Next Steps

1. Fix panic-prone code (use Result types)
2. Implement filename IOC matching
3. Add score threshold support
4. Implement exit codes
5. Add hash score parsing from IOC files
6. Extract YARA rule metadata
7. Add platform-specific path exclusions
8. Implement basic CLI flags (score thresholds, log options)


