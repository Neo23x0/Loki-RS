# Loki v1 Feature Inventory

This document provides a comprehensive inventory of all features, behaviors, and implementation details found in Loki v1 (Python). This serves as the reference specification for achieving feature parity in Loki2.

**Last Updated**: Based on analysis of Loki repository
**Loki v1 Version**: 0.51.1 (from lokilogger.py)

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

---

## CLI Interface

### Command Line Arguments

**Location**: `loki.py`, lines 1456-1528 (`main()` function using `argparse`)

#### Path and Scanning Options

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `-p`, `--path` | string | `C:\` (Windows) or `/` (Linux/Mac) | Path to scan | Line 1464 |
| `-s` | int (KB) | 5000 | Maximum file size to check in KB | Line 1465 |
| `--allhds` | flag | False | Scan all local hard drives (Windows only) | Line 1472 |
| `--alldrives` | flag | False | Scan all drives (including network/removable) | Line 1473 |
| `--force` | flag | False | Force scan on excluded folders | Line 1499 |
| `--nofilescan` | flag | False | Skip the file scan | Line 1477 |
| `--noprocscan` | flag | False | Skip the process scan | Line 1476 |

#### Output and Logging Options

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `-l`, `--log-file` | string | `loki_<hostname>_<timestamp>.log` | Log file path | Line 1466 |
| `--logfolder` | string | "" | Folder for log files (uses default filename) | Line 1492 |
| `--nolog` | flag | False | Don't write a local log file | Line 1487 |
| `-r`, `--remote-loghost` | string | "" | Remote syslog system | Line 1467 |
| `-t`, `--remote-syslog-port` | int | 514 | Remote syslog port | Line 1468 |
| `--syslogtcp` | flag | False | Use TCP instead of UDP for syslog | Line 1491 |
| `--csv` | flag | False | Write CSV log format to STDOUT | Line 1485 |
| `--onlyrelevant` | flag | False | Only print warnings or alerts | Line 1486 |
| `--printall` | flag | False | Print all files that are scanned | Line 1474 |
| `--allreasons` | flag | False | Print all reasons that caused the score | Line 1475 |
| `--noindicator` | flag | False | Do not show a progress indicator | Line 1482 |
| `--dontwait` | flag | False | Do not wait on exit | Line 1483 |

#### Scoring and Thresholds

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `-a`, `--alert-level` | int | 100 | Alert score threshold | Line 1469 |
| `-w`, `--warning-level` | int | 60 | Warning score threshold | Line 1470 |
| `-n`, `--notice-level` | int | 40 | Notice score threshold | Line 1471 |

#### Scan Mode Options

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `--intense` | flag | False | Intense scan mode (scan unknown file types) | Line 1484 |
| `--vulnchecks` | flag | False | Run vulnerability checks | Line 1478 |
| `--rootkit` | flag | False | Skip the rootkit check (Windows only) | Line 1481 |
| `--nolevcheck` | flag | False | Skip Levenshtein distance check | Line 1479 |
| `--scriptanalysis` | flag | False | Statistical analysis for scripts (beta) | Line 1480 |

#### Process Scanning Options

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `--maxworkingset` | int (MB) | 200 | Max working set size for process scan | Line 1490 |
| `--nopesieve` | flag | False | Do not perform pe-sieve scans | Line 1493 |
| `--pesieveshellc` | flag | False | Perform pe-sieve shellcode scan | Line 1494 |
| `--nolisten` | flag | False | Do not show listening connections | Line 1496 |
| `--excludeprocess` | string (repeatable) | [] | Exclude executable name from scans | Line 1497 |

#### Utility Options

| Flag | Type | Default | Description | Code Location |
|------|------|---------|-------------|---------------|
| `--update` | flag | False | Update signatures from signature-base | Line 1488 |
| `--debug` | flag | False | Debug output | Line 1489 |
| `--version` | flag | False | Show version and exit | Line 1500 |
| `--python` | string | "python" | Override default python path | Line 1495 |
| `-h`, `--help` | flag | - | Show help message | argparse default |

### Argument Validation

**Location**: `loki.py`, lines 1504-1524

1. **Syslog TCP validation** (line 1504-1506):
   - If `--syslogtcp` is set, `-r` must also be set
   - Exit code 1 if invalid

2. **Log file validation** (line 1508-1520):
   - `--nolog` incompatible with `-l` or `--logfolder`
   - Exit code 1 if invalid
   - Default log filename: `loki_<hostname>_<timestamp>.log`
   - If `--logfolder` specified, uses default filename in that folder
   - If `-l` not specified and no `--logfolder`, uses default filename in current directory

3. **PE-Sieve validation** (line 1522-1524):
   - `--pesieveshellc` incompatible with `--nopesieve`
   - Exit code 1 if invalid

4. **Process exclusions** (line 1526):
   - All process names in `--excludeprocess` are lowercased

### Config File Support

**Location**: `config/excludes.cfg`

- User-defined excludes via regex patterns
- Each line is a regex applied to full file path (case-insensitive)
- Comments start with `#`
- Empty lines ignored
- Loaded in `Loki.__init__()` via `initialize_excludes()` (line 1290)

---

## Scan Targets

### Directory Scanning

**Location**: `loki.py`, `Loki.scan_path()` method (line 197)

#### Recursion Behavior

- Uses `os.walk(path, onerror=walk_error, followlinks=False)`
- Does NOT follow symlinks by default
- Error handler: `walk_error()` function (line 1441) - logs error and continues

#### Platform-Specific Default Paths

**Location**: `loki.py`, lines 1602-1624

- **Windows**: Default `C:\` (from `-p` default)
- **Linux/Mac**: Default `/` (if `-p` was `C:\`, converts to `/`)
- **All drives** (`--alldrives`): Scans all logical drives (Windows only)
- **All hard drives** (`--allhds`): Scans only fixed drives (Windows only)

#### Path Exclusions

**Location**: `loki.py`, `Loki.__init__()` and `scan_path()`

##### Linux/Mac Static Excludes (Start of Path)

**Location**: Lines 122-124, 149-158

- `/proc`
- `/dev`
- `/sys/kernel/debug`
- `/sys/kernel/slab`
- `/sys/devices`
- `/usr/src/linux`
- `/media` (if not `--alldrives`)
- `/volumes` (if not `--alldrives`)
- Mounted devices from `getExcludedMountpoints()` (if not `--alldrives`)

##### Linux/Mac Static Excludes (End of Path)

**Location**: Line 124, 273-278

- `/initctl`

##### Windows Excludes

- Program directory (where Loki is running from) - line 297
- Network drives (unless `--alldrives`)

##### User-Defined Excludes

**Location**: `config/excludes.cfg`, loaded via `initialize_excludes()` (line 1290)

- Regex patterns applied to full file path
- Case-insensitive matching
- Examples in README: `\\Ntfrs\\`, `\\Ntds\\`, `\\EDB[^\.]+\.log`

#### File Type Handling

**Location**: `loki.py`, lines 76-88, 254-344

##### Evil Extensions (Always Scanned)

**Location**: Line 77-82

```
.vbs, .ps, .ps1, .rar, .tmp, .bas, .bat, .chm, .cmd, .com, .cpl, .crt, .dll, .exe, 
.hta, .js, .lnk, .msc, .ocx, .pcd, .pif, .pot, .pdf, .reg, .scr, .sct, .sys, .url, 
.vb, .vbe, .wsc, .wsf, .wsh, .ct, .t, .input, .war, .jsp, .jspx, .php, .asp, .aspx, 
.doc, .docx, .xls, .xlsx, .ppt, .pptx, .tmp, .log, .dump, .pwd, .w, .txt, .conf, 
.cfg, .config, .psd1, .psm1, .ps1xml, .clixml, .psc1, .pssc, .pl, .www, .rdp, .jar, 
.docm, .sys
```

##### Script Extensions (for Script Analysis)

**Location**: Line 84-86

```
.asp, .vbs, .ps1, .bas, .bat, .js, .vb, .vbe, .wsc, .wsf, .wsh, .jsp, .jspx, .php, 
.asp, .aspx, .psd1, .psm1, .ps1xml, .clixml, .psc1, .pssc, .pl
```

##### File Type Detection

**Location**: `lib/helpers.py`, `get_file_type()` function

- Uses file magic signatures from `signature-base/misc/file-type-signatures.txt`
- Format: `HEX_SIGNATURE;DESCRIPTION`
- Loaded in `initialize_filetype_magics()` (line 1261)
- Checks first bytes of file against signatures
- Returns file type string (e.g., "PE", "MDMP", "ZIP", "UNKNOWN")

##### Fast Scan Mode (Non-Intense)

**Location**: Line 339-343

- If `fileType == "UNKNOWN"` AND `extension not in EVIL_EXTENSIONS`:
  - Skip intense checks (hash, YARA)
  - Still checks filename IOCs and Levenshtein
  - Can be overridden with `--intense` flag

##### Intense Scan Mode

**Location**: Line 364-369

- Scans all file types, including unknown
- Always performs hash and YARA checks
- Enabled by `--intense` flag or if file type is known/evil extension

#### File Size Limits

**Location**: Line 301, 352-356

- Default: 5000 KB (from `-s` flag, default 5000)
- Files exceeding limit:
  - Skip intense checks (hash, YARA)
  - Still check filename IOCs
  - Log with `--printall`
- Exception: MDMP files always scanned regardless of size (line 359-361)

#### Special File Handling

**Location**: Lines 270-283 (Linux/Mac)

- Skips character devices (`S_ISCHR`)
- Skips block devices (`S_ISBLK`)
- Skips FIFOs (`S_ISFIFO`)
- Skips symlinks (`S_ISLNK`) - already handled by `followlinks=False`
- Skips sockets (`S_ISSOCK`)

#### Archive Handling

- No explicit archive extraction
- ZIP files detected via file magic
- SWF files: decompressed scan mentioned in README (since v0.8)

---

## IOC/Signature Support

### IOC File Locations

**Location**: `loki.py`, line 161

- Base path: `signature-base/iocs/`
- Files are selected by name containing keywords:
  - `hash` → Hash IOCs
  - `filename` → Filename IOCs
  - `c2` → C2 IOCs
  - `falsepositive` → False positive hashes

### Hash IOCs

**Location**: `loki.py`, `initialize_hash_iocs()` (line 1188)

#### File Format

```
Hash;Description [Reference]
```

Or with score:

```
Hash;Score;Description [Reference]
```

#### Parsing Rules

- Delimiter: `;` (semicolon)
- Comments: Lines starting with `#` are ignored
- Empty lines: Ignored
- Hash type detection: By length
  - 32 chars → MD5
  - 40 chars → SHA1
  - 64 chars → SHA256
- Hash storage: Converted to integer for binary search
- Default score: 100 (if not specified)
- Score range: Integer (typically 0-100)

#### Hash Whitelist

**Location**: Lines 1189-1201

Excluded hashes (empty files, line breaks):
- MD5: `d41d8cd98f00b204e9800998ecf8427e`, `68b329da9893e34099c7d8ad5cb9c940`, `81051bcc2cf1bedf378224b0a93e2877`
- SHA1: `da39a3ee5e6b4b0d3255bfef95601890afd80709`, `adc83b19e793491b1c6ea0fd8b46cd9f32e592fc`, `ba8ab5a0280b953aa97435ff8946cbcbb2755a27`
- SHA256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b`, `7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6`

#### False Positive Hashes

**Location**: Line 184, 1235-1236

- Files with `hash` AND `falsepositive` in filename
- Same format as hash IOCs
- Checked before hash matching (line 397-398)
- If match found, skip file entirely

#### Hash Matching

**Location**: Lines 374-429

- Computes MD5, SHA1, SHA256 for each file
- Uses binary search on sorted integer lists (line 403, 408, 413)
- Match level: "Malware" (score >= 80) or "Suspicious" (score < 80)
- Log format: `{Level} Hash TYPE: {type} HASH: {hash} SUBSCORE: {score} DESC: {description}`

### Filename IOCs

**Location**: `loki.py`, `initialize_filename_iocs()` (line 1030)

#### File Format

```
# (optional) Description [Reference]
Filename as Regex[;Score as integer[;False-positive as Regex]]
```

#### Parsing Rules

- Delimiter: `;` (semicolon)
- Comments: Lines starting with `#` (stored as description for following patterns)
- Empty lines: Ignored
- Description: Last comment line before pattern
- Score: Default if not specified (appears to be 0, but typically set)
- False positive regex: Optional third field
- Environment variable replacement: `replaceEnvVars()` (line 1071)
- OS-specific transforms: `transformOS()` (line 1073)

#### Matching Logic

**Location**: Lines 305-315

- Applied to full file path (not just filename)
- Case-sensitive regex matching
- False positive check: If FP regex matches, skip this IOC
- Score accumulation: Adds to total score
- Log format: `File Name IOC matched PATTERN: {pattern} SUBSCORE: {score} DESC: {description}`

### C2 IOCs

**Location**: `loki.py`, `initialize_c2_iocs()` (line 981)

#### File Format

```
# (optional) Description [Reference]
C2_Server[;Score]
```

#### Parsing Rules

- Delimiter: `;` (semicolon, optional)
- Comments: Lines starting with `#` (stored as description)
- Empty lines: Ignored
- Minimum length: 4 characters (line 1012-1015)
- Storage: Lowercased, stored in dictionary with description

#### Matching Logic

**Location**: `check_process_connections()` method (referenced line 756)

- Applied to process network connections
- Compares connection endpoints (IP/FQDN) with C2 IOCs
- Logged as process scan alerts

### YARA Rules

**Location**: `loki.py`, `initialize_yara_rules()` (line 1103)

#### Rule Directories

**Location**: Lines 164-166

1. `signature-base/yara/`
2. `signature-base/iocs/yara/`
3. `signature-base/3rdparty/`

#### File Selection

- Extension: `.yar` or `.yara`
- Excluded: Files starting with `.`, `~`, or `_`
- Recursive: `os.walk()` through directories

#### Compilation

- Test compile each file individually (line 1136-1151)
- On error: Log error, skip file (or exit if `--debug`)
- Concatenate all valid rules into single string
- Compile all rules together (line 1163-1177)
- External variables defined:
  - `filename` (string)
  - `filepath` (string)
  - `extension` (string)
  - `filetype` (string)
  - `md5` (string, legacy)
  - `owner` (string)

#### Rule Metadata

**Location**: Lines 528-544

- `description`: Rule description
- `cluster`: IceWater cluster identifier
- `reference`: Reference URL
- `viz_url`: Visualization URL
- `author`: Rule author
- `score`: Rule score (default 70)
- `memory`: Flag for process memory scanning (1 = scan memory)

#### Matching Strings

**Location**: Lines 547-550, `get_string_matches()` (line 558)

- Extracts matched strings from YARA results
- Format: `{identifier}: '{value}'`
- Truncated to 140 chars if longer
- Included in log message

---

## Matching Logic

### Case Sensitivity

- **Hash matching**: Case-insensitive (hashes lowercased on load, line 1217)
- **Filename IOCs**: Case-sensitive regex (Python `re` module)
- **YARA rules**: Case-sensitive (YARA engine default)
- **Path comparisons**: Case-insensitive on Windows, case-sensitive on Linux/Mac

### Hash Algorithms

**Location**: `lib/helpers.py`, `generateHashes()` function

- **MD5**: `hashlib.md5()`
- **SHA1**: `hashlib.sha1()`
- **SHA256**: `hashlib.sha256()`
- Computed on full file content (read into memory)
- Format: Hexadecimal lowercase

### Regex Engine

- Python `re` module
- Compiled regex objects for filename IOCs
- No special flags (case-sensitive)

### Path Handling

- **Normalization**: OS-specific path separators
- **Environment variables**: Replaced in filename IOCs (`%VAR%` on Windows, `$VAR` on Unix)
- **Unicode**: Encoded to ASCII with replacement for YARA externals (line 250-251)

### Score Calculation

**Location**: Lines 242, 315, 429, 463

- Accumulative: Each match adds its score
- Total score determines message level:
  - `>= alert-level` (default 100) → ALERT
  - `>= warning-level` (default 60) → WARNING
  - `>= notice-level` (default 40) → NOTICE
  - `< notice-level` → Not logged (unless `--printall`)

---

## Output and Reporting

### Console Output

**Location**: `lib/lokilogger.py`, `log_to_stdout()` (line 117)

#### CSV Mode (`--csv`)

- Format: `{timestamp},{hostname},{level},{message}`
- No colorization
- All messages to STDOUT

#### Normal Mode

- Colorized output using `colorama`
- Color scheme:
  - NOTICE: Cyan
  - INFO: Green
  - WARNING: Yellow
  - ALERT: Red
  - DEBUG: White
  - ERROR: Magenta
  - RESULT: Green (clean), Yellow (suspicious), Red (indicators)
- Formatting:
  - Message type in brackets: `[ALERT]`, `[WARNING]`, etc.
  - Key-value pairs colorized (e.g., `FILE:`, `MD5:`, `REASON_1:`)
  - Line breaks before key words for readability

### Log File Output

**Location**: `lib/lokilogger.py`, `log_to_file()` method

- Default filename: `loki_{hostname}_{timestamp}.log`
- Format: `[YYYY-MM-DDTHH:MM:SSZ] {LEVEL} {message}`
- UTF-8 encoding
- Appended (old file removed at start, line 1540)

### Syslog Output

**Location**: `lib/lokilogger.py`, lines 63-76

- RFC5424 format
- Facility: `LOG_LOCAL3`
- Protocol: UDP (default) or TCP (`--syslogtcp`)
- Port: 514 (default) or custom (`-t`)
- Host: Specified via `-r`

### Message Types

**Location**: `lib/lokilogger.py`, `log()` method (line 78)

- **ALERT**: Score >= alert threshold
- **WARNING**: Score >= warning threshold
- **NOTICE**: Score >= notice threshold
- **INFO**: Informational messages
- **DEBUG**: Debug messages (only if `--debug`)
- **ERROR**: Error messages
- **RESULT**: Final scan results

### Final Results Summary

**Location**: `loki.py`, lines 1627-1639

- Counts: Alerts, warnings, notices
- Messages:
  - If alerts: "Indicators detected!" + recommendation
  - Else if warnings: "Suspicious objects detected!" + recommendation
  - Else: "SYSTEM SEEMS TO BE CLEAN."
- False positive reporting URL

---

## Performance and Threading

### Concurrency Model

- **Single-threaded**: No explicit threading for file scanning
- **Process scanning**: Sequential (one process at a time)
- **YARA scanning**: Synchronous (blocking)

### Timeouts

- **YARA file scan**: No explicit timeout (YARA default)
- **YARA process scan**: No explicit timeout (YARA default)
- **Process execution**: 10 seconds (for helper processes, line 239)

### Limits

- **File size**: Configurable via `-s` (default 5000 KB)
- **Process working set**: Configurable via `--maxworkingset` (default 200 MB)
- **YARA matches per process**: Warning if > 5 matches (line 712-713)

### Performance Optimizations

- Hash IOCs: Sorted lists + binary search (`bisect_left`, line 91-94)
- File type magic: Maximum signature length cached (line 1275-1276)
- YARA rules: Compiled once, reused for all files/processes

---

## Logging

### Verbosity Levels

- **Normal**: INFO, WARNING, ALERT, NOTICE, ERROR, RESULT
- **Debug** (`--debug`): Adds DEBUG messages
- **Trace**: Not explicitly implemented (DEBUG is most verbose)

### Log Destinations

1. **Console** (STDOUT): Always (unless CSV mode)
2. **Log file**: Default (unless `--nolog`)
3. **Syslog**: If `-r` specified

### Log Filtering

- **`--onlyrelevant`**: Only ALERT and WARNING messages
- **`--printall`**: All scanned files logged at INFO level
- **`--allreasons`**: All match reasons (default: first 2)

### Log Format Details

- Timestamp: ISO 8601 format with Z suffix
- Hostname: System hostname
- Module: "Init", "FileScan", "ProcessScan", "Results"
- Message: Free-form text with key-value pairs

---

## Update Mechanisms

### Signature Update

**Location**: `loki-upgrader.py`

- Command: `--update` flag
- Method: Git pull from signature-base repository
- Behavior: Updates submodule, exits after completion
- Exit code: 0

### Signature Base Location

- Subdirectory: `signature-base/`
- Auto-retrieval: If missing/empty, attempts to clone (line 140-143)

---

## Platform Specifics

### Windows

#### Drive Handling

- **Logical drives**: `win32api.GetLogicalDriveStrings()`
- **Drive types**: `win32file.GetDriveType()`
  - `DRIVE_FIXED`: Local hard drives
  - `DRIVE_REMOVABLE`: Removable media
  - `DRIVE_REMOTE`: Network drives
- **All drives** (`--alldrives`): All logical drives
- **All HDDs** (`--allhds`): Only `DRIVE_FIXED`

#### Process Scanning

- **WMI**: Used for process enumeration (`wmi.WMI()`)
- **Process memory**: YARA `match(pid=pid)`
- **PE-Sieve**: Windows-only tool for process analysis
- **Admin check**: `shell.IsUserAnAdmin()`

#### Path Handling

- Path separator: `\` (backslash)
- Case-insensitive paths
- UNC paths: Supported (network drives)

#### Special Features

- **Rootkit check**: Windows-only (`--rootkit` flag, but actually runs check)
- **Vulnerability checks**: Windows-only (`--vulnchecks`)
- **DoublePulsar check**: Windows-only
- **Process priority**: Set to "nice" priority

### Linux/Mac

#### Path Handling

- Path separator: `/` (forward slash)
- Case-sensitive paths
- Mount points: Excluded by default (unless `--alldrives`)

#### Process Scanning

- **Limited**: Process memory scanning may be disabled
- **Admin check**: `os.geteuid() == 0`

#### Special File Types

- Character devices, block devices, FIFOs, sockets: Skipped
- Symlinks: Not followed (`followlinks=False`)

---

## Quality of Life Features

### Progress Indicator

**Location**: `lib/helpers.py`, `printProgress()` function

- Shows file count during scan
- Disabled with `--noindicator`
- Format: Simple counter (e.g., "Scanning file 1234...")

### Statistics Summary

**Location**: Lines 1627-1639

- Counts: Alerts, warnings, notices
- Final message: Based on highest severity found
- Scan completion time logged

### Scan Duration

- Start time: Logged at initialization
- End time: Logged at completion
- Format: ISO 8601 timestamps

### Counters

- **Alerts**: Incremented on ALERT messages
- **Warnings**: Incremented on WARNING messages
- **Notices**: Incremented on NOTICE messages
- **Message count**: Total messages logged

---

## Exit Codes

**Location**: `loki.py`, lines 1504-1641

| Code | Condition | Location |
|------|-----------|----------|
| 0 | Normal completion | Line 1641 |
| 0 | `--version` flag | Line 1550 |
| 0 | `--update` flag (after update) | Line 1555 |
| 0 | CTRL+C (signal handler) | Line 1454 |
| 1 | Invalid `--syslogtcp` without `-r` | Line 1506 |
| 1 | Invalid `--nolog` with `-l` or `--logfolder` | Line 1510 |
| 1 | Invalid `--logfolder` and `-l` both specified | Line 1514 |
| 1 | Invalid `--pesieveshellc` with `--nopesieve` | Line 1524 |
| 1 | Error during initialization (if `--debug`) | Various |

### Signal Handling

- **SIGINT** (CTRL+C): Caught, logs message, exits with code 0
- Handler: `signal_handler()` (line 1448)

---

## Additional Features

### Levenshtein Distance Check

**Location**: `lib/levenshtein.py`, `LevCheck` class

- Checks if filename is similar to well-known system files
- Score: 60
- Subscore: 40
- Disabled with `--nolevcheck`

### Script Statistical Analysis

**Location**: `Loki.script_stats_analysis()` method (line 1329)

- Beta feature (`--scriptanalysis`)
- Analyzes character distribution in script files
- Detects obfuscated code
- Applied to files with script extensions

### PE-Sieve Integration

**Location**: `lib/pesieve.py`, `PESieve` class

- Windows-only
- Scans processes for:
  - Replaced processes
  - Implanted PE
  - Implanted shellcode
  - Patched processes
  - Unreachable executables
- Disabled with `--nopesieve`
- Shellcode scan: `--pesieveshellc`

### Process Anomaly Checks

**Location**: Lines 759-843

- System process (PID != 4)
- smss.exe (parent, path, priority)
- csrss.exe (path, priority)
- wininit.exe (path, priority)
- services.exe (path, priority, parent)
- lsass.exe (count, path, priority)
- winlogon.exe (path, priority, parent)
- svchost.exe (owner, count, path)
- explorer.exe (parent, path)
- waitfor.exe (suspicious backdoor)

### Process Connection Checks

**Location**: `check_process_connections()` method

- Compares process network connections with C2 IOCs
- Disabled with `--nolisten`

### Rootkit Check

**Location**: `check_rootkit()` method

- Windows-only
- Regin filesystem check (mentioned in README)
- Actually runs when `--rootkit` flag is set (counterintuitive)

### Vulnerability Checks

**Location**: `lib/vuln_checker.py`, `VulnChecker` class

- Windows-only
- Enabled with `--vulnchecks`
- Checks for known vulnerabilities

### DoublePulsar Check

**Location**: `lib/doublepulsar.py`, `DoublePulsar` class

- Windows-only
- Checks for DoublePulsar backdoor

---

## Edge Cases and Special Behaviors

### File Access Errors

- **Permission denied**: Logged at DEBUG level (or ERROR if `--show-access-errors` equivalent)
- **File not found**: Handled by `walk_error()` handler
- **Unicode errors**: Encoded to ASCII with replacement for YARA

### Empty Files

- Hash whitelist excludes empty file hashes
- Still scanned for filename IOCs and YARA

### Large Files

- Exceeding size limit: Skip intense checks
- MDMP files: Always scanned regardless of size

### Process Access Errors

- **Access denied**: Logged at ERROR or DEBUG
- **Process terminated**: Handled gracefully
- **Large working set**: Skipped (stability)

### YARA Compilation Errors

- **Individual rule error**: Logged, file skipped
- **Final compilation error**: Exits with code 1 (if `--debug`)

### Missing Signature Base

- Auto-retrieval attempted
- Error if still missing

---

## Notes

- This inventory is based on code analysis of the Loki v1 repository
- Some behaviors may vary by platform
- Beta features (script analysis) may have incomplete implementations
- Exit code 0 is used for both success and early exits (version, update, CTRL+C)


