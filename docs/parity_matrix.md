# Loki2 Parity Matrix

This document provides a feature-by-feature comparison between Loki v1 and Loki2, identifying gaps, bugs, and implementation plans.

**Last Updated**: Based on comprehensive analysis
**Loki v1 Version**: 0.51.1
**Loki2 Version**: 2.0.1-alpha

---

## Legend

**Status:**
- ✅ **Implemented**: Feature exists and works
- ⚠️ **Partial**: Feature exists but incomplete or has issues
- ❌ **Missing**: Feature not implemented
- 🐛 **Broken**: Feature exists but has bugs
- 🔄 **Divergent**: Works differently than v1 (may be intentional)

**Priority:**
- **P0**: Release blocker - must have for v1 parity
- **P1**: High priority - important for usability
- **P2**: Medium priority - nice to have
- **P3**: Low priority - can defer
- **Skip**: Can be skipped (better alternatives or not needed)

---

## Core Scanning Features

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **File System Scanning** | Recursive directory walk with `os.walk()`, `followlinks=False` | ✅ Implemented | Uses `walkdir` with `follow_links(false)` to match v1 behavior | ✅ | ✅ Complete | Test with symlink directories |
| **File Type Filtering** | Filters by extension list + file magic signatures | ⚠️ Partial | Uses `file-format` crate, different approach, missing "evil extensions" list | P1 | Add evil extensions list, consider file magic loading | Test with various file types |
| **File Size Limit** | Default 5000 KB, configurable via `-s` | ⚠️ Partial | Default 10MB (bytes), no KB option | P1 | Add `-s` flag for KB, keep bytes option | Test size limit enforcement |
| **Hash IOC Matching** | MD5/SHA1/SHA256 matching with binary search | ✅ Implemented | Binary search implemented - hashes organized by type and sorted for O(log n) lookup | ✅ | ✅ Complete | Test with large hash IOC files |
| **Hash Score Parsing** | Reads score from IOC file (3-column format) | ✅ Implemented | Supports 2-column (hash;description → score=75) and 3-column (hash;score;description) formats | ✅ | ✅ Complete | Test with IOC files containing scores |
| **False Positive Hashes** | Checks false positive hashes before matching | ✅ Implemented | Loads files with "hash" and "falsepositive" in filename, checks before hash matching, skips file if match found | ✅ | ✅ Complete | Test with false positive hash file |
| **Hash Whitelist** | Excludes empty file hashes | ❌ Missing | No whitelist | P2 | Add hash whitelist | Test with empty files |
| **Filename IOC Matching** | Regex matching on full file path | ✅ Implemented | Regex compilation and matching implemented, supports false positive regex | ✅ | ✅ Complete | Test with filename IOC patterns |
| **Filename IOC False Positives** | Optional FP regex per IOC | ✅ Implemented | Third column parsed as false positive regex | ✅ | ✅ Complete | Test with FP patterns |
| **Filename IOC Environment Vars** | Replaces `%VAR%` / `$VAR` in patterns | ❌ Missing | No replacement | P2 | Add env var replacement | Test with patterns containing vars |
| **YARA Rule Compilation** | Compiles from multiple directories | ⚠️ Partial | Only one directory, no recursive walk. ✅ Migrated to YARA-X. | P1 | Add recursive walk, multiple directories | Test with nested rule directories |
| **YARA Metadata Extraction** | Extracts score, description, reference, author | ✅ Implemented | Using YARA-X API: `matching_rule.metadata()` extracts description, author, score from rule metadata | ✅ | ✅ Complete - Migrated to YARA-X | Test with rules containing metadata |
| **YARA Matched Strings** | Shows matched string values with offsets | ✅ Implemented | Using YARA-X API: `pattern.matches()` extracts matched strings with offsets, hex-encodes non-ASCII | ✅ | ✅ Complete - Migrated to YARA-X | Test with rules that match strings, including non-ASCII |
| **YARA Memory Rules** | Checks `memory` meta field for process scanning | ❌ Missing | Scans all rules on processes | P1 | Filter rules by memory flag | Test with memory-only rules |
| **Process Memory Scanning** | YARA scan of process memory | ✅ Implemented | Works, but no working set limit | P1 | Add `--maxworkingset` flag | Test with large processes |
| **C2 IOC Matching** | Matches process network connections | ✅ Implemented | Loads C2 IOCs from files with "c2" in filename, matches against process network connections from /proc/net/tcp and /proc/net/udp | ✅ | ✅ Complete | Test with process connections |

---

## CLI Interface

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Path Selection (`-p`)** | Default `C:\` or `/`, configurable | ⚠️ Partial | Uses `--folder` instead of `-p` | P1 | Add `-p` alias, keep `--folder` | Test path selection |
| **File Size (`-s` KB)** | Size in KB, default 5000 | ❌ Missing | Only bytes option exists | P1 | Add `-s` flag for KB | Test KB vs bytes |
| **Score Thresholds (`-a/-w/-n`)** | Alert/Warning/Notice levels | ✅ Implemented | `--alert-level`, `--warning-level`, `--notice-level` flags (default: 80/60/40), `--max-reasons` flag | ✅ | ✅ Complete | Test with different thresholds |
| **Log File (`-l`)** | Custom log file path | ❌ Missing | Fixed filename only | P2 | Add `-l` flag | Test custom log paths |
| **Log Folder (`--logfolder`)** | Folder for log files | ❌ Missing | No folder option | P2 | Add `--logfolder` flag | Test log folder |
| **No Log (`--nolog`)** | Skip log file writing | ❌ Missing | Always writes log | P2 | Add `--nolog` flag | Test no log mode |
| **Syslog (`-r/-t/--syslogtcp`)** | Remote syslog logging | ❌ Missing | No syslog support | P3 | Add syslog support (low priority) | Test syslog output |
| **CSV Output (`--csv`)** | CSV format to STDOUT | ❌ Missing | No CSV mode | P2 | Add CSV output format | Test CSV parsing |
| **Only Relevant (`--onlyrelevant`)** | Filter to warnings/alerts | ❌ Missing | All messages logged | P2 | Add filtering | Test message filtering |
| **Print All (`--printall`)** | Log all scanned files | ❌ Missing | No verbose mode | P3 | Add verbose logging | Test verbose output |
| **All Reasons (`--allreasons`)** | Show all match reasons | ⚠️ Partial | Always shows all (no option to limit) | P3 | Add flag to limit reasons | Test reason display |
| **Intense Mode (`--intense`)** | Scan unknown file types | ⚠️ Partial | `--scan-all-files` similar but not identical | P2 | Align with v1 behavior | Test intense mode |
| **Force (`--force`)** | Override exclusions | ❌ Missing | No override option | P2 | Add force flag | Test exclusion override |
| **Version (`--version`)** | Show version and exit | ✅ Implemented | `--version` flag shows version and exits | ✅ | ✅ Complete | Test version display |
| **Update (`--update`)** | Update signatures | ❌ Missing | No update mechanism | P2 | Add git-based update | Test signature update |
| **Help (`-h/--help`)** | Show help | ✅ Implemented | Works via rustop | ✅ | - | - |

---

## Path Exclusions and Filtering

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Linux Path Exclusions** | Excludes `/proc`, `/dev`, `/sys`, etc. | ✅ Implemented | Excludes `/proc`, `/dev`, `/sys/kernel/debug`, `/sys/kernel/slab`, `/sys/devices`, `/usr/src/linux`, `/media`, `/volumes` (unless `--scan-all-drives`) | ✅ | ✅ Complete | Test on Linux system |
| **Windows Drive Handling** | `--allhds`, `--alldrives` options | ❌ Missing | No Windows-specific drive handling | P2 | Add Windows drive enumeration | Test on Windows |
| **User Excludes Config** | `config/excludes.cfg` regex patterns | ❌ Missing | No config file support | P1 | Load and apply excludes.cfg | Test with exclude patterns |
| **Program Directory Skip** | Skips Loki's own directory | ❌ Missing | May scan own directory | P1 | Detect and skip program directory | Test with Loki2 in scan path |
| **Mounted Devices** | Excludes `/media`, `/volumes` | ⚠️ Partial | Only excludes `/Volumes/` | P1 | Add `/media` exclusion | Test with mounted drives |
| **Network Drives** | Excludes network drives (unless `--alldrives`) | ❌ Missing | No network drive detection | P2 | Detect and exclude network drives | Test with network mounts |

---

## Output and Reporting

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Console Colors** | Colorama with specific colors per level | ⚠️ Partial | Basic colors via flexi_logger | P2 | Enhance colorization to match v1 | Test color output |
| **Message Formatting** | Key-value pairs with line breaks | ⚠️ Partial | Basic formatting | P2 | Add key-value formatting | Test formatted output |
| **Result Summary** | Final counts and recommendations | ✅ Implemented | Shows files/processes scanned/matched and alert/warning/notice counts at end of scan | ✅ | ✅ Complete | Test summary output |
| **Alert/Warning/Notice Counters** | Tracks counts per level | ✅ Implemented | Counted during scan and displayed in summary | ✅ | ✅ Complete | Test counter accuracy |
| **Log File Timestamp** | `loki_{hostname}_{timestamp}.log` | ⚠️ Partial | No timestamp in filename | P2 | Add timestamp to filename | Test log file naming |
| **Log File Removal** | Removes old log at start | ⚠️ Partial | Appends instead | P2 | Remove old log file | Test log file handling |

---

## Error Handling and Robustness

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Graceful IOC Load Errors** | Logs error, continues or exits gracefully | ✅ Implemented | Replaced `expect()` with Result handling, returns empty vectors on errors | ✅ | ✅ Complete | Test with missing IOC files |
| **Graceful YARA Errors** | Logs error, skips file | ✅ Implemented | Returns Result from compilation, handles scan errors gracefully | ✅ | ✅ Complete | Test with invalid YARA rules |
| **File Access Error Handling** | Logs and continues | ✅ Implemented | Handles errors gracefully | ✅ | ✅ Complete | - |
| **Process Scan Error Handling** | Logs and continues | ✅ Implemented | Handles errors gracefully | ✅ | ✅ Complete | - |
| **Exit Codes** | 0 for success, 1 for errors | ✅ Implemented | Exit 0 for success (no matches), exit 1 for fatal errors, exit 2 for partial success (matches found) | ✅ | ✅ Complete | Test exit code scenarios |
| **Signal Handling (CTRL+C)** | Catches SIGINT, exits gracefully | ❌ Missing | No signal handling | P1 | Add signal handler | Test CTRL+C handling |
| **Argument Validation** | Validates conflicting flags | ❌ Missing | No validation | P1 | Add argument validation | Test invalid flag combinations |

---

## Platform-Specific Features

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Windows Process Enumeration** | WMI for process list | ⚠️ Partial | Uses sysinfo (cross-platform) | P2 | Consider WMI for Windows | Test process enumeration |
| **PE-Sieve Integration** | Windows process analysis tool | ❌ Missing | No PE-Sieve support | Skip | Windows-only, complex dependency | - |
| **Rootkit Check** | Regin filesystem check | ❌ Missing | No rootkit check | Skip | Windows-only, specialized | - |
| **Vulnerability Checks** | Windows vulnerability scanner | ❌ Missing | No vuln checks | Skip | Windows-only, specialized | - |
| **Process Anomaly Checks** | System process validation | ❌ Missing | No anomaly checks | P3 | Low priority, Windows-focused | - |
| **DoublePulsar Check** | Backdoor detection | ❌ Missing | No DoublePulsar check | Skip | Windows-only, specialized | - |
| **Admin/Root Check** | Warns if not admin/root | ❌ Missing | No privilege check | P2 | Add privilege detection | Test privilege warnings |
| **Process Priority** | Sets nice priority | ❌ Missing | No priority setting | P3 | Low priority | - |

---

## Advanced Features

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Levenshtein Distance** | Filename similarity check | ❌ Missing | No Levenshtein check | P3 | Low priority, can be added later | - |
| **Script Analysis** | Statistical obfuscation detection | ❌ Missing | Beta feature in v1 | Skip | Beta feature, can skip | - |
| **Progress Indicator** | File count display | ❌ Missing | No progress display | P3 | Nice to have | - |
| **SWF Decompression** | Decompresses SWF files | ❌ Missing | No archive handling | Skip | Specialized, low usage | - |
| **Memory Dump Scanning** | Special handling for MDMP files | ❌ Missing | No special case | P2 | Add MDMP special handling | Test with memory dumps |

---

## Performance Optimizations

| Feature | Loki v1 Behavior | Loki2 Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Hash Binary Search** | Sorted lists + binary search | ❌ Missing | Linear search | P1 | Implement binary search | Test with large hash sets |
| **File Magic Caching** | Caches max signature length | ❌ Missing | No magic file support | P2 | If adding magic file, cache length | - |
| **YARA Rule Reuse** | Compiled once, reused | ✅ Implemented | Works correctly | ✅ | - | - |

---

## Release Blockers (P0)

These features must be implemented for v1 parity:

1. **Filename IOC Matching** - Core detection feature, currently TODO
2. **Hash Score Parsing** - Currently hardcoded to 100, should default to 75, support 3-column format
3. **Score Thresholds** - Essential for proper alerting (default: 80 alert, 60 warning, 40 notice)
4. **Score Calculation** - Use weighted formula (not simple addition) - see formula below
5. **Exit Codes** - Follow common standards (0 success, non-zero errors)
6. **Error Handling** - Robust recovery - continue scanning even if individual checks fail
7. **Linux Path Exclusions** - Exclude system directories on Linux
8. **YARA Metadata Extraction** - Extract description, author, score, and string matches (hex for non-ASCII)

---

## High Priority (P1)

Important for usability but not blockers:

1. **Hash Binary Search** - Performance issue with large IOC sets
2. **False Positive Hash Support** - Important for accuracy
3. **User Excludes Config** - Common user need
4. **C2 IOC Matching** - Core detection feature
5. **YARA Memory Rules** - Filter process scanning rules
6. **Process Working Set Limit** - Stability for large processes
7. **Result Summary** - User feedback
8. **Alert/Warning/Notice Counters** - User feedback

---

## Can Be Skipped or Deferred

These features can be skipped or have better alternatives:

1. **PE-Sieve Integration** - Windows-only, complex dependency, can skip
2. **Rootkit Check** - Windows-only, specialized, can skip
3. **Vulnerability Checks** - Windows-only, specialized, can skip
4. **DoublePulsar Check** - Windows-only, specialized, can skip
5. **Script Analysis** - Beta feature in v1, can skip
6. **SWF Decompression** - Specialized, low usage, can skip
7. **Levenshtein Distance** - Low priority, can defer
8. **Progress Indicator** - Nice to have, can defer
9. **Syslog Support** - Low usage, can defer to P3

---

## Score Calculation Formula

**Important**: Loki2 will use a **weighted score calculation** instead of simple addition. This is a divergence from Loki v1 but provides better scoring.

### Formula

Given sub-scores (s₀, s₁, s₂, ...) ordered in descending order, the total score is calculated as:

```
score = 100 * (1 - (1 - s₀/100/2⁰) * (1 - s₁/100/2¹) * (1 - s₂/100/2²) * ...)
```

### Properties

- **Maximum score**: Always capped at 100
- **Weighting**: Higher scores weighted more heavily
- **Multiple matches**: Lower scores contribute less to total
- **Ordering**: Sub-scores must be sorted descending before calculation

### Example

Python calculation with 5 sub-scores (none exceeding 75):

```python
subscore0 = 1 - 70 / 100 / pow(2, 0)  # = 0.3
subscore1 = 1 - 70 / 100 / pow(2, 1)  # = 0.65
subscore2 = 1 - 50 / 100 / pow(2, 2)  # = 0.875
subscore3 = 1 - 40 / 100 / pow(2, 3)  # = 0.95
subscore4 = 1 - 40 / 100 / pow(2, 4)  # = 0.975
score = 100 * (1 - (0.3 * 0.65 * 0.875 * 0.95 * 0.975))
# score = 84.195859375
```

### Implementation Notes

- Sub-scores are called "reasons" in the output
- Only positive scores are included
- Top N reasons shown (default: 2, configurable via `--max-reasons`)
- Each reason shows its sub-score
- Total score is the calculated weighted score

### Default Thresholds

- **Alert**: ≥ 80
- **Warning**: ≥ 60
- **Notice**: ≥ 40

---

## Implementation Notes

### Better Approaches in Loki2

Some features in Loki2 may be implemented differently (and better) than v1:

1. **File Format Detection**: Using `file-format` crate instead of custom magic file - **Keep this approach**
2. **Process Enumeration**: Using `sysinfo` (cross-platform) instead of WMI - **Keep this approach**
3. **Logging**: Using `flexi_logger` instead of custom logger - **Keep but enhance**
4. **CLI Parsing**: Using `rustop` instead of argparse - **Keep this approach**

### Divergences from v1 (Intentional)

1. **Score Calculation**: v1 uses simple addition, v2 uses weighted formula - **Better approach, caps at 100**
2. **Hash Default Score**: v1 uses 100, v2 uses 75 - **More conservative default**

### Divergences to Fix

1. **Symlink Following**: v1 doesn't follow, v2 does - **Should match v1**
2. **File Size Units**: v1 uses KB, v2 uses bytes - **Add KB option, keep bytes**
3. **Log File Naming**: v1 has timestamp, v2 doesn't - **Add timestamp**
4. **Hash Search**: v1 uses binary search, v2 linear - **Should optimize**

---

## Test Strategy

### Unit Tests Needed

1. Hash IOC parsing (2 and 3 column formats)
2. Filename IOC regex compilation and matching
3. Score threshold filtering
4. YARA metadata extraction
5. Exit code scenarios

### Integration Tests Needed

1. End-to-end scan with sample files
2. IOC file loading and matching
3. YARA rule compilation and scanning
4. Error handling with invalid inputs
5. Platform-specific path exclusions

### Golden Tests (v1 vs v2)

1. Run both on same test dataset
2. Compare detected hits count
3. Compare output formats
4. Compare exit codes
5. Compare performance

---

## Next Steps

### Phase 1: Critical Fixes (P0)

1. **Error Handling**:
   - Replace all `expect()` and `unwrap()` with Result handling
   - Ensure scanner continues even if individual checks fail
   - Log errors but don't panic

2. **Hash Score Parsing**:
   - Default score: 75 (not 100)
   - Support 2-column format: `hash;description` (score = 75)
   - Support 3-column format: `hash;score;description` (use provided score)
   - Handle integer parsing errors gracefully

3. **Score Calculation**:
   - Implement weighted score formula
   - Sort sub-scores descending
   - Calculate total score using formula
   - Display sub-scores as "reasons"

4. **Score Thresholds**:
   - Default: Alert ≥ 80, Warning ≥ 60, Notice ≥ 40
   - Add CLI flags: `-a`, `-w`, `-n` (configurable)
   - Filter output by threshold
   - Add `--max-reasons` flag (default: 2)

5. **Exit Codes**:
   - 0: Success (scan completed)
   - 1: Error (invalid arguments, missing signatures, fatal errors)
   - 2: Partial success (some errors but scan continued)
   - Consider: Signal handling (CTRL+C) → exit 0

6. **Filename IOC Matching**:
   - Compile regex patterns
   - Match against full file path
   - Handle false positive regex (3rd column)
   - Apply environment variable replacement

7. **Linux Path Exclusions**:
   - Exclude: `/proc`, `/dev`, `/sys/kernel/debug`, `/sys/kernel/slab`, `/sys/devices`, `/usr/src/linux`
   - Exclude: `/media`, `/volumes` (unless `--scan-all-drives`)
   - Exclude: `/initctl` (end of path)

8. **YARA Metadata Extraction**:
   - Extract: `description`, `author`, `score` from rule metadata
   - Extract matched strings with offsets
   - Hex-encode non-ASCII strings
   - Display in match output

### Phase 2: Core Features (P1)

1. **Hash Binary Search**: Optimize for large IOC sets
2. **False Positive Hash Support**: Load and check before matching
3. **User Excludes Config**: Load `config/excludes.cfg`
4. **C2 IOC Matching**: Load and match process connections
5. **Result Summary**: Final counts and recommendations
6. **Counters**: Track alerts/warnings/notices

### Phase 3: Enhancements (P2-P3)

1. **CLI Flags**: Add missing flags (`-l`, `--logfolder`, `--nolog`, etc.)
2. **Output Formatting**: Enhanced console output
3. **Log File**: Add timestamp to filename
4. **Progress Indicator**: File count display
5. **Platform Features**: Windows drive handling, admin checks

