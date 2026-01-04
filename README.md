# Loki-RS

**Loki-RS** is a complete rewrite of the popular [Loki IOC and YARA Scanner](https://github.com/Neo23x0/Loki) in Rust. It is designed for performance, reliability, and ease of deployment, providing a single-binary solution for scanning systems for Indicators of Compromise (IOCs).

> **Status**: ⚠️ Alpha (v2.0.2). Active development. Not yet ready for production use.

## 🚀 Features

*   **High Performance**: Written in Rust for speed and memory safety.
*   **IOC Scanning**:
    *   **File Names**: Regex-based pattern matching on full file paths.
    *   **Hashes**: MD5, SHA1, and SHA256 scanning with optimized binary search.
    *   **C2 Connections**: Detects active network connections to known C2 servers (IP/Domain).
*   **YARA Scanning**:
    *   **File Content**: Scans files using compiled YARA rules.
    *   **Process Memory**: Scans memory of running processes (currently Linux-focused).
*   **Smart Filtering**:
    *   Skips system directories (e.g., `/proc`, `/sys`) and mounted drives by default.
    *   Ignores known false positives defined in signature sets.
    *   Checks file magic headers to identify executables even with wrong extensions.
*   **Scoring System**:
    *   Weighted scoring algorithm to prioritize relevant matches.
    *   Configurable thresholds for Alerts, Warnings, and Notices.

## 📥 Installation (Recommended)

The easiest way to use Loki-RS is to download the pre-compiled binary for your platform.

### 1. Download Release

Go to the [Releases Page](https://github.com/Neo23x0/Loki-RS/releases) and download the archive for your operating system:

*   **Linux**: `loki-linux-x86_64-vX.Y.Z.tar.gz` (or `aarch64` for ARM)
*   **Windows**: `loki-windows-x86_64-vX.Y.Z.zip`
*   **macOS**: `loki-macos-x86_64-vX.Y.Z.tar.gz` (or `aarch64` for Apple Silicon)

### 2. Setup Signatures

The release packages contain a set of signatures (IOCs and YARA rules) at the time of the release. However, **these signatures are likely outdated** by the time you download and extract the package.

We strongly encourage you to update the signatures immediately after extraction using the included `loki-util` tool.

```bash
# Extract the binary
tar -xzvf loki-linux-*.tar.gz
cd loki-linux-*

# Update signatures to the latest version
./loki-util update
```

This will download the latest IOCs and YARA rules into the `signatures/` directory.

### 3. Run

```bash
# Linux/macOS (requires root for full capabilities)
sudo ./loki --help

# Windows (Run as Administrator)
loki.exe --help
```

## 🛠️ Loki Util

The release package includes a utility tool named `loki-util` (or `loki-util.exe` on Windows) to help manage the installation.

### Commands

*   `update`: Updates the local signature base (IOCs and YARA rules) by downloading the latest versions from the repository.
    ```bash
    ./loki-util update
    ```
    *Note: Ensure you have internet access for this command to work.*

*   `upgrade`: Performs a full self-update (source build) if running from a git repository. (Not applicable for release binaries).

## 💻 Usage

### Common Commands

```bash
# Basic scan of the system (default behavior)
sudo ./loki

# Scan a specific folder
sudo ./loki --folder /tmp

# Scan with debug output
sudo ./loki --debug

# output logs to a JSONL file
sudo ./loki --jsonl scan_results.jsonl
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--folder <PATH>` | `/` | Folder to scan. |
| `--max-file-size <BYTES>` | `10000000` | Maximum file size to scan (10MB). |
| `--scan-all-files` | `false` | Scan all files regardless of extension/type. |
| `--scan-all-drives` | `false` | Scan all drives including mounted/network/cloud. |
| `--noprocs` | `false` | Skip process memory scanning. |
| `--nofs` | `false` | Skip filesystem scanning. |
| `--show-access-errors` | `false` | Show errors when accessing files/processes. |
| `--alert-level <SCORE>` | `80` | Score threshold for ALERT. |
| `--warning-level <SCORE>` | `60` | Score threshold for WARNING. |
| `--notice-level <SCORE>` | `40` | Score threshold for NOTICE. |
| `--max-reasons <NUM>` | `2` | Max number of match reasons to display per hit. |
| `--jsonl <FILE>` | `None` | Enable structured JSONL logging to file. |
| `--debug` | `false` | Show debug information. |
| `--trace` | `false` | Show verbose trace output. |
| `--version` | `false` | Show version and exit. |

## 📊 Scoring & Output

Loki-RS uses a weighted scoring system. Matches (YARA rules, IOCs) contribute to a total score for each file or process.

*   **ALERT** (Score ≥ 80): High probability of malicious activity.
*   **WARNING** (Score ≥ 60): Suspicious elements found.
*   **NOTICE** (Score ≥ 40): Interesting characteristics or low-confidence matches.

See [docs/score_calculation.md](docs/score_calculation.md) for details on the algorithm.

## 🛠️ Development / Build from Source

If you want to contribute or build the latest version yourself:

### Requirements
*   Rust toolchain (`rustc`, `cargo`)
*   Git

### Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/Neo23x0/Loki-RS.git
cd Loki-RS

# 2. Get signatures
git clone https://github.com/Neo23x0/signature-base signatures

# 3. Build for release
cargo build --release

# 4. Run
sudo ./target/release/loki
```

For detailed build instructions, including cross-compilation, see [docs/BUILD.md](docs/BUILD.md).

## 📂 Documentation

*   [Build Guide](docs/BUILD.md): Detailed build steps for all platforms.
*   [Score Calculation](docs/score_calculation.md): Explanation of the scoring formula.
*   [Parity Matrix](docs/parity_matrix.md): Comparison with Loki v1.

## ⚖️ License

Loki-RS is open-source software licensed under the [GNU General Public License v3.0](LICENSE).

Copyright (c) 2025 Florian Roth
