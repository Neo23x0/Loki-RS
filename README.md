![Loki RS Logo](./images/loki-logo.png)

# Loki-RS

A rewrite of [Loki](https://github.com/Neo23x0/Loki) in Rust. Single binary, fast, and straightforward IOC and YARA scanning.

**Status**: Beta. Works, but still under active development.

## Features

- YARA scanning of files and process memory
- IOC matching (MD5/SHA1/SHA256 hashes, filename patterns, C2 indicators)
- Multi-threaded scanning with configurable thread count
- Archive scanning (ZIP files)
- Interactive TUI with real-time stats and controls
- Remote logging via syslog (UDP/TCP) (SYSLOG/JSON)
- Configurable scoring thresholds
- Smart filtering (skips /proc, /sys, mounted drives by default)
- Magic header detection for executables
- JSONL output for log ingestion

## Installation

Download the pre-compiled binary for your platform from the [Releases Page](https://github.com/Neo23x0/Loki-RS/releases).

```bash
# Extract
tar -xzvf loki-linux-*.tar.gz
cd loki-linux-*

# Update signatures (recommended)
./loki-util update

# Run
sudo ./loki --help
```

Signatures ship with the release but get stale quickly. Run `loki-util update` to fetch the latest IOCs and YARA rules.

## Signatures

Loki-RS uses detection content from two sources:

**IOCs** are pulled from [signature-base](https://github.com/Neo23x0/signature-base), a collection of hash, filename, and C2 indicators maintained alongside Loki.

**YARA rules** come from [YARA Forge](https://yaraforge.com/), which aggregates and quality-checks rules from public repositories. Loki-RS uses the **Core** rule set - high accuracy, low false positives, optimized for performance. If you need broader coverage, you can swap in the Extended or Full sets from YARA Forge.

## Usage

```bash
# Basic scan
sudo ./loki

# Scan specific folder
sudo ./loki --folder /tmp

# Launch TUI
sudo ./loki --tui
```

## Common Scenarios

```bash
# Scan a mounted image (skip process scanning, use all cores)
sudo ./loki --noprocs --folder ~/image1 --threads 0

# Slow and cautious scan (lower CPU limit, single thread)
sudo ./loki --cpu-limit 60 --threads 1

# Scan and send logs to remote syslog
sudo ./loki --remote syslog-host.internal:514 --remote-proto udp
```

## Command Line Options

### Scan Target
| Option | Default | Description |
|--------|---------|-------------|
| `-f, --folder <PATH>` | `/` | Folder to scan |

### Scan Control
| Option | Default | Description |
|--------|---------|-------------|
| `--noprocs` | `false` | Skip process memory scanning |
| `--nofs` | `false` | Skip filesystem scanning |
| `--noarchives` | `false` | Skip scanning inside archives (ZIP) |
| `--scan-all-drives` | `false` | Scan all drives including mounted/network/cloud |
| `--scan-all-files` | `false` | Scan all files regardless of extension/type |

### Output Options
| Option | Default | Description |
|--------|---------|-------------|
| `-l, --log <FILE>` | auto | Plain text log file |
| `--nolog` | `false` | Disable plaintext log output |
| `-j, --jsonl <FILE>` | auto | JSONL output file |
| `--no-jsonl` | `false` | Disable JSONL output |
| `-r, --remote <HOST:PORT>` | none | Remote syslog destination |
| `-p, --remote-proto <PROTO>` | `udp` | Remote protocol (udp/tcp) |
| `--remote-format <FMT>` | `syslog` | Remote format (syslog/json) |

### Tuning
| Option | Default | Description |
|--------|---------|-------------|
| `--alert-level <SCORE>` | `80` | Score threshold for ALERT |
| `--warning-level <SCORE>` | `60` | Score threshold for WARNING |
| `--notice-level <SCORE>` | `40` | Score threshold for NOTICE |
| `--max-reasons <NUM>` | `2` | Max match reasons to display per finding |
| `-m, --max-file-size <BYTES>` | `64000000` | Maximum file size to scan (64MB) |
| `-c, --cpu-limit <PERCENT>` | `100` | CPU utilization limit (1-100) |
| `--threads <NUM>` | `-2` | Number of threads (0=all, -1=all-1, -2=all-2) |

### Info & Debug
| Option | Default | Description |
|--------|---------|-------------|
| `--version` | - | Show version and exit |
| `-d, --debug` | `false` | Show debug output |
| `--trace` | `false` | Show verbose trace output |
| `--show-access-errors` | `false` | Show file/process access errors |
| `--tui` | `false` | Launch interactive TUI mode |

## TUI Mode

The terminal interface provides real-time monitoring during scans.

```bash
sudo ./loki --tui --folder /path/to/scan
```

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume |
| `s` | Skip current items |
| `t` | Toggle thread overlay |
| `+` / `-` | Adjust CPU limit |
| Arrow keys | Scroll logs |

![Loki TUI Screenshot](./images/loki-tui-1.png)

## Building from Source

```bash
git clone https://github.com/Neo23x0/Loki-RS.git
cd Loki-RS
cargo build --release
./target/release/loki-util update
sudo ./target/release/loki
```

Requires Rust toolchain. See [docs/BUILD.md](docs/BUILD.md) for cross-compilation.

## Documentation

- [Build Guide](docs/BUILD.md)
- [Score Calculation](docs/score_calculation.md)
- [Parity Matrix](docs/parity_matrix.md)

## About

A side project. For enterprise-grade scanning with extensive features and support, check out [THOR](https://www.nextron-systems.com/) from Nextron Systems.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).

Copyright (c) 2025 Florian Roth
