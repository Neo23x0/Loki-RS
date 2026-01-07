# Loki-RS Build Guide

This guide provides step-by-step instructions for building Loki-RS on different platforms.

## Table of Contents

- [Linux Build](#linux-build)
- [Cross-Platform Build](#cross-platform-build)
- [Windows Build](#windows-build)
- [macOS Build](#macos-build)
- [Release Builds](#release-builds)
- [Troubleshooting](#troubleshooting)

---

## Linux Build

### Prerequisites

#### Required Tools

1. **Rust Toolchain**
   ```bash
   # Install Rust using rustup (recommended)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   
   # Verify installation
   rustc --version
   cargo --version
   ```

2. **System Dependencies**
   ```bash
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y build-essential pkg-config libssl-dev
   
   # Fedora/RHEL/CentOS
   sudo dnf install -y gcc openssl-devel
   
   # Arch Linux
   sudo pacman -S base-devel openssl
   ```

#### Optional: Development Tools

```bash
# Install clippy (linter) and rustfmt (formatter)
rustup component add clippy rustfmt

# Install cargo-audit (security audit)
cargo install cargo-audit
```

### Build Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Neo23x0/Loki-RS.git
   cd Loki-RS
   ```

2. **Build Release Version**
   ```bash
   cargo build --release
   ```
   Main binary: `target/release/loki`
   Utility binary: `target/release/loki-util`

3. **Fetch Signatures**
   ```bash
   ./target/release/loki-util update
   ```
   This downloads the latest signatures to `./signatures`.

4. **Build Debug Version** (Optional)
   ```bash
   cargo build
   ```
   Binary will be at: `target/debug/loki`

5. **Run Tests**
   ```bash
   cargo test
   ```

6. **Code Quality Checks**
   ```bash
   # Format code
   cargo fmt
   
   # Lint code
   cargo clippy
   
   # Security audit
   cargo audit
   ```

### Build Output

- **Debug build**: `target/debug/loki` (~10-20 MB, unoptimized, with debug symbols)
- **Release build**: `target/release/loki` (~5-10 MB, optimized, stripped)

---

## Cross-Platform Build

### Prerequisites

1. **Install Rust Cross-Compilation Targets**
   ```bash
   # Add target for Windows (x86_64)
   rustup target add x86_64-pc-windows-gnu
   
   # Add target for macOS (x86_64)
   rustup target add x86_64-apple-darwin
   
   # Add target for macOS (ARM64/Apple Silicon)
   rustup target add aarch64-apple-darwin
   
   # Add target for Linux (ARM64)
   rustup target add aarch64-unknown-linux-gnu
   ```

2. **Install Cross-Compilation Tools**

   **For Windows builds:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -y mingw-w64
   
   # Fedora
   sudo dnf install -y mingw64-gcc
   
   # Arch Linux
   sudo pacman -S mingw-w64-gcc
   ```

   **For macOS builds:**
   - Requires macOS SDK (only available on macOS)
   - Or use `osxcross` (complex setup)

   **For Linux ARM builds:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -y gcc-aarch64-linux-gnu
   
   # Fedora
   sudo dnf install -y gcc-aarch64-linux-gnu
   ```

### Build Commands

```bash
# Build for Windows (from Linux)
cargo build --release --target x86_64-pc-windows-gnu

# Build for macOS x86_64 (from macOS)
cargo build --release --target x86_64-apple-darwin

# Build for macOS ARM64 (from macOS)
cargo build --release --target aarch64-apple-darwin

# Build for Linux ARM64
cargo build --release --target aarch64-unknown-linux-gnu
```

### Cross-Compilation Notes

- **Windows**: Requires `mingw-w64` toolchain. Some crates may have issues with Windows-specific features.
- **macOS**: Cross-compilation from Linux is complex. Best done on macOS itself or using CI/CD.
- **ARM**: Requires appropriate cross-compiler toolchain.

---

## Windows Build

### Prerequisites

1. **Install Rust**
   - Download and run: https://rustup.rs/
   - Or use: `winget install Rustlang.Rustup`

2. **Install Visual Studio Build Tools**
   - Download: https://visualstudio.microsoft.com/downloads/
   - Install "Desktop development with C++" workload
   - Or install "Build Tools for Visual Studio"

3. **Install Git**
   - Download: https://git-scm.com/download/win

### Build Steps

1. **Open Developer Command Prompt**
   - Start Menu → Visual Studio → Developer Command Prompt
   - Or use PowerShell/CMD with Visual Studio environment

2. **Clone and Build**
   ```cmd
   git clone https://github.com/Neo23x0/Loki-RS.git
   cd Loki-RS
   cargo build --release
   ```

3. **Binary Location**
   ```
   target\release\loki.exe
   ```

### Alternative: Using WSL

If you have Windows Subsystem for Linux (WSL):

```bash
# In WSL
sudo apt-get update
sudo apt-get install -y build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cd /mnt/c/path/to/Loki-RS
cargo build --release
```

---

## macOS Build

### Prerequisites

1. **Install Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

2. **Install Rust**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. **Install Homebrew** (optional, for additional tools)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

### Build Steps

```bash
# Clone repository
git clone https://github.com/Neo23x0/Loki-RS.git
cd Loki-RS

# Build release
cargo build --release

# Binary location
./target/release/loki
```

### Apple Silicon (M1/M2/M3) Notes

- Rust automatically detects ARM64 architecture
- No special configuration needed
- Use `aarch64-apple-darwin` target if explicitly needed:
  ```bash
  cargo build --release --target aarch64-apple-darwin
  ```

---

## Release Builds

### Creating Release Binaries

1. **Clean Build**
   ```bash
   cargo clean
   cargo build --release
   ```

2. **Strip Binary** (reduce size)
   ```bash
   # Linux
   strip target/release/loki
   
   # macOS
   strip target/release/loki
   
   # Windows (using strip from MinGW or Visual Studio)
   strip target/release/loki.exe
   ```

3. **Verify Binary**
   ```bash
   # Check binary info
   file target/release/loki
   
   # Test run
   ./target/release/loki --version
   ```

### Release Package Structure

For distribution, create a package with:

```
loki-release-v2.0.0/
├── loki (or loki.exe)
├── README.md
├── LICENSE
└── signatures/
    ├── yara/     (YARA rules from YARA Forge)
    └── iocs/     (IOC files from signature-base)
```

### Automated Release Builds

See `.github/workflows/release.yml` for automated release builds on Git tags.

---

## Troubleshooting

### Common Issues

#### 1. "linker `cc` not found"

**Solution:**
```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Fedora
sudo dnf install gcc

# macOS
xcode-select --install
```

#### 2. "OpenSSL not found"

**Solution:**
```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev pkg-config

# Fedora
sudo dnf install openssl-devel

# macOS (with Homebrew)
brew install openssl
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
```

#### 3. "Permission denied" when running binary

**Solution:**
```bash
chmod +x target/release/loki
```

#### 4. "Signatures not found"

**Solution:**
```bash
# Use loki-util to download signatures
./loki-util update

# Or manually create structure and download
mkdir -p ./signatures/yara ./signatures/iocs
# Download YARA rules from YARA Forge and IOCs from signature-base
```

#### 5. Build fails with "out of memory"

**Solution:**
- Use `cargo build --release` (release builds use less memory)
- Increase swap space
- Build on a machine with more RAM

#### 6. Cross-compilation fails

**Solution:**
- Ensure all cross-compilation toolchains are installed
- Check `.cargo/config.toml` for target-specific settings
- Some crates may not support all targets

### Getting Help

- Check [Rust Installation Guide](https://www.rust-lang.org/tools/install)
- Review [Cargo Book](https://doc.rust-lang.org/cargo/)
- Check crate-specific documentation for dependencies
- Open an issue on GitHub with:
  - OS and version
  - Rust version (`rustc --version`)
  - Full error message
  - Build command used

---

## Build Configuration

### Environment Variables

- `RUSTFLAGS`: Additional flags for rustc
  ```bash
  export RUSTFLAGS="-C target-cpu=native"  # Optimize for current CPU
  ```

- `CARGO_TARGET_DIR`: Custom target directory
  ```bash
  export CARGO_TARGET_DIR=/custom/path
  ```

### Cargo Configuration

Create `.cargo/config.toml` for project-specific settings:

```toml
[build]
# Use specific linker
target = "x86_64-unknown-linux-gnu"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

---

## Performance Tips

1. **Use Release Builds**: Always use `--release` for production
2. **Enable LTO**: Add to `Cargo.toml`:
   ```toml
   [profile.release]
   lto = true
   ```
3. **Optimize for Size**: Add to `Cargo.toml`:
   ```toml
   [profile.release]
   opt-level = "z"  # Optimize for size
   ```
4. **Parallel Compilation**: Cargo uses all CPU cores by default

---

## Next Steps

After building:

1. Run tests: `cargo test`
2. Check code quality: `cargo clippy`
3. Format code: `cargo fmt`
4. Review [README.md](../README.md) for usage instructions


