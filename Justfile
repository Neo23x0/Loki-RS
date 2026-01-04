# LOKI2 Build System - Justfile
# Modern command runner alternative to Makefile
# Install: cargo install just
# Usage: just <command>

# Default recipe
default:
    @just --list

# Build the release binary
build:
    #!/usr/bin/env bash
    echo "[!] The build has a bunch of dependencies"
    echo "[i] For information on how to fulfill these prerequisites see the workflow file in .github/workflows/"
    echo "[+] Building LOKI release version ..."
    if [[ "$(uname -s)" == "Linux" ]]; then
        cargo build --release --target x86_64-unknown-linux-musl
        echo "[+] Binary location: target/x86_64-unknown-linux-musl/release/loki"
    else
        cargo build --release
        echo "[+] Binary location: target/release/loki"
    fi
    echo "[+] Build successful!"

# Create a complete build package
package: build install-signatures
    #!/usr/bin/env bash
    echo "[+] Creating build package ..."
    mkdir -p build/signatures build/config
    
    # Copy binary
    if [[ "$(uname -s)" == "Linux" ]]; then
        cp target/x86_64-unknown-linux-musl/release/loki build/loki
    else
        cp target/release/loki build/loki
    fi
    chmod +x build/loki
    echo "[+] Binary copied to build/loki"
    
    # Copy usage guide
    if [ -f USAGE.md ]; then
        cp USAGE.md build/
    else
        echo "# LOKI2 Usage Guide" > build/USAGE.md
        echo "" >> build/USAGE.md
        echo "See README.md for usage instructions." >> build/USAGE.md
    fi
    
    # Copy config
    if [ -f config/excludes.cfg.example ]; then
        cp config/excludes.cfg.example build/config/excludes.cfg
    else
        echo "# LOKI2 Exclusions Configuration" > build/config/excludes.cfg
    fi
    
    # Copy LICENSE
    [ -f LICENSE ] && cp LICENSE build/ || true
    
    echo ""
    echo "[✓] Build package created successfully!"
    echo "[✓] Package location: build/"
    echo "[✓] Binary: build/loki"
    echo "[✓] Signatures: build/signatures/"
    echo "[✓] Config: build/config/"
    echo "[✓] Usage guide: build/USAGE.md"

# Install or link signatures
install-signatures:
    #!/usr/bin/env bash
    echo "[+] Setting up signatures ..."
    mkdir -p build/signatures
    
    if [ -d "./signatures" ] || [ -L "./signatures" ]; then
        echo "[+] Found signatures, copying ..."
        cp -rL ./signatures/* build/signatures/ 2>/dev/null || true
    else
        echo "[!] No local signatures found."
        echo "    You can:"
        echo "    1. Clone: git clone https://github.com/Neo23x0/signature-base ../signature-base/"
        echo "    2. Link: ln -s ../signature-base/ ./signatures"
        echo "    3. Or manually copy to build/signatures/"
        mkdir -p build/signatures/yara build/signatures/iocs
        echo "# Place YARA rules (.yar files) here" > build/signatures/yara/README.txt
        echo "# Place IOC files here" > build/signatures/iocs/README.txt
    fi
    echo "[+] Signatures setup complete"

# Clean build artifacts
clean:
    #!/usr/bin/env bash
    echo "[+] Cleaning up ..."
    rm -rf target dist tmp build
    echo "[+] Clean complete"

# Clean only build directory
clean-build:
    #!/usr/bin/env bash
    echo "[+] Cleaning build directory ..."
    rm -rf build
    echo "[+] Build directory cleaned"

# Show help
help:
    @just --list


