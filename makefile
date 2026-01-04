# LOKI2 Build System
# Enhanced Makefile for building and packaging LOKI2

.DEFAULT_GOAL := help

# Detect OS and set appropriate flags
OSFLAG :=
BINARY_NAME := loki
BUILD_DIR := build
SIGNATURES_DIR := $(BUILD_DIR)/signatures
CONFIG_DIR := $(BUILD_DIR)/config

ifeq ($(OS),Windows_NT)
	# LOKI2 can't be built on Windows!
	# For information on how to build LOKI2 for Windows see the workflow file in .github/workflows/build-linux-to-win.yml
	$(error LOKI2 cannot be built natively on Windows. Use cross-compilation from Linux.)
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		OSFLAG += --target x86_64-unknown-linux-musl
		BINARY_PATH := target/x86_64-unknown-linux-musl/release/$(BINARY_NAME)
	endif
	ifeq ($(UNAME_S),Darwin)
		BINARY_PATH := target/release/$(BINARY_NAME)
	endif
endif

.PHONY: help build clean package install-signatures

help: ## Show this help message
	@echo "LOKI2 Build System"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          - Build the release binary"
	@echo "  make package        - Create a complete build package"
	@echo "  make clean          - Clean build artifacts"

build: ## Build LOKI release version (both loki and loki-util)
	@echo "[!] The build has a bunch of dependencies"
	@echo "[i] For information on how to fulfill these prerequisites see the workflow file in .github/workflows/"
	@echo "[+] Building LOKI release version ..."
	@USE_MUSL=""; \
	if [ "$(OSFLAG)" != "" ]; then \
		if command -v rustup >/dev/null 2>&1; then \
			if rustup target list --installed 2>/dev/null | grep -q "x86_64-unknown-linux-musl"; then \
				USE_MUSL="$(OSFLAG)"; \
				echo "[+] Using musl target for static binary"; \
			else \
				echo "[!] musl target not installed. Installing..."; \
				if rustup target add x86_64-unknown-linux-musl 2>/dev/null; then \
					USE_MUSL="$(OSFLAG)"; \
					echo "[+] musl target installed successfully"; \
				else \
					echo "[!] Could not install musl target. Building without it..."; \
				fi; \
			fi; \
		else \
			echo "[!] rustup not found. Building without musl target (dynamic binary)"; \
		fi; \
	fi; \
	cargo build --release $$USE_MUSL --bin loki --bin loki-util || (echo "[!] Build with musl target failed, trying without target..." && cargo build --release --bin loki --bin loki-util)
	@if [ -f "$(BINARY_PATH)" ]; then \
		echo "[+] Build successful!"; \
		echo "[+] Binary location: $(BINARY_PATH)"; \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		echo "[+] Build successful!"; \
		echo "[+] Binary location: target/release/$(BINARY_NAME)"; \
		BINARY_PATH="target/release/$(BINARY_NAME)"; \
	else \
		echo "[!] Build failed or binary not found"; \
		exit 1; \
	fi
	@if [ -f "target/release/loki-util" ] || [ -f "target/x86_64-unknown-linux-musl/release/loki-util" ]; then \
		echo "[+] loki-util binary built successfully"; \
	fi

package: build fetch-signatures install-signatures ## Create a complete build package with binary, signatures, config, and usage guide
	@echo "[+] Creating build package ..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(SIGNATURES_DIR)
	@mkdir -p $(CONFIG_DIR)
	@echo "[+] Copying binaries to $(BUILD_DIR)/ ..."
	@if [ -f "$(BINARY_PATH)" ]; then \
		cp $(BINARY_PATH) $(BUILD_DIR)/$(BINARY_NAME); \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		cp target/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME); \
	else \
		echo "[!] Binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@chmod +x $(BUILD_DIR)/$(BINARY_NAME)
	@if [ -f "target/release/loki-util" ]; then \
		cp target/release/loki-util $(BUILD_DIR)/loki-util; \
		chmod +x $(BUILD_DIR)/loki-util; \
	elif [ -f "target/x86_64-unknown-linux-musl/release/loki-util" ]; then \
		cp target/x86_64-unknown-linux-musl/release/loki-util $(BUILD_DIR)/loki-util; \
		chmod +x $(BUILD_DIR)/loki-util; \
	fi
	@echo "[+] Creating usage guide ..."
	@cp USAGE.md $(BUILD_DIR)/ 2>/dev/null || echo "[!] USAGE.md not found, creating from template..."
	@test -f $(BUILD_DIR)/USAGE.md || echo "# LOKI2 Usage Guide\n\nSee README.md for usage instructions." > $(BUILD_DIR)/USAGE.md
	@echo "[+] Creating config files ..."
	@test -f $(CONFIG_DIR)/excludes.cfg || cp config/excludes.cfg.example $(CONFIG_DIR)/excludes.cfg 2>/dev/null || echo "# LOKI2 Exclusions Configuration\n# Add regex patterns here, one per line\n# Example: ^/proc/.*" > $(CONFIG_DIR)/excludes.cfg
	@echo "[+] Copying LICENSE ..."
	@cp LICENSE $(BUILD_DIR)/ 2>/dev/null || echo "[!] LICENSE not found"
	@echo ""
	@echo ""
	@echo "[✓] Build package created successfully!"
	@echo "[✓] Package location: $(BUILD_DIR)/"
	@echo "[✓] Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@if [ -f "$(BUILD_DIR)/loki-util" ]; then \
		echo "[✓] Utility: $(BUILD_DIR)/loki-util"; \
	fi
	@echo "[✓] Signatures: $(SIGNATURES_DIR)/"
	@echo "[✓] Config: $(CONFIG_DIR)/"
	@echo "[✓] Usage guide: $(BUILD_DIR)/USAGE.md"

fetch-signatures: ## Fetch IOCs and YARA signatures from remote repositories
	@echo "[+] Fetching signatures from remote repositories ..."
	@mkdir -p ./signatures/iocs
	@mkdir -p ./signatures/yara
	@mkdir -p ./tmp
	@echo "[+] Downloading IOCs from signature-base ..."
	@if command -v wget >/dev/null 2>&1; then \
		wget -q https://github.com/Neo23x0/signature-base/archive/master.tar.gz -O ./tmp/signature-base.tar.gz && \
		tar -xzf ./tmp/signature-base.tar.gz -C ./tmp && \
		cp -r ./tmp/signature-base-master/iocs/* ./signatures/iocs/ 2>/dev/null || true; \
	elif command -v curl >/dev/null 2>&1; then \
		curl -sL https://github.com/Neo23x0/signature-base/archive/master.tar.gz -o ./tmp/signature-base.tar.gz && \
		tar -xzf ./tmp/signature-base.tar.gz -C ./tmp && \
		cp -r ./tmp/signature-base-master/iocs/* ./signatures/iocs/ 2>/dev/null || true; \
	else \
		echo "[!] Neither wget nor curl found. Skipping IOC download."; \
	fi
	@echo "[+] Downloading YARA rules from yara-forge ..."
	@if command -v wget >/dev/null 2>&1; then \
		wget -q https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip -O ./tmp/yara-forge-rules-core.zip && \
		unzip -q -o ./tmp/yara-forge-rules-core.zip -d ./tmp/yara-forge 2>/dev/null || true && \
		find ./tmp/yara-forge -name "*.yar" -exec cp {} ./signatures/yara/ \; 2>/dev/null || true; \
	elif command -v curl >/dev/null 2>&1; then \
		curl -sL https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip -o ./tmp/yara-forge-rules-core.zip && \
		unzip -q -o ./tmp/yara-forge-rules-core.zip -d ./tmp/yara-forge 2>/dev/null || true && \
		find ./tmp/yara-forge -name "*.yar" -exec cp {} ./signatures/yara/ \; 2>/dev/null || true; \
	else \
		echo "[!] Neither wget nor curl found. Skipping YARA rules download."; \
	fi
	@rm -rf ./tmp
	@echo "[+] Signatures fetched successfully"

install-signatures: ## Install or link signature-base to build directory
	@echo "[+] Setting up signatures ..."
	@mkdir -p $(SIGNATURES_DIR)
	@if [ -d "./signatures" ]; then \
		echo "[+] Found local signatures directory, copying ..."; \
		cp -r ./signatures/* $(SIGNATURES_DIR)/ 2>/dev/null || true; \
	elif [ -L "./signatures" ]; then \
		echo "[+] Found signature symlink, following ..."; \
		cp -rL ./signatures/* $(SIGNATURES_DIR)/ 2>/dev/null || true; \
	else \
		echo "[!] No local signatures found. Run 'make fetch-signatures' to download them."; \
		echo "[+] Creating placeholder structure ..."; \
		mkdir -p $(SIGNATURES_DIR)/yara; \
		mkdir -p $(SIGNATURES_DIR)/iocs; \
		echo "# Place YARA rules (.yar files) in this directory" > $(SIGNATURES_DIR)/yara/README.txt; \
		echo "# Place IOC files in this directory" > $(SIGNATURES_DIR)/iocs/README.txt; \
	fi
	@echo "[+] Signatures setup complete"

dist: build fetch-signatures ## Create distribution package (downloads signatures from GitHub)
	@echo "[+] Creating distribution package ..."
	@mkdir -p ./dist/loki/signatures
	@mkdir -p ./tmp
	@echo "[+] Copying binaries ..."
	@if [ -f "$(BINARY_PATH)" ]; then \
		cp $(BINARY_PATH) ./dist/loki/$(BINARY_NAME); \
	elif [ -f "target/release/$(BINARY_NAME)" ]; then \
		cp target/release/$(BINARY_NAME) ./dist/loki/$(BINARY_NAME); \
	else \
		echo "[!] Binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@chmod +x ./dist/loki/$(BINARY_NAME)
	@if [ -f "target/release/loki-util" ]; then \
		cp target/release/loki-util ./dist/loki/loki-util; \
		chmod +x ./dist/loki/loki-util; \
		echo "[+] Copied loki-util binary"; \
	fi
	@echo "[+] Copying signatures to ./dist/loki/signatures ..."
	@cp -r ./signatures/yara ./dist/loki/signatures/ 2>/dev/null || true
	@cp -r ./signatures/iocs ./dist/loki/signatures/ 2>/dev/null || true
	@echo "[+] Copying documentation ..."
	@cp LICENSE ./dist/loki/ 2>/dev/null || true
	@cp README.md ./dist/loki/ 2>/dev/null || true
	@test -f USAGE.md && cp USAGE.md ./dist/loki/ || true
	@echo "[+] Creating config directory ..."
	@mkdir -p ./dist/loki/config
	@test -f config/excludes.cfg.example && cp config/excludes.cfg.example ./dist/loki/config/excludes.cfg || echo "# LOKI2 Exclusions Configuration" > ./dist/loki/config/excludes.cfg
	@rm -rf ./tmp
	@echo "[✓] Distribution package created in ./dist/loki/"

clean: ## Clean build artifacts
	@echo "[+] Cleaning up ..."
	@rm -rf ./target
	@rm -rf ./dist
	@rm -rf ./tmp
	@rm -rf $(BUILD_DIR)
	@echo "[+] Clean complete"

clean-build: ## Clean only the build directory (keep target/)
	@echo "[+] Cleaning build directory ..."
	@rm -rf $(BUILD_DIR)
	@echo "[+] Build directory cleaned"
