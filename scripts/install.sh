#!/bin/sh
# HYPR Universal Installer
# Usage: curl -fsSL https://get.hypr.tech | sh
#    or: curl -fsSL https://raw.githubusercontent.com/hyprhq/hypr/main/scripts/install.sh | sh
set -e

# Colors (POSIX-compatible)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
GITHUB_REPO="hyprhq/hypr"
INSTALL_DIR="/usr/local/bin"
VERSION="${HYPR_VERSION:-latest}"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)
            printf "${RED}Unsupported operating system: %s${NC}\n" "$OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)
            printf "${RED}Unsupported architecture: %s${NC}\n" "$ARCH"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    printf "${BLUE}Detected platform: %s${NC}\n" "$PLATFORM"
}

# Check for required commands
check_requirements() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            printf "${RED}Required command not found: %s${NC}\n" "$cmd"
            exit 1
        fi
    done
}

# Get download URL for latest release
get_download_url() {
    BINARY_NAME="$1"
    if [ "$VERSION" = "latest" ]; then
        echo "https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-${PLATFORM}"
    else
        echo "https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}-${PLATFORM}"
    fi
}

# Download and install binaries
install_binaries() {
    printf "${YELLOW}Downloading HYPR binaries...${NC}\n"

    HYPR_URL=$(get_download_url "hypr")
    HYPRD_URL=$(get_download_url "hyprd")

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    # Download binaries
    printf "  Downloading hypr...\n"
    curl -fsSL "$HYPR_URL" -o "$TMP_DIR/hypr" || {
        printf "${RED}Failed to download hypr${NC}\n"
        exit 1
    }

    printf "  Downloading hyprd...\n"
    curl -fsSL "$HYPRD_URL" -o "$TMP_DIR/hyprd" || {
        printf "${RED}Failed to download hyprd${NC}\n"
        exit 1
    }

    # Make executable
    chmod +x "$TMP_DIR/hypr" "$TMP_DIR/hyprd"

    # Install (requires sudo on most systems)
    printf "${YELLOW}Installing binaries to %s...${NC}\n" "$INSTALL_DIR"
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/hypr" "$INSTALL_DIR/"
        mv "$TMP_DIR/hyprd" "$INSTALL_DIR/"
    else
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "$TMP_DIR/hypr" "$INSTALL_DIR/"
        sudo mv "$TMP_DIR/hyprd" "$INSTALL_DIR/"
    fi

    printf "${GREEN}Binaries installed successfully${NC}\n"
}

# Install Linux dependencies
install_linux_deps() {
    printf "${YELLOW}Installing Linux dependencies...${NC}\n"

    # Detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        printf "  Installing virtiofsd via apt...\n"
        sudo apt-get update -qq
        sudo apt-get install -y virtiofsd
    elif command -v dnf >/dev/null 2>&1; then
        printf "  Installing virtiofsd via dnf...\n"
        sudo dnf install -y virtiofsd
    elif command -v yum >/dev/null 2>&1; then
        printf "  Installing virtiofsd via yum...\n"
        sudo yum install -y virtiofsd
    elif command -v pacman >/dev/null 2>&1; then
        printf "  Installing virtiofsd via pacman...\n"
        sudo pacman -Sy --noconfirm virtiofsd
    else
        printf "${YELLOW}  Could not detect package manager. Please install virtiofsd manually.${NC}\n"
    fi

    # Download cloud-hypervisor if not present
    if ! command -v cloud-hypervisor >/dev/null 2>&1; then
        printf "  cloud-hypervisor will be downloaded automatically on first run\n"
    fi
}

# Install macOS dependencies
install_macos_deps() {
    printf "${YELLOW}Installing macOS dependencies...${NC}\n"

    # Check for Homebrew
    if ! command -v brew >/dev/null 2>&1; then
        printf "${RED}Homebrew is required but not installed.${NC}\n"
        printf "Install it from: https://brew.sh\n"
        exit 1
    fi

    if [ "$ARCH" = "arm64" ]; then
        printf "  Apple Silicon detected. Installing krunkit...\n"

        # Add krunkit tap
        if ! brew tap 2>/dev/null | grep -q "slp/krunkit"; then
            brew tap slp/krunkit
        fi

        # Install krunkit
        if ! command -v krunkit >/dev/null 2>&1; then
            brew install krunkit
        else
            printf "  krunkit already installed\n"
        fi

        printf "${GREEN}  GPU support enabled via Metal/Venus${NC}\n"
    else
        printf "  Intel Mac detected. Installing vfkit...\n"

        if ! command -v vfkit >/dev/null 2>&1; then
            brew install vfkit
        else
            printf "  vfkit already installed\n"
        fi

        printf "${YELLOW}  Note: GPU passthrough not available on Intel Macs${NC}\n"
    fi
}

# Setup systemd service (Linux)
setup_systemd() {
    printf "${YELLOW}Setting up systemd service...${NC}\n"

    # Create data directories
    sudo mkdir -p /var/lib/hypr/{logs,images,cache}
    sudo mkdir -p /var/log/hypr
    sudo mkdir -p /run/hypr

    # Create systemd service file
    sudo tee /etc/systemd/system/hyprd.service >/dev/null << 'EOF'
[Unit]
Description=HYPR Daemon - MicroVM Orchestration
Documentation=https://github.com/hyprhq/hypr
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hyprd
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/hypr /var/log/hypr /run/hypr /tmp

# Environment
Environment=RUST_LOG=info
Environment=HOME=/var/lib/hypr

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable hyprd
    sudo systemctl start hyprd

    printf "${GREEN}  hyprd service started and enabled${NC}\n"
}

# Setup LaunchDaemon (macOS)
setup_launchdaemon() {
    printf "${YELLOW}Setting up LaunchDaemon...${NC}\n"

    PLIST_PATH="/Library/LaunchDaemons/ai.hypr.hyprd.plist"
    HYPR_DATA_DIR="/var/lib/hypr"

    # Create data directories
    sudo mkdir -p "$HYPR_DATA_DIR"/{logs,images,cache}
    sudo mkdir -p /var/log/hypr

    # Create hypr group if it doesn't exist
    if ! dscl . -read /Groups/hypr >/dev/null 2>&1; then
        NEXT_GID=500
        while dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -q "^${NEXT_GID}$"; do
            NEXT_GID=$((NEXT_GID + 1))
        done
        sudo dscl . -create /Groups/hypr
        sudo dscl . -create /Groups/hypr PrimaryGroupID "$NEXT_GID"
        sudo dscl . -create /Groups/hypr RealName "HYPR Users"
        printf "  Created 'hypr' group\n"
    fi

    # Add current user to hypr group
    HYPR_USER="${SUDO_USER:-$(whoami)}"
    if [ "$HYPR_USER" != "root" ]; then
        if ! dscl . -read /Groups/hypr GroupMembership 2>/dev/null | grep -q "\b${HYPR_USER}\b"; then
            sudo dseditgroup -o edit -a "$HYPR_USER" -t user hypr 2>/dev/null || true
            printf "  Added user '%s' to 'hypr' group\n" "$HYPR_USER"
        fi
    fi

    # Set permissions
    sudo chown -R root:hypr "$HYPR_DATA_DIR"
    sudo chmod 770 "$HYPR_DATA_DIR"
    sudo chmod 770 "$HYPR_DATA_DIR"/{logs,images,cache}
    sudo chown -R root:hypr /var/log/hypr
    sudo chmod 770 /var/log/hypr

    # Create LaunchDaemon plist
    sudo tee "$PLIST_PATH" >/dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.hypr.hyprd</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hyprd</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/hypr/hyprd.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/hypr/hyprd.log</string>

    <key>WorkingDirectory</key>
    <string>/var/lib/hypr</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>RUST_LOG</key>
        <string>info</string>
        <key>HOME</key>
        <string>/var/lib/hypr</string>
    </dict>
</dict>
</plist>
EOF

    # Load the service
    sudo launchctl unload "$PLIST_PATH" 2>/dev/null || true
    sudo launchctl load "$PLIST_PATH"

    printf "${GREEN}  hyprd LaunchDaemon started${NC}\n"
}

# Print success message
print_success() {
    printf "\n${GREEN}=== HYPR Installation Complete ===${NC}\n\n"

    printf "Quick start:\n"
    printf "  hypr run nginx          # Run nginx in a microVM\n"
    printf "  hypr ps                 # List running VMs\n"
    printf "  hypr logs <vm> -f       # Stream VM logs\n"
    printf "  hypr exec <vm> sh       # Execute shell in VM\n"
    printf "  hypr rm <vm>            # Remove a VM\n"
    printf "\n"

    if [ "$OS" = "darwin" ]; then
        if [ "$ARCH" = "arm64" ]; then
            printf "GPU Support: ${GREEN}Enabled (Metal/Venus)${NC}\n"
            printf "  hypr gpu list          # List available GPUs\n"
            printf "  hypr run --gpu nginx   # Run with GPU\n"
        else
            printf "GPU Support: ${YELLOW}Not available on Intel Macs${NC}\n"
        fi
        printf "\nService management:\n"
        printf "  sudo launchctl stop ai.hypr.hyprd   # Stop daemon\n"
        printf "  sudo launchctl start ai.hypr.hyprd  # Start daemon\n"
        printf "  tail -f /var/log/hypr/hyprd.log     # View logs\n"
    else
        if [ "$ARCH" = "amd64" ]; then
            printf "GPU Support: ${GREEN}Available via VFIO${NC}\n"
            printf "  hypr gpu list                    # List available GPUs\n"
            printf "  hypr run --gpu 0000:01:00.0 ...  # Run with GPU passthrough\n"
        fi
        printf "\nService management:\n"
        printf "  sudo systemctl status hyprd    # Check status\n"
        printf "  sudo systemctl restart hyprd   # Restart daemon\n"
        printf "  journalctl -u hyprd -f         # View logs\n"
    fi

    printf "\nDocumentation: https://github.com/hyprhq/hypr\n"
    printf "\n${GREEN}Enjoy HYPR!${NC}\n"
}

# Main installation flow
main() {
    printf "${GREEN}"
    printf "  _   ___   ______  _____  \n"
    printf " | | | \\ \\ / /  _ \\|  __ \\ \n"
    printf " | |_| |\\ V /| |_) | |__) |\n"
    printf " |  _  | | | |  __/|  _  / \n"
    printf " |_| |_| |_| |_|   |_| \\_\\ \n"
    printf "${NC}\n"
    printf "Universal MicroVM Orchestration\n\n"

    detect_platform
    check_requirements
    install_binaries

    # Install platform-specific dependencies
    case "$OS" in
        linux)
            install_linux_deps
            setup_systemd
            ;;
        darwin)
            install_macos_deps
            setup_launchdaemon
            ;;
    esac

    print_success
}

# Run main
main "$@"
