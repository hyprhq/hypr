#!/bin/sh
# HYPR Universal Installer
# Usage: curl -fsSL https://get.hypr.tech | sh
set -e

# --- Styles & Helpers ---
# We use tput if available for safer color handling, falling back to raw codes
BOLD="$(tput bold 2>/dev/null || printf '\033[1m')"
DIM="$(tput dim 2>/dev/null || printf '\033[2m')"
RED="$(tput setaf 1 2>/dev/null || printf '\033[0;31m')"
GREEN="$(tput setaf 2 2>/dev/null || printf '\033[0;32m')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '\033[0;33m')"
BLUE="$(tput setaf 4 2>/dev/null || printf '\033[0;34m')"
CYAN="$(tput setaf 6 2>/dev/null || printf '\033[0;36m')"
RESET="$(tput sgr0 2>/dev/null || printf '\033[0m')"

# Config
GITHUB_REPO="hyprhq/hypr"
INSTALL_DIR="/usr/local/bin"
VERSION="${HYPR_VERSION:-latest}"

# Visual helpers
fmt_header()  { printf "\n${BOLD}${BLUE}==>${RESET} ${BOLD}%s${RESET}\n" "$1"; }
fmt_info()    { printf " ${BLUE}  ->${RESET} %s\n" "$1"; }
fmt_success() { printf " ${GREEN}  ✔${RESET}  %s\n" "$1"; }
fmt_warn()    { printf " ${YELLOW}  !${RESET}  %s\n" "$1"; }
fmt_error()   { printf " ${RED}  ✘  %s${RESET}\n" "$1"; exit 1; }

# --- Logic ---

detect_platform() {
    fmt_header "Detecting System"
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      fmt_error "Unsupported operating system: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              fmt_error "Unsupported architecture: $ARCH" ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    fmt_success "Platform: ${BOLD}$OS${RESET} / ${BOLD}$ARCH${RESET}"
}

check_requirements() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            fmt_error "Required command not found: $cmd"
        fi
    done
}

get_download_url() {
    BINARY_NAME="$1"
    if [ "$VERSION" = "latest" ]; then
        echo "https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-${PLATFORM}"
    else
        echo "https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}-${PLATFORM}"
    fi
}

install_binaries() {
    fmt_header "Installing Core Binaries"
    
    HYPR_URL=$(get_download_url "hypr")
    HYPRD_URL=$(get_download_url "hyprd")

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    fmt_info "Fetching ${BOLD}hypr${RESET} CLI..."
    curl -fsSL "$HYPR_URL" -o "$TMP_DIR/hypr" || fmt_error "Failed to download hypr"

    fmt_info "Fetching ${BOLD}hyprd${RESET} daemon..."
    curl -fsSL "$HYPRD_URL" -o "$TMP_DIR/hyprd" || fmt_error "Failed to download hyprd"

    chmod +x "$TMP_DIR/hypr" "$TMP_DIR/hyprd"

    fmt_info "Moving to $INSTALL_DIR (may require password)"
    
    # Check write access
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/hypr" "$INSTALL_DIR/"
        mv "$TMP_DIR/hyprd" "$INSTALL_DIR/"
    else
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "$TMP_DIR/hypr" "$INSTALL_DIR/"
        sudo mv "$TMP_DIR/hyprd" "$INSTALL_DIR/"
    fi

    fmt_success "Binaries installed"
}

install_linux_deps() {
    fmt_header "Linux Dependencies"

    if command -v apt-get >/dev/null 2>&1; then
        fmt_info "Using apt-get..."
        sudo apt-get update -qq >/dev/null
        sudo apt-get install -y virtiofsd >/dev/null 2>&1 || fmt_warn "virtiofsd install failed, please install manually"
    elif command -v dnf >/dev/null 2>&1; then
        fmt_info "Using dnf..."
        sudo dnf install -y virtiofsd >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        fmt_info "Using pacman..."
        sudo pacman -Sy --noconfirm virtiofsd >/dev/null 2>&1
    else
        fmt_warn "Could not detect package manager. Ensure 'virtiofsd' is installed."
    fi

    fmt_success "Dependencies checked"
}

setup_systemd() {
    fmt_header "System Integration (systemd)"
    
    # Create dirs
    sudo mkdir -p /var/lib/hypr/{logs,images,cache} /var/log/hypr /run/hypr

    # Service file
    # Note: hyprd needs broad system access for:
    # - /dev/kvm, /dev/vhost-*, /dev/net/tun (virtualization)
    # - /sys (network config, VFIO)
    # - Network namespace and bridge management
    sudo tee /etc/systemd/system/hyprd.service >/dev/null << 'EOF'
[Unit]
Description=HYPR Daemon
Documentation=https://github.com/hyprhq/hypr
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hyprd
Restart=always
RestartSec=5
Environment=RUST_LOG=info
Environment=HOME=/var/lib/hypr
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable hyprd >/dev/null 2>&1
    sudo systemctl start hyprd
    fmt_success "Service active: hyprd"
}

setup_launchdaemon() {
    fmt_header "System Integration (LaunchDaemon)"

    PLIST_PATH="/Library/LaunchDaemons/ai.hypr.hyprd.plist"
    HYPR_DATA_DIR="/var/lib/hypr"

    # Dirs
    sudo mkdir -p "$HYPR_DATA_DIR"/{logs,images,cache} /var/log/hypr

    # Group creation logic
    if ! dscl . -read /Groups/hypr >/dev/null 2>&1; then
        fmt_info "Creating 'hypr' group..."
        NEXT_GID=500
        while dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -q "^${NEXT_GID}$"; do
            NEXT_GID=$((NEXT_GID + 1))
        done
        sudo dscl . -create /Groups/hypr
        sudo dscl . -create /Groups/hypr PrimaryGroupID "$NEXT_GID"
        sudo dscl . -create /Groups/hypr RealName "HYPR Users"
    fi

    # User add logic
    HYPR_USER="${SUDO_USER:-$(whoami)}"
    if [ "$HYPR_USER" != "root" ]; then
        if ! dscl . -read /Groups/hypr GroupMembership 2>/dev/null | grep -q "\b${HYPR_USER}\b"; then
            sudo dseditgroup -o edit -a "$HYPR_USER" -t user hypr 2>/dev/null || true
            fmt_success "Added $HYPR_USER to hypr group"
        fi
    fi

    # Permissions
    sudo chown -R root:hypr "$HYPR_DATA_DIR" /var/log/hypr
    sudo chmod 770 "$HYPR_DATA_DIR" "$HYPR_DATA_DIR"/{logs,images,cache} /var/log/hypr

    # Plist content
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

    sudo launchctl unload "$PLIST_PATH" 2>/dev/null || true
    sudo launchctl load "$PLIST_PATH"
    fmt_success "LaunchDaemon loaded"
}

print_success() {
    printf "\n"
    printf "   ${GREEN}╭───────────────────────────────────────╮${RESET}\n"
    printf "   ${GREEN}│${RESET}       ${BOLD}HYPR INSTALLED SUCCESSFULLY${RESET}     ${GREEN}│${RESET}\n"
    printf "   ${GREEN}╰───────────────────────────────────────╯${RESET}\n\n"

    printf "  ${BOLD}Run your first microVM:${RESET}\n"
    printf "    ${CYAN}hypr run nginx${RESET}\n\n"

    printf "  ${BOLD}Commands:${RESET}\n"
    printf "    ${CYAN}hypr ps${RESET}           List VMs\n"
    printf "    ${CYAN}hypr logs <vm>${RESET}    Stream logs\n"
    printf "    ${CYAN}hypr exec <vm>${RESET}    Shell access\n\n"

    printf "  ${BOLD}Service Status:${RESET}\n"
    if [ "$OS" = "darwin" ]; then
        printf "    Logs:   ${DIM}tail -f /var/log/hypr/hyprd.log${RESET}\n"
        printf "    Restart:${DIM}sudo launchctl kickstart -k system/ai.hypr.hyprd${RESET}\n"
    else
        printf "    Logs:   ${DIM}journalctl -u hyprd -f${RESET}\n"
        printf "    Restart:${DIM}sudo systemctl restart hyprd${RESET}\n"
    fi
    
    printf "\n  ${DIM}✨ containers are cute. hypr is inevitable.${RESET}\n"
}

# --- Intro Joke ---
run_intro() {
    clear
    printf "${BLUE}"
    # Slightly tighter ASCII art
    cat << "EOF"

 ██╗  ██╗██╗   ██╗██████╗ ██████╗ 
 ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗
 ███████║ ╚████╔╝ ██████╔╝██████╔╝
 ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══██╗
 ██║  ██║   ██║   ██║     ██║  ██║
 ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝
EOF
    printf "${RESET}"
    
    # The Joke: Use DIM color to make it look like a background process
    printf "\n${DIM}🐳 docker pull hypr/runtime:latest${RESET}"
    sleep 0.4
    printf "\n${DIM}latest: Pulling from hypr/runtime${RESET}"
    sleep 0.2
    printf "\n${DIM}Digest: sha256:9a2156bf77bcd236800f4ddb${RESET}"
    sleep 0.1
    printf "\n${DIM}Status: Downloaded newer hypervisor in 0.14s${RESET}"
    sleep 0.4
    printf "\n\n${DIM}🐳 docker run hypr/runtime${RESET}"
    sleep 0.6
    printf "\n${DIM}Error: Unable to find image 'hypr/runtime:latest' locally${RESET}"
    sleep 0.8
    printf "\n${DIM}Status: Booting nested VM to run container to run hypr...${RESET}"
    sleep 1.2
    
    # The Punchline: Clear the line and print neatly
    printf "\n\n${BOLD}${RED}Wait, no.${RESET} ${BOLD}HYPR boots faster than Docker prints that line.${RESET}\n"
    sleep 0.5
    printf "Let's do this the real way.\n"
    sleep 0.5
}

# --- Main ---
main() {
    run_intro
    detect_platform
    check_requirements
    install_binaries

    case "$OS" in
        linux)
            install_linux_deps
            setup_systemd
            ;;
        darwin)
            setup_launcnhdaemon
            ;;
    esac

    print_success
}

main "$@"
