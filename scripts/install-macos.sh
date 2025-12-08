#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

INSTALL_DIR="/usr/local/bin"
PLIST_PATH="/Library/LaunchDaemons/ai.hypr.hyprd.plist"
HYPR_DATA_DIR="/var/lib/hypr"

echo -e "${GREEN}=== HYPR Installer for macOS ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run with sudo: sudo ./scripts/install-macos.sh${NC}"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}Building hypr...${NC}"
cd "$PROJECT_DIR"
cargo build --release -p hypr-daemon -p hypr-cli

echo -e "${YELLOW}Installing binaries...${NC}"
mkdir -p "$INSTALL_DIR"
cp target/release/hyprd "$INSTALL_DIR/"
cp target/release/hypr "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/hyprd"
chmod +x "$INSTALL_DIR/hypr"

echo -e "${YELLOW}Installing kernel...${NC}"
mkdir -p "$HYPR_DATA_DIR"

# Download kernel for current architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    KERNEL_URL="https://github.com/cloud-hypervisor/linux/releases/latest/download/Image-arm64"
    KERNEL_NAME="vmlinux"
else
    KERNEL_URL="https://github.com/cloud-hypervisor/linux/releases/latest/download/vmlinux-x86_64"
    KERNEL_NAME="vmlinux"
fi

KERNEL_PATH="$HYPR_DATA_DIR/$KERNEL_NAME"
if [ ! -f "$KERNEL_PATH" ]; then
    echo "  Downloading kernel for $ARCH..."
    curl -fsSL "$KERNEL_URL" -o "$KERNEL_PATH" || wget -q -O "$KERNEL_PATH" "$KERNEL_URL"
    chmod 644 "$KERNEL_PATH"
    echo "  Kernel installed to $KERNEL_PATH"
else
    echo "  Kernel already exists at $KERNEL_PATH"
fi

echo -e "${YELLOW}Creating LaunchDaemon...${NC}"
cat > "$PLIST_PATH" << 'EOF'
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
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>RUST_LOG</key>
        <string>info</string>
        <key>HOME</key>
        <string>/var/lib/hypr</string>
    </dict>
</dict>
</plist>
EOF

# Create required directories (matches hypr_core::paths when running as root)
mkdir -p /var/log/hypr
mkdir -p /var/lib/hypr/logs
mkdir -p /var/lib/hypr/images
mkdir -p /var/lib/hypr/cache

# Make data directory writable by all users so CLI can register images
chmod 777 /var/lib/hypr
chmod 777 /var/lib/hypr/logs
chmod 777 /var/lib/hypr/images
chmod 777 /var/lib/hypr/cache

# Create database file with open permissions (before daemon starts)
touch /var/lib/hypr/hypr.db
chmod 666 /var/lib/hypr/hypr.db

echo -e "${YELLOW}Loading LaunchDaemon...${NC}"
# Stop existing service if running
launchctl unload "$PLIST_PATH" 2>/dev/null || true
# Load new service
launchctl load "$PLIST_PATH"

echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "hyprd is now running as a system service."
echo ""
echo "Commands:"
echo "  hypr ps              - List running VMs"
echo "  hypr run <image>     - Run a VM"
echo "  hypr logs <vm> -f    - Stream VM logs"
echo "  hypr rm <vm>         - Remove a VM"
echo ""
echo "Service management:"
echo "  sudo launchctl stop ai.hypr.hyprd     - Stop daemon"
echo "  sudo launchctl start ai.hypr.hyprd   - Start daemon"
echo "  tail -f /var/log/hypr/hyprd.log      - View daemon logs"
echo ""
echo -e "${GREEN}Enjoy HYPR!${NC}"
