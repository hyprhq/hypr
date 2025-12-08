#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PLIST_PATH="/Library/LaunchDaemons/ai.hypr.hyprd.plist"

echo -e "${YELLOW}=== HYPR Uninstaller for macOS ===${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run with sudo: sudo ./scripts/uninstall-macos.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}Stopping daemon...${NC}"
launchctl unload "$PLIST_PATH" 2>/dev/null || true

echo -e "${YELLOW}Removing LaunchDaemon...${NC}"
rm -f "$PLIST_PATH"

echo -e "${YELLOW}Removing binaries...${NC}"
rm -f /usr/local/bin/hyprd
rm -f /usr/local/bin/hypr

echo -e "${YELLOW}Removing data directories...${NC}"
rm -rf /var/lib/hypr
rm -rf /var/log/hypr

echo ""
echo -e "${GREEN}HYPR uninstalled.${NC}"
echo ""
echo "Note: User data in ~/.hypr was preserved."
echo "To remove it: rm -rf ~/.hypr"
