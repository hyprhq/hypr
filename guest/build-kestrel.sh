#!/bin/bash
# Build kestrel.c for Linux (x86_64 and aarch64)
# Run this on a Linux machine or in Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$(uname -s)" != "Linux" ]; then
    echo "⚠️  This script must run on Linux (native or Docker)"
    echo ""
    echo "To build on macOS, use Docker:"
    echo "  docker run --rm -v \"\$(pwd):/work\" -w /work alpine:3.19 sh -c '"
    echo "    apk add gcc musl-dev && ./build-kestrel.sh"
    echo "  '"
    exit 1
fi

echo "Building kestrel for Linux..."

# x86_64
echo "Building x86_64..."
gcc -static -Os -s -o kestrel-linux-x86_64 kestrel.c

# aarch64 (requires cross-compiler)
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    echo "Building aarch64..."
    aarch64-linux-gnu-gcc -static -Os -s -o kestrel-linux-aarch64 kestrel.c
else
    echo "⚠️  aarch64-linux-gnu-gcc not found, skipping arm64 build"
    echo "    Install: apt-get install gcc-aarch64-linux-gnu"
fi

echo "✅ Built kestrel:"
ls -lh kestrel-linux-* 2>/dev/null || echo "(some builds may have been skipped)"
