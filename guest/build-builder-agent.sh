#!/bin/bash
#
# Build script for builder-agent.c
#
# This script compiles builder-agent.c to a static Linux binary.
# It requires a Linux environment (native or Docker).
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building builder-agent.c..."

# Check if we're on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "⚠️  Warning: Not running on Linux"
    echo "builder-agent.c must be compiled for Linux (Alpine)"
    echo ""
    echo "Options:"
    echo "  1. Run this script on a Linux machine"
    echo "  2. Use Docker:"
    echo "     docker run --rm -v \$(pwd):/work alpine:3.19 sh -c 'apk add gcc musl-dev && cd /work && gcc -static -O2 -o builder-agent builder-agent.c'"
    echo ""
    exit 1
fi

# Compile with static linking
gcc -static -O2 -Wall -Wextra -o builder-agent builder-agent.c

# Verify it's statically linked
if ldd builder-agent 2>&1 | grep -q "not a dynamic executable"; then
    echo "✅ builder-agent compiled successfully (static binary)"
    ls -lh builder-agent
else
    echo "❌ Error: builder-agent is not statically linked"
    ldd builder-agent
    exit 1
fi

# Show file info
file builder-agent
echo ""
echo "To test: Run this binary as PID 1 in an Alpine VM"
