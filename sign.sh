#!/bin/bash

# Script to build and sign the hypr binaries with VZ entitlements

set -e

# Build the project
echo "Building hypr..."
cargo build --release

# Binaries to sign
BINARIES=("target/release/hyprd" "target/release/hypr")
ENTITLEMENTS="hyprd.entitlements"

# Check if entitlements file exists
if [ ! -f "$ENTITLEMENTS" ]; then
    echo "❌ Error: Entitlements file not found at $ENTITLEMENTS"
    echo "Run this to create it:"
    echo ""
    echo 'cat > hyprd.entitlements << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
EOF'
    echo ""
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Entitlements file content:"
cat "$ENTITLEMENTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Sign each binary
for BINARY in "${BINARIES[@]}"; do
    if [ ! -f "$BINARY" ]; then
        echo "⚠️  Warning: Binary not found at $BINARY, skipping..."
        continue
    fi
    
    echo ""
    echo "🔐 Signing $BINARY with entitlements..."
    
    # Remove existing signature first
    codesign --remove-signature "$BINARY" 2>/dev/null || true
    
    # Sign with entitlements
    codesign --sign - \
        --entitlements "$ENTITLEMENTS" \
        --force \
        --timestamp=none \
        "$BINARY"
    
    echo "   ✓ Signed successfully"
    
    # Verify entitlements are present (try multiple methods)
    echo "   Verifying entitlements..."
    
    # Use the correct syntax (without the colon, as it's deprecated)
    ENTITLEMENTS_OUTPUT=$(codesign -d --entitlements - "$BINARY" 2>&1)
    
    if echo "$ENTITLEMENTS_OUTPUT" | grep -q "com.apple.security.virtualization"; then
        echo "   ✓ VZ entitlement confirmed!"
    else
        echo "   ⚠️  Could not verify entitlements in output"
        echo "$ENTITLEMENTS_OUTPUT"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All binaries signed successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Show details for each binary
for BINARY in "${BINARIES[@]}"; do
    if [ -f "$BINARY" ]; then
        echo "📋 $(basename $BINARY) signature:"
        codesign -dv "$BINARY" 2>&1 | head -5
        echo ""
    fi
done

