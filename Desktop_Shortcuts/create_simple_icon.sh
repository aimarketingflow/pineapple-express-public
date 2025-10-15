#!/bin/bash

# Create a simple StealthShark icon using built-in macOS tools
# AIMF LLC - MobileShield Ecosystem

echo "🎨 Creating StealthShark icon using macOS tools..."

# Create a simple icon using sips and built-in tools
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ICON_DIR="$SCRIPT_DIR"

# Create a simple text-based icon using ImageMagick if available, otherwise use a system icon
if command -v convert &> /dev/null; then
    echo "Using ImageMagick to create icon..."
    convert -size 512x512 xc:navy \
            -fill white -pointsize 120 -gravity center -annotate +0+0 "🦈" \
            "$ICON_DIR/stealthshark-icon.png"
    echo "✅ Icon created with ImageMagick"
elif [ -f "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns" ]; then
    echo "Using system application icon as base..."
    # Copy a generic app icon and rename it
    cp "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns" "$ICON_DIR/stealthshark-icon.icns"
    
    # Convert to PNG if sips is available
    if command -v sips &> /dev/null; then
        sips -s format png "$ICON_DIR/stealthshark-icon.icns" --out "$ICON_DIR/stealthshark-icon.png" &>/dev/null
        rm "$ICON_DIR/stealthshark-icon.icns" 2>/dev/null
        echo "✅ Icon created using system tools"
    fi
else
    echo "⚠️ Creating placeholder icon file..."
    # Create a simple placeholder
    echo "StealthShark Icon Placeholder" > "$ICON_DIR/stealthshark-icon.txt"
fi

echo "🦈 Icon creation complete!"
