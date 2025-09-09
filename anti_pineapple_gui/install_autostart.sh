#!/bin/bash

# Anti-Pineapple Auto-Start Installation Script
# This script sets up the Anti-Pineapple GUI to auto-start on macOS boot

echo "🛡️ Installing Anti-Pineapple Auto-Start Service..."

# Get the current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_FILE="$SCRIPT_DIR/com.aimf.antipineapple.plist"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"

# Create LaunchAgents directory if it doesn't exist
mkdir -p "$LAUNCH_AGENTS_DIR"

# Copy the plist file to LaunchAgents
cp "$PLIST_FILE" "$LAUNCH_AGENTS_DIR/"

# Load the service
launchctl load "$LAUNCH_AGENTS_DIR/com.aimf.antipineapple.plist"

echo "✅ Anti-Pineapple service installed successfully!"
echo "📋 Service will now:"
echo "   • Start automatically on system boot"
echo "   • Monitor network connections"
echo "   • Auto-authenticate on trusted networks"
echo "   • Block untrusted WiFi Pineapple attacks"
echo ""
echo "📁 Logs location: $SCRIPT_DIR/logs/"
echo "🔧 To uninstall: launchctl unload ~/Library/LaunchAgents/com.aimf.antipineapple.plist"
echo ""
echo "🔐 System is now protected!"
