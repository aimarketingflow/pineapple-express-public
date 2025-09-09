#!/bin/bash

# Anti-Pineapple Auto-Start Uninstall Script

echo "🛡️ Uninstalling Anti-Pineapple Auto-Start Service..."

LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_FILE="$LAUNCH_AGENTS_DIR/com.aimf.antipineapple.plist"

# Unload the service if it's running
if [ -f "$PLIST_FILE" ]; then
    launchctl unload "$PLIST_FILE"
    rm "$PLIST_FILE"
    echo "✅ Anti-Pineapple service uninstalled successfully!"
else
    echo "⚠️ Service not found - may already be uninstalled"
fi

echo "🔧 Service has been removed from auto-start"
