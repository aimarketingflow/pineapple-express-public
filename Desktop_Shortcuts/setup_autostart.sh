#!/bin/bash

# StealthShark Auto-Start Setup Script
# AIMF LLC - MobileShield Ecosystem v1.0
# Sets up StealthShark to automatically start when computer boots

echo "🦈 StealthShark Auto-Start Setup"
echo "🛡️ AIMF LLC - MobileShield Ecosystem"
echo ""

# Get the current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
STEALTHSHARK_DIR="$(dirname "$SCRIPT_DIR")"

echo "📁 StealthShark Directory: $STEALTHSHARK_DIR"
echo ""

# Check if LaunchAgent already exists
LAUNCHAGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_FILE="$LAUNCHAGENTS_DIR/com.aimfllc.stealthshark.plist"

if [ -f "$PLIST_FILE" ]; then
    echo "⚠️ Auto-start is already installed"
    read -p "Do you want to reinstall? (y/n): " reinstall
    if [[ ! $reinstall =~ ^[Yy]$ ]]; then
        echo "❌ Setup cancelled"
        exit 0
    fi
    
    echo "🗑️ Removing existing auto-start..."
    launchctl unload "$PLIST_FILE" 2>/dev/null
    rm "$PLIST_FILE"
fi

# Create LaunchAgents directory if it doesn't exist
mkdir -p "$LAUNCHAGENTS_DIR"

# Update the plist file with correct paths
echo "📝 Creating LaunchAgent configuration..."
cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aimfllc.stealthshark</string>
    <key>ProgramArguments</key>
    <array>
        <string>$STEALTHSHARK_DIR/launch.sh</string>
        <string>--auto-start</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$STEALTHSHARK_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/stealthshark.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/stealthshark_error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>PYTHONPATH</key>
        <string>$STEALTHSHARK_DIR</string>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>
EOF

# Load the LaunchAgent
echo "🚀 Installing auto-start service..."
if launchctl load "$PLIST_FILE"; then
    echo "✅ Auto-start installed successfully!"
    echo ""
    echo "📋 Configuration:"
    echo "   • StealthShark will start automatically when you log in"
    echo "   • Default monitoring duration: 6 hours"
    echo "   • Application will run minimized in background"
    echo "   • Logs available at: /tmp/stealthshark.log"
    echo ""
    echo "🔧 To manage auto-start settings:"
    echo "   • Open StealthShark GUI → Settings tab"
    echo "   • Use 'Install/Remove Auto-Start' buttons"
    echo ""
    echo "🗑️ To manually remove auto-start:"
    echo "   launchctl unload '$PLIST_FILE'"
    echo "   rm '$PLIST_FILE'"
    echo ""
    echo "🦈 StealthShark auto-start is now active!"
else
    echo "❌ Failed to install auto-start"
    echo "You may need to grant permissions in System Preferences"
    exit 1
fi
