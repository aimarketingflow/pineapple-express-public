#!/bin/bash

# StealthShark Desktop Shortcut Installer
# AIMF LLC - MobileShield Ecosystem v1.0
# Installs desktop shortcuts for StealthShark Anti-Pineapple Detection System

echo "🦈 StealthShark Desktop Shortcut Installer"
echo "🛡️ AIMF LLC - MobileShield Ecosystem"
echo ""

# Get the current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
STEALTHSHARK_DIR="$(dirname "$SCRIPT_DIR")"

echo "📁 StealthShark Directory: $STEALTHSHARK_DIR"
echo "📁 Desktop Shortcuts Directory: $SCRIPT_DIR"
echo ""

# Create icon if possible
echo "🎨 Creating StealthShark icon..."
if command -v python3 &> /dev/null; then
    cd "$SCRIPT_DIR"
    python3 create_icon.py
    if [ $? -eq 0 ]; then
        echo "✅ Icon created successfully"
    else
        echo "⚠️ Icon creation failed, using default"
    fi
else
    echo "⚠️ Python3 not found, skipping icon creation"
fi

echo ""

# Install macOS .app bundle
echo "🍎 Installing macOS .app bundle..."
if [ -d "$SCRIPT_DIR/StealthShark.app" ]; then
    # Copy to Applications folder (optional)
    read -p "Install to /Applications folder? (y/n): " install_apps
    if [[ $install_apps =~ ^[Yy]$ ]]; then
        sudo cp -R "$SCRIPT_DIR/StealthShark.app" /Applications/
        if [ $? -eq 0 ]; then
            echo "✅ StealthShark.app installed to /Applications"
        else
            echo "❌ Failed to install to /Applications"
        fi
    fi
    
    # Copy to Desktop
    read -p "Create shortcut on Desktop? (y/n): " install_desktop
    if [[ $install_desktop =~ ^[Yy]$ ]]; then
        cp -R "$SCRIPT_DIR/StealthShark.app" ~/Desktop/
        if [ $? -eq 0 ]; then
            echo "✅ StealthShark.app shortcut created on Desktop"
        else
            echo "❌ Failed to create Desktop shortcut"
        fi
    fi
else
    echo "❌ StealthShark.app not found"
fi

echo ""

# Install Linux .desktop file
echo "🐧 Installing Linux .desktop file..."
if [ -f "$SCRIPT_DIR/StealthShark.desktop" ]; then
    # Update paths in desktop file to absolute paths
    sed -i.bak "s|%INSTALL_DIR%|$STEALTHSHARK_DIR|g" "$SCRIPT_DIR/StealthShark.desktop"
    
    # Install to user applications
    mkdir -p ~/.local/share/applications
    cp "$SCRIPT_DIR/StealthShark.desktop" ~/.local/share/applications/
    if [ $? -eq 0 ]; then
        echo "✅ StealthShark.desktop installed to ~/.local/share/applications"
        
        # Update desktop database
        if command -v update-desktop-database &> /dev/null; then
            update-desktop-database ~/.local/share/applications
            echo "✅ Desktop database updated"
        fi
    else
        echo "❌ Failed to install .desktop file"
    fi
    
    # Copy to Desktop if requested
    read -p "Create .desktop shortcut on Desktop? (y/n): " install_desktop_linux
    if [[ $install_desktop_linux =~ ^[Yy]$ ]]; then
        cp "$SCRIPT_DIR/StealthShark.desktop" ~/Desktop/
        chmod +x ~/Desktop/StealthShark.desktop
        if [ $? -eq 0 ]; then
            echo "✅ StealthShark.desktop shortcut created on Desktop"
        else
            echo "❌ Failed to create Desktop shortcut"
        fi
    fi
else
    echo "❌ StealthShark.desktop not found"
fi

echo ""
echo "🎉 Desktop shortcut installation complete!"
echo ""
echo "📋 Available shortcuts:"
echo "   • macOS: StealthShark.app (double-click to launch)"
echo "   • Linux: StealthShark.desktop (right-click → Allow Launching)"
echo "   • Manual: Run ./launch.sh from StealthShark directory"
echo ""
echo "🆕 NEW FEATURES:"
echo "   • ⚙️ Settings Tab: Configure monitoring duration (default: 6 hours)"
echo "   • 🚀 Auto-Start: Set up automatic launch at computer boot"
echo "   • ⏱️ Smart Timer: Automatic monitoring timeout with notifications"
echo "   • 📡 Configurable Scan Interval: Adjust network scanning frequency"
echo ""
echo "🔧 To set up auto-start:"
echo "   1. Launch StealthShark"
echo "   2. Go to Settings tab"
echo "   3. Click 'Install Auto-Start'"
echo "   4. StealthShark will start automatically on boot with 6-hour monitoring"
echo ""
echo "📝 Or use the automated setup script:"
echo "   ./setup_autostart.sh"
echo ""
echo "🦈 StealthShark is ready to protect your network!"
