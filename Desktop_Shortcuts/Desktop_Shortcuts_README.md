# StealthShark Desktop Shortcuts v1.0
**AIMF LLC - MobileShield Ecosystem**

## 🦈 Overview
This directory contains desktop shortcuts and installation tools for StealthShark Anti-Pineapple Detection System v1.0. These shortcuts provide easy access to launch StealthShark from your desktop or applications menu.

## 📁 Contents

### Desktop Shortcut Files
- **`StealthShark.app/`** - macOS application bundle (double-click to launch)
- **`StealthShark.desktop`** - Linux desktop entry file
- **`stealthshark-icon.png`** - Application icon (512x512 PNG)

### Installation & Setup Tools
- **`install_desktop_shortcut.sh`** - Automated installer for desktop shortcuts
- **`create_icon.py`** - Advanced icon creator (requires Pillow)
- **`create_simple_icon.sh`** - Simple icon creator using system tools

## 🚀 Quick Installation

### Automatic Installation (Recommended)
```bash
cd Desktop_Shortcuts
./install_desktop_shortcut.sh
```

### Manual Installation

#### macOS
1. **Desktop Shortcut:**
   ```bash
   cp -R StealthShark.app ~/Desktop/
   ```

2. **Applications Folder:**
   ```bash
   sudo cp -R StealthShark.app /Applications/
   ```

#### Linux
1. **System Installation:**
   ```bash
   cp StealthShark.desktop ~/.local/share/applications/
   update-desktop-database ~/.local/share/applications
   ```

2. **Desktop Shortcut:**
   ```bash
   cp StealthShark.desktop ~/Desktop/
   chmod +x ~/Desktop/StealthShark.desktop
   ```

## 🎯 Usage

### macOS (.app bundle)
- **Double-click** `StealthShark.app` to launch
- Right-click → "Open" if security warning appears
- Launches StealthShark GUI automatically

### Linux (.desktop file)
- **Double-click** `StealthShark.desktop` to launch
- Right-click → "Allow Launching" if needed
- Available in applications menu after installation

## 🔧 Customization

### Updating Paths
If you move StealthShark to a different location, update these files:

**StealthShark.app/Contents/MacOS/StealthShark:**
```bash
STEALTHSHARK_DIR="/path/to/your/StealthShark-PublicRelease"
```

**StealthShark.desktop:**
```ini
Exec=/path/to/your/StealthShark-PublicRelease/launch.sh
Path=/path/to/your/StealthShark-PublicRelease
```

### Creating Custom Icons
1. **Advanced (requires Pillow):**
   ```bash
   pip3 install --user Pillow
   python3 create_icon.py
   ```

2. **Simple (system tools):**
   ```bash
   ./create_simple_icon.sh
   ```

## 🛠️ Troubleshooting

### Common Issues

**"Application cannot be opened" (macOS)**
- Right-click → "Open" → "Open" to bypass security
- Or: System Preferences → Security & Privacy → "Open Anyway"

**"Permission denied"**
```bash
chmod +x StealthShark.app/Contents/MacOS/StealthShark
chmod +x StealthShark.desktop
```

**Desktop shortcut doesn't work**
- Verify StealthShark path in shortcut files
- Ensure `launch.sh` is executable in main directory
- Check that Python3 and dependencies are installed

**Icon not displaying**
- Run icon creation scripts
- Verify icon file exists: `stealthshark-icon.png`
- Update icon path in desktop files if needed

### Manual Launch
If shortcuts fail, you can always launch manually:
```bash
cd /path/to/StealthShark-PublicRelease
./launch.sh
```

## 📋 Technical Details

### File Structure
```
Desktop_Shortcuts/
├── StealthShark.app/
│   └── Contents/
│       ├── Info.plist          # macOS app metadata
│       └── MacOS/
│           └── StealthShark    # Launch script
├── StealthShark.desktop        # Linux desktop entry
├── stealthshark-icon.png       # Application icon
├── install_desktop_shortcut.sh # Automated installer
├── create_icon.py              # Advanced icon creator
├── create_simple_icon.sh       # Simple icon creator
└── Desktop_Shortcuts_README.md # This file
```

### Compatibility
- **macOS:** 10.15+ (Catalina and newer)
- **Linux:** Most distributions with desktop environment
- **Dependencies:** Python 3.7+, PyQt6, StealthShark requirements

## 🔄 Updates

### Updating Desktop Shortcuts
When StealthShark is updated:
1. Re-run `install_desktop_shortcut.sh`
2. Or manually update version numbers in `Info.plist`
3. Recreate icons if branding changes

### Version History
- **v1.1** (Sep 15, 2025) - Added auto-start functionality and Settings tab integration
- **v1.0** (Sep 15, 2025) - Initial desktop shortcuts for StealthShark v1.0

## 🏢 About
Created for StealthShark Anti-Pineapple Detection System  
**AIMF LLC - MobileShield Ecosystem**

## 📄 License
Same license as StealthShark main application.

---
🦈 **StealthShark Desktop Shortcuts - Easy Access to Network Protection!**
