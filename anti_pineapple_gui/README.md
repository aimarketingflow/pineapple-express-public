# 🛡️ Anti-Pineapple BSSID NFC Security System

## Overview
Advanced WiFi Pineapple detection and prevention system with NFC-based authentication and automatic network verification.

## Features
- **🔐 NFC Authentication**: Secure tag-based authentication system
- **🌐 Network Binding**: Tags bound to specific BSSID/SSID combinations
- **🚨 Auto-Detection**: Automatic detection of WiFi Pineapple attacks
- **🔒 Auto-Start**: Runs automatically on macOS boot
- **⚠️ Network Verification**: Warns about untrusted networks before connection
- **📊 Real-time Monitoring**: Continuous network threat monitoring

## Installation

### Auto-Start Setup
```bash
# Install auto-start service
./install_autostart.sh

# Uninstall auto-start service
./uninstall_autostart.sh
```

### Manual Run
```bash
python3 anti_pineapple_gui.py
```

## How It Works

### 1. Network-Bound NFC Tags
- Register NFC tags for specific networks (BSSID + SSID)
- Tags automatically authenticate when connecting to trusted networks
- Universal tags work across all networks

### 2. Auto-Authentication
- On startup, checks current BSSID against registered network tags
- Automatically enables protection if on trusted network
- Updates last-used timestamps for audit trail

### 3. Untrusted Network Detection
- Warns when connecting to networks without registered tags
- Option to disconnect immediately from suspicious networks
- Maintains whitelist of trusted BSSIDs

### 4. Firewall Protection
- **LOCKED (Protected)**: Blocks all non-legitimate BSSIDs
- **UNLOCKED (Unprotected)**: Allows all connections (requires NFC to lock)

## Security Features

### Data Protection
- NFC tag values stored as SHA-256 hashes only
- Device-specific tag binding
- 90-day authentication expiry
- Encrypted storage in `~/.ssh/`

### Network Monitoring
- Real-time BSSID monitoring
- Threat detection and logging
- Automatic blocking of suspicious networks

## Files Structure
```
anti_pineapple_gui/
├── anti_pineapple_gui.py          # Main application
├── com.aimf.antipineapple.plist   # LaunchAgent configuration
├── install_autostart.sh           # Auto-start installer
├── uninstall_autostart.sh         # Auto-start uninstaller
├── logs/                          # Application logs
│   ├── antipineapple.log
│   └── antipineapple_error.log
└── README.md                      # This file
```

## Configuration Files
- `~/.ssh/nfc_tags.json` - Registered NFC tags
- `~/.ssh/anti_pineapple_auth.json` - Authentication profile
- `~/Library/LaunchAgents/com.aimf.antipineapple.plist` - Auto-start service

## Usage

### Register Network-Specific Tag
1. Connect to trusted WiFi network
2. Click "Register NFC for This Network"
3. Scan NFC tag when prompted
4. Tag is now bound to current BSSID/SSID

### Auto-Protection
- System automatically protects when on networks with registered tags
- Dashboard shows green "Authenticated & Protected" status
- Firewall status shows "LOCKED (Protected)"

### Manual Authentication
- Click "Unlock with NFC" on untrusted networks
- Scan registered NFC tag
- System enables protection for current session

## Logs
- Standard output: `logs/antipineapple.log`
- Error output: `logs/antipineapple_error.log`
- Console output shows real-time status

## Troubleshooting

### Service Not Starting
```bash
# Check service status
launchctl list | grep antipineapple

# Reload service
launchctl unload ~/Library/LaunchAgents/com.aimf.antipineapple.plist
launchctl load ~/Library/LaunchAgents/com.aimf.antipineapple.plist
```

### Permission Issues
```bash
# Ensure executable permissions
chmod +x install_autostart.sh uninstall_autostart.sh
chmod +x anti_pineapple_gui.py
```

## Security Considerations
- Never share NFC tag values
- Regularly rotate authentication (90-day expiry)
- Monitor logs for suspicious activity
- Keep trusted BSSID list updated

## AIMF LLC
Advanced cybersecurity technology for community protection.
