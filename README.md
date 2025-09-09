# StealthShark Anti-Pineapple Detection System v1.0
**AIMF LLC - MobileShield Ecosystem**

## 🦈 Overview
StealthShark is an advanced WiFi security tool designed to detect and block pineapple attacks, rogue access points, and other wireless threats. This system provides real-time protection by maintaining a blacklist of malicious BSSIDs and automatically excluding your trusted networks.

## ✨ Key Features
- **🛡️ Real-time Pineapple Detection** - Identifies and blocks malicious WiFi access points
- **📂 CSV Import Protection** - Import threat lists while auto-protecting your current network
- **🎯 BSSID Blacklist Management** - Persistent storage of blocked networks
- **🖥️ Intuitive GUI Interface** - Easy-to-use graphical interface
- **⚡ Live WiFi Scanning** - Real-time network monitoring
- **🔒 Auto-Exclusion** - Protects your trusted networks from accidental blocking

## 🚀 Quick Start

### Prerequisites
- macOS (tested on macOS 10.15+)
- Python 3.7 or higher
- pip3 package manager

### Installation
1. Download and extract the StealthShark package
2. Open Terminal and navigate to the StealthShark directory
3. Run the launcher script:
   ```bash
   ./launch.sh
   ```

### First Time Setup
1. **Configure Your Network Protection:**
   - Edit `csv_import_dialog.py` and `anti_pineapple_gui/simple_gui.py`
   - Replace `YOUR_NETWORK_BSSID_HERE` with your WiFi's BSSID
   - Replace `YOUR_NETWORK_NAME_HERE` with your WiFi's SSID

2. **Find Your Network Information:**
   ```bash
   # On macOS, get current WiFi info:
   /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
   ```

## 📖 Usage Guide

### Main Interface
- **Live Scan** - Monitor for threats in real-time
- **CSV Import** - Import threat databases from WiFi analysis tools
- **Blacklist Management** - View and manage blocked BSSIDs
- **Status Dashboard** - Monitor system status and threat counts

### CSV Import
1. Click "📂 Import CSV" button
2. Select a CSV file with columns: SSID, BSSID, Channel, Security, Signal
3. Review the networks to import
4. Your trusted network will be automatically excluded
5. Confirm import to add threats to blacklist

### Sample CSV Format
```csv
SSID,BSSID,Channel,Security,Signal
EvilTwin_Example,AA:BB:CC:DD:EE:FF,6,WPA2,"-45 dBm"
Pineapple_Demo,11:22:33:44:55:66,11,Open,"-38 dBm"
```

## 🔧 Configuration

### Network Protection Setup
Edit the following files to protect your network:

**csv_import_dialog.py** (lines 407-408):
```python
current_bssid = "YOUR_ACTUAL_BSSID"  # e.g., "AA:BB:CC:DD:EE:FF"
current_ssid = "YOUR_NETWORK_NAME"   # e.g., "MyHomeWiFi"
```

**anti_pineapple_gui/simple_gui.py** (lines 100-101):
```python
current_bssid = "YOUR_ACTUAL_BSSID"  # e.g., "AA:BB:CC:DD:EE:FF"
current_ssid = "YOUR_NETWORK_NAME"   # e.g., "MyHomeWiFi"
```

## 📁 File Structure
```
StealthShark-AntiPineapple-v1.0/
├── anti_pineapple_gui/          # Main GUI application
│   └── simple_gui.py            # Primary interface
├── csv_import_dialog.py         # CSV import functionality
├── bssid_blacklist_manager.py   # Blacklist management
├── blacklist.json              # BSSID blacklist storage
├── sample_bssids.csv           # Example threat data
├── requirements.txt            # Python dependencies
├── launch.sh                   # Launch script
└── README.md                   # This file
```

## 🛡️ Security Features

### Auto-Exclusion Protection
- Automatically protects your configured trusted network
- Prevents accidental blocking of your current WiFi
- Works with both BSSID and SSID matching

### Threat Detection
- Identifies pineapple attacks and evil twin networks
- Monitors for rogue access points
- Maintains persistent blacklist across sessions

### Privacy Protection
- No data transmitted to external servers
- Local storage of all configuration and blacklists
- User-controlled network information

## 🔍 Troubleshooting

### Common Issues
1. **"Cannot find GUI files"** - Ensure you're running from the correct directory
2. **Python not found** - Install Python 3.7+ and pip3
3. **Permission denied** - Run `chmod +x launch.sh` to make launcher executable
4. **Import errors** - Install requirements: `pip3 install -r requirements.txt`

### Getting Help
- Check console output for detailed error messages
- Ensure all dependencies are installed
- Verify network configuration is correct

## 📋 Requirements
- Python 3.7+
- PyQt6
- pathlib
- json
- csv
- subprocess
- logging

## 🏢 About AIMF LLC
StealthShark is part of the MobileShield ecosystem by AIMF LLC, providing advanced mobile and wireless security solutions.

## 📄 License
This software is provided as-is for educational and security research purposes.

---
**Version:** 1.0  
**Release Date:** September 9, 2025  
**Compatibility:** macOS 10.15+  

🦈 **Stay protected with StealthShark!**
