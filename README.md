# Persistent Wireshark Suite 🦈
**Advanced Network Security & Monitoring Tools by AIMF LLC**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)

## 🎯 Overview

This repository contains two powerful network monitoring and security applications:

### 🛡️ StealthShark Anti-Pineapple Detection System v1.1
Advanced WiFi security tool designed to detect and block pineapple attacks, rogue access points, and other wireless threats. Provides real-time protection with automatic blacklist management and trusted network exclusion.

### 🔍 LoopbackShark 
Specialized localhost traffic monitor with pattern recognition capabilities for capturing, analyzing, and visualizing loopback interface communications.

## ✨ StealthShark Features
- **🛡️ Real-time Pineapple Detection** - Identifies and blocks malicious WiFi access points
- **⚙️ Settings Tab** - Configure monitoring duration (default: 6 hours) and auto-start
- **🚀 Auto-Start Functionality** - Automatic launch at computer boot with LaunchAgent
- **📂 CSV Import Protection** - Import threat lists while auto-protecting your current network
- **🎯 BSSID Blacklist Management** - Persistent storage of blocked networks
- **🖥️ Desktop Integration** - Native .app bundle and .desktop shortcuts
- **⚡ Live WiFi Scanning** - Real-time network monitoring with configurable intervals
- **🔒 Auto-Exclusion** - Protects your trusted networks from accidental blocking

## 🔥 LoopbackShark Features
- **🎯 Pattern Recognition** - Automatic detection of web servers, databases, APIs
- **📊 Real-time Analysis** - Live monitoring with PyQt6 GUI and dark theme
- **🔍 Application Detection** - Identifies Redis, MySQL, HTTP servers, Node.js, and more
- **📈 Historical Analysis** - Trend analysis from captured data
- **⚙️ Smart Configuration** - Persistent settings with 24-hour default monitoring
- **🖥️ Desktop Integration** - Easy access via command launcher
- **🔌 All Ports Monitoring** - Smart port filtering with toggle functionality
- **📋 Comprehensive Reporting** - JSON and Markdown output formats

## 🚀 Quick Start

### Prerequisites
- macOS (tested on macOS 10.15+)
- Python 3.7+ or higher
- pip3 package manager

## 🛡️ StealthShark Installation & Usage

### Quick Installation
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
=======

```bash
# Install Wireshark (includes tshark)
brew install wireshark

# Configure BPF permissions for unprivileged capture
sudo /usr/local/bin/wireshark-chmodbpf
```

### Installation

```bash
git clone https://github.com/aimarketingflow/persistent-wireshark.git
cd persistent-wireshark
python3 -m venv venv_loopbackshark
source venv_loopbackshark/bin/activate
pip3 install -r requirements_loopbackshark.txt
```

### Launch Options

**🖥️ GUI Application (Recommended)**
```bash
./LoopbackShark.command
```

**⚡ Command Line Interface**
```bash
python3 cli_loopbackshark.py --duration 3600 --debug
```

**🧪 Test Pattern Recognition**
```bash
python3 test_traffic_generator.py
```

## 📊 Features Overview

### Pattern Recognition Engine
- **Automatic Application Detection**: Identifies common localhost applications
- **Port Analysis**: Recognizes development servers, databases, and APIs  
- **Confidence Scoring**: Advanced pattern matching with reliability metrics
- **Real-time Updates**: Live pattern detection during monitoring

### GUI Dashboard
- **Live Monitor Tab**: Real-time packet capture and analysis
- **Trend Analysis Tab**: Historical traffic patterns and statistics
- **Statistics Tab**: Port usage, application detection metrics
- **Pattern Recognition Tab**: Live application detection with confidence scores

### Smart Configuration
- **Persistent Settings**: Automatically saves capture directory and duration
- **24-Hour Default**: Optimized for continuous development monitoring
- **All Ports Mode**: Monitor all localhost traffic or filter specific ports
- **Auto-detection**: Intelligent path resolution for cross-platform compatibility

## 🔧 Configuration

### Settings File
LoopbackShark automatically creates `loopbackshark_settings.json`:

```json
{
  "capture_directory": "./pcap_captures",
  "monitoring_duration": 86400,
  "port_filter": null,
  "all_ports_enabled": true
}
```

### Pattern Templates
Pre-built pattern recognition templates in `pattern_templates/`:
- `loopback_pattern_templates.json` - Comprehensive application signatures
- `simple_port_patterns.json` - Basic port-to-application mappings

## 📁 Project Structure

```
LoopbackShark/
├── loopbackshark_gui.py           # Main GUI application
├── cli_loopbackshark.py           # Command line interface
├── loopback_monitor.py            # Core monitoring engine
├── pattern_recognition.py         # Advanced pattern detection
├── pattern_analyzer.py            # Historical pattern analysis
├── test_traffic_generator.py      # Testing and validation
├── LoopbackShark.command          # Desktop launcher
├── requirements_loopbackshark.txt # Python dependencies
├── pattern_templates/             # Pre-built patterns
├── pcap_captures/                 # Capture file storage
├── analysis_results/              # Output reports
└── LoopbackShark_Terminal_Guide/  # Comprehensive documentation
```

## 🎮 Usage Examples

### Basic Monitoring
```bash
# Monitor for 1 hour with pattern recognition
python3 cli_loopbackshark.py --duration 3600 --patterns

# Monitor specific ports only
python3 cli_loopbackshark.py --ports 3000,8080,5432

# Debug mode with verbose logging
python3 cli_loopbackshark.py --debug --duration 300
```

### Advanced Features
```bash
# Generate test traffic for validation
python3 test_traffic_generator.py

# Extract patterns from historical data
python3 quick_pattern_extractor.py

# Analyze historical captures
python3 pattern_analyzer.py
```

## 📈 Output Formats

### Analysis Reports
- **JSON Format**: Machine-readable analysis results
- **Markdown Summary**: Human-readable traffic reports
- **Pattern Analysis**: Application detection results with confidence scores

### Sample Output
```json
{
  "session_info": {
    "session_id": "20250908_135520",
    "duration": 3600,
    "packets_analyzed": 1247
  },
  "pattern_recognition": {
    "detected_applications": [
      {"app": "Node.js Server", "port": 3000, "confidence": 0.95},
      {"app": "Redis", "port": 6379, "confidence": 0.88}
    ],
    "detection_rate": 0.73
  }
}
```

## 🔍 Pattern Recognition

LoopbackShark includes advanced pattern recognition for:

**Development Servers:**
- Node.js, Flask, Django development servers
- React, Vue.js dev servers
- Static file servers

**Databases:**
- MySQL, PostgreSQL, MongoDB
- Redis, Memcached
- SQLite connections

**APIs & Services:**
- REST APIs, GraphQL endpoints
- Microservices communication
- Docker container networking

## 🛠️ Development

### Running Tests
```bash
python3 -m pytest tests/
```

### Building Documentation
```bash
cd LoopbackShark_Terminal_Guide/
python3 -m http.server 8000
```

## 📞 Support & Contributing

- **Issues**: [GitHub Issues](https://github.com/aimarketingflow/persistent-wireshark/issues)
- **Documentation**: See `LoopbackShark_Terminal_Guide/` directory
- **Contributing**: Pull requests welcome!

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

---

**Built for developers, by developers** 🚀

*LoopbackShark - Advanced localhost monitoring for modern development workflows.*
>>>>>>> 8853b728ead321521b4a5da305036929092dea2b
