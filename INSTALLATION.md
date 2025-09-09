# StealthShark Installation Guide
**Quick Setup for Public Release v1.0**

## 🚀 One-Command Installation

### macOS Quick Start
```bash
# 1. Download and extract StealthShark-AntiPineapple-v1.0
# 2. Open Terminal and navigate to the folder
cd StealthShark-AntiPineapple-v1.0

# 3. Make launcher executable and run
chmod +x launch.sh
./launch.sh
```

## 🔧 Manual Setup (if needed)

### Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### Configure Your Network Protection
1. **Find your WiFi information:**
   ```bash
   # Get current WiFi BSSID and SSID
   /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
   ```

2. **Update configuration files:**
   - Edit `csv_import_dialog.py` (lines 407-408)
   - Edit `anti_pineapple_gui/simple_gui.py` (lines 100-101)
   - Replace `YOUR_NETWORK_BSSID_HERE` with your actual BSSID
   - Replace `YOUR_NETWORK_NAME_HERE` with your actual SSID

### Launch Application
```bash
python3 anti_pineapple_gui/simple_gui.py
```

## ✅ Verification
- GUI should launch with StealthShark interface
- CSV import should work with sample_bssids.csv
- Your network should be auto-excluded from imports

## 🛠️ Troubleshooting
- **Permission denied:** `chmod +x launch.sh`
- **Python not found:** Install Python 3.7+
- **Missing packages:** `pip3 install -r requirements.txt`

Ready to protect against pineapple attacks! 🦈🛡️
