# LoopbackShark - Loopback Traffic Monitor & Analyzer

**AIMF LLC**  
Advanced loopback network traffic monitoring and trend analysis tool

## Overview
LoopbackShark is a specialized network monitoring application designed specifically for capturing, analyzing, and visualizing loopback interface traffic patterns. It provides real-time monitoring of localhost communications and identifies trends in application-to-application communications on your system.

## Key Features
- **Loopback-Specific Monitoring**: Focuses exclusively on loopback (127.0.0.1/::1) traffic
- **Trend Analysis**: Identifies patterns in local application communications
- **Real-time Visualization**: Live charts showing traffic patterns and port usage
- **Application Detection**: Attempts to identify which applications are communicating
- **Advanced Filtering**: Filter by ports, protocols, and application signatures
- **Comprehensive Logging**: Detailed logs with trend analysis reports

## Installation & Setup

### Virtual Environment Setup
```bash
# Create virtual environment
python3 -m venv venv_loopbackshark

# Activate virtual environment
source venv_loopbackshark/bin/activate

# Install dependencies
pip3 install -r requirements_loopbackshark.txt
```

### Required Permissions
LoopbackShark requires root/sudo permissions for packet capture:
```bash
# Run with sudo
sudo python3 loopbackshark_gui.py

# Or setup passwordless capture (recommended)
./setup_passwordless_capture.sh
```

## Usage

### GUI Mode
```bash
python3 loopbackshark_gui.py
```

### CLI Mode
```bash
python3 cli_loopbackshark.py --duration 3600 --output-dir ./analysis_results
```

### Available CLI Options
- `--duration`: Capture duration in seconds (default: 1800)
- `--output-dir`: Output directory for captures and analysis
- `--port-filter`: Filter specific ports (comma-separated)
- `--protocol`: Filter by protocol (tcp/udp/all)
- `--diagnostic`: Run diagnostic test mode
- `--debug`: Enable verbose debug logging

## Example Commands
```bash
# Basic 30-minute loopback monitoring
python3 cli_loopbackshark.py --duration 1800

# Monitor specific ports with debug logging
python3 cli_loopbackshark.py --port-filter 3000,8080,9000 --debug

# Full day monitoring with trend analysis
python3 cli_loopbackshark.py --duration 86400 --output-dir ./daily_analysis
```

## Output Files
- **PCAP Files**: Raw packet captures in `pcap_captures/`
- **Analysis Reports**: Trend analysis in `analysis_results/`
- **Session Logs**: Detailed logs in `persistent_logs/`
- **Charts & Graphs**: Visual analysis in `analysis_results/charts/`

## Architecture
- `loopbackshark_gui.py`: Main GUI application
- `cli_loopbackshark.py`: Command-line interface
- `loopback_monitor.py`: Core monitoring engine
- `utils/`: Helper functions for parsing and analysis
- `trend_analyzer.py`: Advanced trend analysis engine

## Requirements
- Python 3.8+
- PyQt6 (for GUI)
- tshark/Wireshark
- psutil
- matplotlib (for charts)
- pandas (for data analysis)

## License
Copyright 2025 AIMF LLC. All rights reserved.
