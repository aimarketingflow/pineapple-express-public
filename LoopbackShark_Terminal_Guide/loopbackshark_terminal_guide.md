# LoopbackShark Terminal Guide
**AIMF LLC - Advanced Network Analytics**

## Quick Start Commands

### GUI Mode
```bash
# Launch LoopbackShark GUI
python3 loopbackshark_gui.py

# Or use desktop launcher
./LoopbackShark.command
```

### CLI Mode - Basic Commands
```bash
# Basic 30-minute loopback monitoring
python3 cli_loopbackshark.py --duration 1800

# Quick 5-minute test
python3 cli_loopbackshark.py --duration 300

# Run diagnostic test
python3 cli_loopbackshark.py --diagnostic
```

### CLI Mode - Advanced Options
```bash
# Monitor specific ports with debug logging
python3 cli_loopbackshark.py --port-filter 3000,8080,9000 --debug

# TCP-only monitoring for 2 hours  
python3 cli_loopbackshark.py --duration 7200 --protocol tcp

# Full day monitoring with custom output directory
python3 cli_loopbackshark.py --duration 86400 --output-dir ./daily_analysis

# Monitor database ports for 1 hour
python3 cli_loopbackshark.py --port-filter 3306,5432,6379,27017 --duration 3600
```

### Setup Commands
```bash
# Create virtual environment
python3 -m venv venv_loopbackshark

# Activate virtual environment  
source venv_loopbackshark/bin/activate

# Install dependencies
pip3 install -r requirements_loopbackshark.txt

# Make launcher executable
chmod +x LoopbackShark.command
```

### Useful Aliases
Add these to your ~/.zshrc or ~/.bash_profile:

```bash
# LoopbackShark aliases
alias lbshark='cd /path/to/LoopbackShark && python3 cli_loopbackshark.py'
alias lbshark-gui='cd /path/to/LoopbackShark && python3 loopbackshark_gui.py'
alias lbshark-test='cd /path/to/LoopbackShark && python3 cli_loopbackshark.py --diagnostic'
alias lbshark-dev='cd /path/to/LoopbackShark && python3 cli_loopbackshark.py --port-filter 3000,8080,8081,9000 --duration 3600'
```

### Common Port Filters
```bash
# Development servers
--port-filter 3000,8000,8080,9000

# Databases  
--port-filter 3306,5432,6379,27017

# Web services
--port-filter 80,443,8080,8443

# Development stack
--port-filter 3000,3001,8080,9000,5432,6379
```

### Output Analysis
```bash
# View generated reports
ls -la analysis_results/

# Check capture files
ls -la pcap_captures/

# View session logs
ls -la persistent_logs/

# Open latest analysis report
open analysis_results/loopback_summary_*.md
```

### Troubleshooting
```bash
# Check if tshark is installed
which tshark

# Check loopback interface
ifconfig lo0

# Check permissions (if needed)
sudo python3 cli_loopbackshark.py --diagnostic

# Clean up test files
rm -rf test_capture/
```

---
*LoopbackShark Terminal Guide - AIMF LLC*
