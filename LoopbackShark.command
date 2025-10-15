#!/bin/bash
# LoopbackShark Desktop Launcher
# AIMF LLC - Advanced Network Analytics

echo "🦈 Starting LoopbackShark GUI..."
echo "AIMF LLC - Advanced Network Analytics"
echo "Specialized Loopback Traffic Monitor"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv_loopbackshark" ]; then
    echo "🔧 Setting up LoopbackShark virtual environment..."
    python3 -m venv venv_loopbackshark
    source venv_loopbackshark/bin/activate
    pip3 install -r requirements_loopbackshark.txt
    echo "✅ Virtual environment setup complete"
else
    echo "🔧 Activating LoopbackShark virtual environment..."
    source venv_loopbackshark/bin/activate
fi

# Check dependencies
echo "🔍 Checking dependencies..."
if ! command -v tshark &> /dev/null; then
    echo "❌ tshark not found. Please install Wireshark:"
    echo "   brew install wireshark"
    echo "   or download from https://www.wireshark.org/download.html"
    exit 1
fi

echo "✅ Dependencies check passed"
echo ""

# Launch LoopbackShark GUI
echo "🚀 Launching LoopbackShark GUI..."
python3 loopbackshark_gui.py

echo ""
echo "👋 LoopbackShark session ended"
echo "Press any key to close this window..."
read -n 1
