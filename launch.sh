#!/bin/bash

# StealthShark Anti-Pineapple Detection System
# Public Release v1.0
# AIMF LLC - MobileShield Ecosystem

echo "🦈 Starting StealthShark Anti-Pineapple Detection System v1.0"
echo "🛡️ AIMF LLC - MobileShield Ecosystem"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Check if we're in the right directory
if [ ! -f "anti_pineapple_gui/simple_gui.py" ]; then
    echo "❌ Error: Cannot find Anti-Pineapple GUI files"
    echo "Expected location: anti_pineapple_gui/simple_gui.py"
    echo "Current directory: $(pwd)"
    read -p "Press Enter to exit..."
    exit 1
fi

echo "✅ Found Anti-Pineapple GUI files"
echo "📁 Working directory: $(pwd)"
echo ""

# Check for Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed"
    echo "Please install Python3 and try again"
    read -p "Press Enter to exit..."
    exit 1
fi

# Check for pip3
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed"
    echo "Please install pip3 and try again"
    read -p "Press Enter to exit..."
    exit 1
fi

# Install requirements if needed
if [ -f "requirements.txt" ]; then
    echo "📦 Installing required packages..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "⚠️ Warning: Some packages may not have installed correctly"
        echo "The application may still work with existing packages"
    fi
fi

echo ""
echo "🚀 Launching StealthShark Anti-Pineapple GUI..."
python3 anti_pineapple_gui/simple_gui.py

# Keep terminal open if there's an error
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Application exited with error"
    read -p "Press Enter to close..."
fi
