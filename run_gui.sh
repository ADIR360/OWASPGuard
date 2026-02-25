#!/bin/bash
# Simple launcher script for Mini-ZAP GUI

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Virtual environment not found. Please run ./setup.sh first"
    exit 1
fi

# Run the GUI
python gui.py

