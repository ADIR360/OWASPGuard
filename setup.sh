#!/bin/bash
# Setup script for Mini-ZAP

echo "Setting up Mini-ZAP..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Setup complete!"
echo ""
echo "To run the GUI, use:"
echo "  source venv/bin/activate"
echo "  python gui.py"
echo ""
echo "Or use the run script:"
echo "  ./run_gui.sh"

