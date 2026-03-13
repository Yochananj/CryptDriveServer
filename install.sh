#!/bin/bash

# CryptDriveServer Installation Script for macOS
# This script creates a virtual environment, installs dependencies from pyproject.toml, and starts the server

set -e  # Exit on error

echo "=================================================="
echo "🔧 CryptDriveServer Installation Script for macOS"
echo "=================================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed."
    echo "Please install Python 3 from https://www.python.org/downloads/"
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"

# Check if pip is available
if ! python3 -m pip --version &> /dev/null; then
    echo "❌ Error: pip is not available."
    echo "Please install pip for Python 3"
    exit 1
fi

echo "✓ pip found: $(python3 -m pip --version)"

# Check if pyproject.toml exists
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: pyproject.toml not found in project root."
    exit 1
fi

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
if [ -d ".venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing old one..."
    rm -rf .venv
fi

python3 -m venv .venv
echo "✓ Virtual environment created"

# Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source .venv/bin/activate
echo "✓ Virtual environment activated"

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies from pyproject.toml
echo ""
echo "📥 Installing project dependencies from pyproject.toml..."
python -m pip install .
echo "✓ Dependencies installed successfully"

# Installation complete
echo ""
echo "=================================================="
echo "✅ Installation completed successfully!"
echo "=================================================="

# Start the server
echo ""
echo "🚀 Starting CryptDriveServer..."
echo ""
python src/main.py