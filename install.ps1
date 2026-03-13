# CryptDriveServer Installation Script for Windows
# This script creates a virtual environment, installs dependencies from pyproject.toml, and starts the server

$ErrorActionPreference = "Stop"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "🔧 CryptDriveServer Installation Script for Windows" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

# Check if Python 3 is installed
try {
    $pythonVersion = py --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Python 3 is not installed." -ForegroundColor Red
    Write-Host "Please install Python 3 from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check if pip is available
try {
    $pipVersion = py -m pip --version 2>&1
    Write-Host "✓ pip found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: pip is not available." -ForegroundColor Red
    Write-Host "Please install pip for Python 3" -ForegroundColor Yellow
    exit 1
}

# Check if pyproject.toml exists
if (-not (Test-Path "pyproject.toml")) {
    Write-Host "❌ Error: pyproject.toml not found in project root." -ForegroundColor Red
    exit 1
}

# Create virtual environment
Write-Host ""
Write-Host "📦 Creating virtual environment..." -ForegroundColor Cyan
if (Test-Path ".venv") {
    Write-Host "⚠️  Virtual environment already exists. Removing old one..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force ".venv"
}

py -m venv .venv
Write-Host "✓ Virtual environment created" -ForegroundColor Green

# Activate virtual environment
Write-Host ""
Write-Host "🔌 Activating virtual environment..." -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"
Write-Host "✓ Virtual environment activated" -ForegroundColor Green

# Upgrade pip
Write-Host ""
Write-Host "⬆️  Upgrading pip..." -ForegroundColor Cyan
py -m pip install --upgrade pip

# Install dependencies from pyproject.toml
Write-Host ""
Write-Host "📥 Installing project dependencies from pyproject.toml..." -ForegroundColor Cyan
py -m pip install .
Write-Host "✓ Dependencies installed successfully" -ForegroundColor Green

# Installation complete
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan

# Start the server
Write-Host ""
Write-Host "🚀 Starting CryptDriveServer..." -ForegroundColor Cyan
Write-Host ""
py src\main.py