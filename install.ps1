# CryptDriveServer Installation Script for Windows
# This script creates a virtual environment, installs dependencies, and starts the server

$ErrorActionPreference = "Stop"

Write-Host "🔧 CryptDriveServer Installation Script for Windows" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Check if Python 3 is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Python 3 is not installed." -ForegroundColor Red
    Write-Host "Please install Python 3 from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check if pip is available
try {
    $pipVersion = python -m pip --version 2>&1
    Write-Host "✓ pip found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: pip is not available." -ForegroundColor Red
    Write-Host "Please install pip for Python 3" -ForegroundColor Yellow
    exit 1
}

# Create virtual environment
Write-Host ""
Write-Host "📦 Creating virtual environment..." -ForegroundColor Cyan
if (Test-Path "venv") {
    Write-Host "⚠️  Virtual environment already exists. Removing old one..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "venv"
}

python -m venv venv
Write-Host "✓ Virtual environment created" -ForegroundColor Green

# Activate virtual environment
Write-Host ""
Write-Host "🔌 Activating virtual environment..." -ForegroundColor Cyan
& ".\venv\Scripts\Activate.ps1"
Write-Host "✓ Virtual environment activated" -ForegroundColor Green

# Upgrade pip
Write-Host ""
Write-Host "⬆️  Upgrading pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip

# Install dependencies from modules.txt
Write-Host ""
if (Test-Path "src\modules.txt") {
    Write-Host "📥 Installing dependencies from src\modules.txt..." -ForegroundColor Cyan
    pip install -r src\modules.txt
    Write-Host "✓ Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "⚠️  Warning: src\modules.txt not found. Skipping dependency installation." -ForegroundColor Yellow
}

# Installation complete
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan

# Start the server
Write-Host ""
Write-Host "🚀 Starting CryptDriveServer..." -ForegroundColor Cyan
Write-Host ""
python src\main.py