#!/bin/bash

# Desktop Application Setup Script for macOS and Linux
# This script installs all dependencies and configures the application
# Run with: bash setup.sh or ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Phishing Detection Suite - Setup Wizard                 ║"
echo "║  Building Desktop Application                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    PYTHON_CMD="python3"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    PYTHON_CMD="python3"
else
    OS="Unknown"
    PYTHON_CMD="python3"
fi

echo "Detected OS: $OS"
echo ""

# Step 1: Check Python
echo "[1/6] Checking Python installation..."
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${RED}❌ ERROR: Python not found!${NC}"
    echo ""
    echo "Please install Python 3.9 or higher:"
    echo ""
    if [[ "$OS" == "Linux" ]]; then
        echo "Ubuntu/Debian:"
        echo "  sudo apt install python3 python3-pip python3-venv"
        echo ""
        echo "Fedora/RHEL:"
        echo "  sudo dnf install python3 python3-pip"
        echo ""
        echo "Arch:"
        echo "  sudo pacman -S python python-pip"
    else
        echo "macOS:"
        echo "  brew install python@3.11"
        echo ""
        echo "Or download from: https://www.python.org/downloads/"
    fi
    echo ""
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
echo ""

# Step 2: Create virtual environment (optional)
echo "[2/6] Setting up Python environment..."
if [ -d "venv" ]; then
    echo "Activating existing virtual environment..."
    source venv/bin/activate
else
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    source venv/bin/activate
    echo -e "${GREEN}✓${NC} Virtual environment created"
fi
echo ""

# Step 3: Upgrade pip
echo "[3/6] Upgrading pip..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1 || true
echo -e "${GREEN}✓${NC} pip upgraded"
echo ""

# Step 4: Install dependencies
echo "[4/6] Installing Python dependencies..."
echo "Installing: PyQt6, scikit-learn, pandas, numpy, nltk, requests, beautifulsoup4"
PACKAGES=(
    "PyQt6>=6.0.0"
    "PyQt6-Charts>=6.0.0"
    "scikit-learn>=1.0.0"
    "pandas>=1.3.0"
    "numpy>=1.20.0"
    "nltk>=3.6.0"
    "requests>=2.26.0"
    "beautifulsoup4>=4.9.0"
    "joblib>=1.0.0"
)

for package in "${PACKAGES[@]}"; do
    echo "  Installing $package..."
    pip install -q "$package" || echo -e "${YELLOW}⚠${NC}  Warning: Could not install $package"
done

echo -e "${GREEN}✓${NC} All dependencies installed"
echo ""

# Step 5: Download NLTK data
echo "[5/6] Downloading NLTK data..."
$PYTHON_CMD << 'EOF'
import nltk
import ssl

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

print("Downloading NLTK datasets...")
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)
print("✓ NLTK data ready")
EOF
echo ""

# Step 6: Create application directories
echo "[6/6] Creating application directories..."
mkdir -p ~/.phishing_detector/logs
mkdir -p ~/.phishing_detector/cache
mkdir -p ~/.phishing_detector/results

# Create config file
cat > ~/.phishing_detector/config.json << 'EOF'
{
    "version": "1.0.0",
    "threshold": 50,
    "auto_analyze": false,
    "save_logs": true,
    "theme": "Light",
    "log_level": "INFO",
    "cache_enabled": true,
    "cache_size_mb": 100,
    "auto_update": true
}
EOF

echo -e "${GREEN}✓${NC} Configuration directories created at ~/.phishing_detector"
echo ""

# Create desktop entry for Linux
if [[ "$OS" == "Linux" ]]; then
    echo "Creating desktop entry..."
    CURRENT_DIR=$(pwd)
    
    mkdir -p ~/.local/share/applications
    
    cat > ~/.local/share/applications/phishing-detection-suite.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Phishing Detection Suite
Comment=Email Phishing Detection and Malware Analysis Tool
Exec=bash -c 'cd $CURRENT_DIR && source venv/bin/activate 2>/dev/null; python3 desktop_app.py'
Icon=security-tools
Terminal=false
Categories=Security;System;Utility;
EOF

    echo -e "${GREEN}✓${NC} Desktop entry created"
fi

# macOS application alias
if [[ "$OS" == "macOS" ]]; then
    echo "Creating macOS launcher..."
    CURRENT_DIR=$(pwd)
    
    mkdir -p ~/Applications
    
    cat > ~/Applications/Phishing\ Detection\ Suite.command << 'EOF'
#!/bin/bash
cd "SCRIPT_DIR"
source venv/bin/activate 2>/dev/null || true
python3 desktop_app.py
EOF
    
    sed -i '' "s|SCRIPT_DIR|$CURRENT_DIR|g" ~/Applications/Phishing\ Detection\ Suite.command
    chmod +x ~/Applications/Phishing\ Detection\ Suite.command
    
    echo -e "${GREEN}✓${NC} macOS launcher created in ~/Applications"
fi

# Final summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Setup Complete! ✅                                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Your Phishing Detection Suite is ready to use!"
echo ""
echo "Quick Start:"
echo "─────────────────────────────────────────────────────────────"

if [[ "$OS" == "Linux" ]]; then
    echo "1. Search for 'Phishing Detection Suite' in your applications menu"
    echo "2. Or run from terminal:"
    echo "   source venv/bin/activate"
    echo "   python3 desktop_app.py"
else
    echo "1. Open ~/Applications/Phishing Detection Suite.command"
    echo "2. Or run from terminal:"
    echo "   source venv/bin/activate"
    echo "   python3 desktop_app.py"
fi

echo ""
echo "Features:"
echo "─────────────────────────────────────────────────────────────"
echo "✓ Email Phishing Detector - Analyze emails for phishing"
echo "✓ File Malware Analyzer - Scan files for malware"
echo "✓ Real-time threat assessment"
echo "✓ Confidence scores and risk levels"
echo "✓ File hash calculation (MD5, SHA1, SHA256)"
echo ""
echo "Help:"
echo "─────────────────────────────────────────────────────────────"
echo "• Check the Help tab in the application"
echo "• Read DESKTOP_GUIDE.md for detailed instructions"
echo "• Use Settings tab to configure preferences"
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Happy analyzing! 🛡️                                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
