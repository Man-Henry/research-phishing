@echo off
REM Desktop Application Setup Script for Windows
REM This script installs all dependencies and configures the application
REM Run with: setup.bat or double-click this file

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║  Phishing Detection Suite - Setup Wizard for Windows      ║
echo ║  Building Desktop Application                             ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python not found!
    echo.
    echo Please install Python 3.9 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo ✓ Python found
python --version
echo.

REM Step 1: Upgrade pip
echo [1/5] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Warning: Could not upgrade pip
) else (
    echo ✓ pip upgraded
)
echo.

REM Step 2: Install dependencies
echo [2/5] Installing dependencies...
echo Installing: PyQt6, scikit-learn, pandas, numpy, nltk, requests, beautifulsoup4
python -m pip install -q PyQt6 PyQt6-Charts scikit-learn pandas numpy nltk requests beautifulsoup4 joblib
if errorlevel 1 (
    echo ❌ ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo ✓ All dependencies installed
echo.

REM Step 3: Download NLTK data
echo [3/5] Downloading NLTK data...
python -c "import nltk; nltk.download('punkt', quiet=True); nltk.download('stopwords', quiet=True); nltk.download('wordnet', quiet=True)" 2>nul
echo ✓ NLTK data ready
echo.

REM Step 4: Create directories
echo [4/5] Creating application directories...
if not exist "%USERPROFILE%\.phishing_detector" mkdir "%USERPROFILE%\.phishing_detector"
if not exist "%USERPROFILE%\.phishing_detector\logs" mkdir "%USERPROFILE%\.phishing_detector\logs"
if not exist "%USERPROFILE%\.phishing_detector\cache" mkdir "%USERPROFILE%\.phishing_detector\cache"
if not exist "%USERPROFILE%\.phishing_detector\results" mkdir "%USERPROFILE%\.phishing_detector\results"
echo ✓ Directories created at: %USERPROFILE%\.phishing_detector
echo.

REM Step 5: Create configuration file
echo [5/5] Creating configuration file...
(
    echo {
    echo     "version": "1.0.0",
    echo     "threshold": 50,
    echo     "auto_analyze": false,
    echo     "save_logs": true,
    echo     "theme": "Light",
    echo     "log_level": "INFO",
    echo     "cache_enabled": true,
    echo     "cache_size_mb": 100,
    echo     "auto_update": true
    echo }
) > "%USERPROFILE%\.phishing_detector\config.json"
echo ✓ Configuration file created
echo.

REM Step 6: Create desktop shortcut
echo Creating desktop shortcut...
powershell -NoProfile -Command ^
    "$desktop = [Environment]::GetFolderPath('Desktop'); ^
    $currentDir = Get-Location | Select-Object -ExpandProperty Path; ^
    $appPath = Join-Path $currentDir 'desktop_app.py'; ^
    $shell = New-Object -ComObject WScript.Shell; ^
    $shortcut = $shell.CreateShortcut($desktop + '\\Phishing Detection Suite.lnk'); ^
    $shortcut.TargetPath = 'python.exe'; ^
    $shortcut.Arguments = $appPath; ^
    $shortcut.WorkingDirectory = $currentDir; ^
    $shortcut.Description = 'Email Phishing Detection and Malware Analysis Suite'; ^
    $shortcut.Save(); ^
    Write-Host 'Created desktop shortcut'"
if errorlevel 0 (
    echo ✓ Desktop shortcut created
)
echo.

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║  Setup Complete! ✅                                       ║
echo ╚════════════════════════════════════════════════════════════╝
echo.
echo Your Phishing Detection Suite is ready to use!
echo.
echo Quick Start:
echo ─────────────────────────────────────────────────────────────
echo 1. Look for "Phishing Detection Suite" shortcut on Desktop
echo 2. Double-click to launch the application
echo 3. Or run from command line:
echo    python desktop_app.py
echo.
echo Features:
echo ─────────────────────────────────────────────────────────────
echo ✓ Email Phishing Detector - Analyze emails for phishing
echo ✓ File Malware Analyzer - Scan files for malware
echo ✓ Real-time threat assessment
echo ✓ Confidence scores and risk levels
echo ✓ File hash calculation (MD5, SHA1, SHA256)
echo.
echo Help:
echo ─────────────────────────────────────────────────────────────
echo • Check the Help tab in the application
echo • Read DESKTOP_GUIDE.md for detailed instructions
echo • Use Settings tab to configure preferences
echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║  Happy analyzing! 🛡️                                       ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

pause
