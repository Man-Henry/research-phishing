"""
Build installer and packaged executable for desktop application
Supports Windows (.exe), macOS (.app), and Linux (.deb)
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import platform


def run_command(cmd, description=""):
    """Run command and handle output"""
    if description:
        print(f"\n{'='*70}")
        print(f"▶ {description}")
        print(f"{'='*70}")
    print(f"$ {cmd}\n")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"❌ Failed: {description}")
        return False
    return True


def create_windows_installer():
    """Create Windows MSI installer using NSIS"""
    print("\n🪟 Building Windows Installer...")
    
    # Create NSIS script
    nsis_script = """
    ; NSIS Installer Script for Phishing Detection Tool
    !include "MUI2.nsh"
    
    !define PRODUCT_NAME "Phishing Detection Suite"
    !define PRODUCT_VERSION "1.0.0"
    !define PRODUCT_PUBLISHER "Security Tools"
    !define PRODUCT_WEB_SITE "https://github.com"
    
    Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
    OutFile "dist/PhishingDetectionSuite-1.0.0-Setup.exe"
    InstallDir "$PROGRAMFILES\\PhishingDetectionSuite"
    
    !insertmacro MUI_PAGE_WELCOME
    !insertmacro MUI_PAGE_DIRECTORY
    !insertmacro MUI_PAGE_INSTFILES
    !insertmacro MUI_PAGE_FINISH
    
    !insertmacro MUI_LANGUAGE "English"
    
    Section "Install"
        SetOutPath "$INSTDIR"
        File "dist/PhishingDetectionSuite.exe"
        File "dist/library.zip"
        
        ; Create shortcuts
        CreateDirectory "$SMPROGRAMS\\${PRODUCT_NAME}"
        CreateShortCut "$SMPROGRAMS\\${PRODUCT_NAME}\\${PRODUCT_NAME}.lnk" "$INSTDIR\\PhishingDetectionSuite.exe"
        CreateShortCut "$DESKTOP\\${PRODUCT_NAME}.lnk" "$INSTDIR\\PhishingDetectionSuite.exe"
    SectionEnd
    
    Section "Uninstall"
        RMDir /r "$INSTDIR"
        RMDir /r "$SMPROGRAMS\\${PRODUCT_NAME}"
        Delete "$DESKTOP\\${PRODUCT_NAME}.lnk"
    SectionEnd
    """
    
    installer_path = Path("dist/installer.nsi")
    installer_path.parent.mkdir(parents=True, exist_ok=True)
    installer_path.write_text(nsis_script)
    
    print("✓ NSIS script created: dist/installer.nsi")
    print("  Note: To build the MSI, install NSIS and run: makensis.exe dist/installer.nsi")
    return True


def create_windows_batch_installer():
    """Create simple batch installer for Windows"""
    batch_script = """@echo off
setlocal enabledelayedexpansion

echo.
echo ========================================
echo Phishing Detection Suite - Installer
echo ========================================
echo.

REM Create program files directory
set INSTALL_DIR=%ProgramFiles%\\PhishingDetectionSuite
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Installing application...
copy /Y PhishingDetectionSuite.exe "%INSTALL_DIR%\\" >nul
if errorlevel 1 (
    echo Error: Failed to copy executable
    exit /b 1
)

REM Create shortcuts
echo Creating desktop shortcut...
powershell -NoProfile -Command ^
    "$desktop = [Environment]::GetFolderPath('Desktop'); ^
    $shell = New-Object -ComObject WScript.Shell; ^
    $shortcut = $shell.CreateShortcut($desktop + '\\Phishing Detection Suite.lnk'); ^
    $shortcut.TargetPath = '!INSTALL_DIR!\\PhishingDetectionSuite.exe'; ^
    $shortcut.Save()"

REM Create start menu shortcut
powershell -NoProfile -Command ^
    "$startMenu = [Environment]::GetFolderPath('StartMenu'); ^
    $appDir = $startMenu + '\\Programs\\Phishing Detection Suite'; ^
    if (!(Test-Path $appDir)) { mkdir $appDir }; ^
    $shell = New-Object -ComObject WScript.Shell; ^
    $shortcut = $shell.CreateShortcut($appDir + '\\Phishing Detection Suite.lnk'); ^
    $shortcut.TargetPath = '!INSTALL_DIR!\\PhishingDetectionSuite.exe'; ^
    $shortcut.Save()"

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Application installed to: %INSTALL_DIR%
echo.
echo Desktop shortcut created.
echo Start Menu folder created.
echo.
echo To uninstall, delete the folder: %INSTALL_DIR%
echo.
pause
"""
    
    installer_path = Path("dist/install.bat")
    installer_path.parent.mkdir(parents=True, exist_ok=True)
    installer_path.write_text(batch_script)
    
    print("✓ Windows batch installer created: dist/install.bat")
    return True


def create_mac_installer():
    """Create macOS .dmg installer"""
    print("\n🍎 Building macOS Installer...")
    
    # DMG creation script
    dmg_script = """#!/bin/bash
set -e

echo "Creating macOS .dmg installer..."

# Create temporary directory
mkdir -p dist/temp/Phishing\ Detection\ Suite.app/Contents/MacOS
mkdir -p dist/temp/Phishing\ Detection\ Suite.app/Contents/Resources

# Copy executable
cp dist/PhishingDetectionSuite dist/temp/Phishing\ Detection\ Suite.app/Contents/MacOS/

# Create Info.plist
cat > dist/temp/Phishing\ Detection\ Suite.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>PhishingDetectionSuite</string>
    <key>CFBundleIdentifier</key>
    <string>com.securitytools.phishingdetection</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Phishing Detection Suite</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>NSMainNibFile</key>
    <string>MainMenu</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Create .dmg
hdiutil create -volname "Phishing Detection Suite" -srcfolder dist/temp -ov -format UDZO dist/PhishingDetectionSuite-1.0.0.dmg

# Cleanup
rm -rf dist/temp

echo "✓ macOS .dmg created: dist/PhishingDetectionSuite-1.0.0.dmg"
"""
    
    script_path = Path("dist/create_dmg.sh")
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(dmg_script)
    
    print("✓ macOS installer script created: dist/create_dmg.sh")
    return True


def create_linux_installer():
    """Create Linux .deb package"""
    print("\n🐧 Building Linux Installer...")
    
    # Create debian control file
    control_content = """Package: phishing-detection-suite
Version: 1.0.0
Architecture: amd64
Maintainer: Security Tools <info@securitytools.org>
Description: Email Phishing Detection and Malware Analysis Tool
 A comprehensive desktop application for cybersecurity threat detection.
 Analyze emails for phishing attempts and files for malware signatures.
Depends: python3 (>= 3.9), python3-pyqt6
Homepage: https://github.com
"""
    
    control_path = Path("dist/debian/DEBIAN/control")
    control_path.parent.mkdir(parents=True, exist_ok=True)
    control_path.write_text(control_content)
    
    # Create desktop entry
    desktop_entry = """[Desktop Entry]
Version=1.0
Type=Application
Name=Phishing Detection Suite
Comment=Email Phishing Detection and Malware Analysis
Exec=/usr/bin/phishing-detection-suite
Icon=security-tools
Terminal=false
Categories=Security;System;Utility;
"""
    
    desktop_path = Path("dist/debian/usr/share/applications/phishing-detection-suite.desktop")
    desktop_path.parent.mkdir(parents=True, exist_ok=True)
    desktop_path.write_text(desktop_entry)
    
    print("✓ Linux .deb package files created in: dist/debian/")
    print("  Note: To build .deb, run: dpkg-deb --build dist/debian phishing-detection-suite-1.0.0.deb")
    return True


def create_pyinstaller_spec():
    """Create PyInstaller spec file for building executables"""
    spec_content = """# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

project_root = os.path.join(os.path.dirname(__file__), '..')

a = Analysis(
    [os.path.join(project_root, 'app', 'gui', 'desktop_app.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'resources', 'templates'), 'resources/templates'),
        (os.path.join(project_root, 'resources', 'static'), 'resources/static'),
        (os.path.join(project_root, 'resources', 'images'), 'resources/images'),
        (os.path.join(project_root, 'resources', 'icons'), 'resources/icons'),
        (os.path.join(project_root, 'app', 'core'), 'app/core'),
    ],
    hiddenimports=['PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets', 'PyQt6.QtCharts'] + collect_submodules('nltk'),
    hookspath=[],
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PhishingDetectionSuite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Hide terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(project_root, 'resources', 'icons', 'logo.ico') if platform.system() == 'Windows' else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PhishingDetectionSuite'
)

app = BUNDLE(
    coll,
    name='PhishingDetectionSuite.app',
    icon=None,
    bundle_identifier=None,
    info_plist={
        'NSPrincipalClass': 'NSApplication',
        'NSHighResolutionCapable': 'True',
    },
) if platform.system() == 'Darwin' else None
"""
    
    spec_path = Path("desktop_app.spec")
    spec_path.write_text(spec_content)
    print("✓ PyInstaller spec created: desktop_app.spec")
    return True


def build_executables():
    """Build executables using PyInstaller"""
    print("\n📦 Building Executables with PyInstaller...")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("⚠️  PyInstaller not found. Install with: pip install pyinstaller")
        return False
    
    # Build for current platform
    system = platform.system()
    project_root = os.path.join(os.path.dirname(__file__), '..')
    desktop_app = os.path.join(project_root, 'app', 'gui', 'desktop_app.py')
    logo_ico = os.path.join(project_root, 'resources', 'icons', 'logo.ico')
    logo_png = os.path.join(project_root, 'resources', 'images', 'logo.png')
    
    if system == "Windows":
        cmd = f'pyinstaller --onefile --windowed --noconsole --icon="{logo_ico}" --name PhishingDetectionSuite --add-data "{logo_png};resources/images" --add-data "{logo_ico};resources/icons" "{desktop_app}"'
        run_command(cmd, "Building Windows executable")
    
    elif system == "Darwin":  # macOS
        cmd = f'pyinstaller --onefile --windowed --noconsole --name PhishingDetectionSuite --add-data "{logo_png}:resources/images" "{desktop_app}"'
        run_command(cmd, "Building macOS executable")
    
    elif system == "Linux":
        cmd = f'pyinstaller --onefile --windowed --noconsole --name PhishingDetectionSuite --add-data "{logo_png}:resources/images" "{desktop_app}"'
        run_command(cmd, "Building Linux executable")
    
    return True


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   Phishing Detection Suite - Installer Builder            ║
    ║   Build standalone installers for all platforms           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    system = platform.system()
    print(f"Current Platform: {system}")
    
    # Build PyInstaller spec
    print("\n[1/5] Creating PyInstaller configuration...")
    create_pyinstaller_spec()
    
    # Build executables
    print("\n[2/5] Building platform-specific executable...")
    build_executables()
    
    # Create platform-specific installers
    if system == "Windows":
        print("\n[3/5] Creating Windows installers...")
        create_windows_batch_installer()
        create_windows_installer()
        
    elif system == "Darwin":
        print("\n[3/5] Creating macOS installer...")
        create_mac_installer()
        
    elif system == "Linux":
        print("\n[3/5] Creating Linux installer...")
        create_linux_installer()
    
    # Summary
    print("\n" + "="*70)
    print("✅ INSTALLER BUILD COMPLETE")
    print("="*70)
    print(f"\nPlatform: {system}")
    print("\nBuilt Files:")
    
    dist_dir = Path("dist")
    if dist_dir.exists():
        for file in dist_dir.rglob("*"):
            if file.is_file():
                size = file.stat().st_size / 1024 / 1024
                print(f"  • {file.relative_to('dist')} ({size:.2f} MB)")
    
    print("\nNext Steps:")
    if system == "Windows":
        print("  1. Run: dist\\install.bat (for simple installation)")
        print("  2. Or use: dist\\PhishingDetectionSuite.exe (pre-built)")
    elif system == "Darwin":
        print("  1. Run: ./dist/create_dmg.sh")
        print("  2. Mount and install from .dmg")
    elif system == "Linux":
        print("  1. Run: dpkg-deb --build dist/debian phishing-detection-suite-1.0.0.deb")
        print("  2. Install: sudo dpkg -i phishing-detection-suite-1.0.0.deb")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
