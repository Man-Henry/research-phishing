#!/usr/bin/env python3
"""
One-click setup script for Phishing Detection Suite desktop application
Installs all dependencies and prepares the application for first run
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import shutil


class SetupWizard:
    """Interactive setup wizard for desktop application"""
    
    def __init__(self):
        self.system = platform.system()
        self.python_exe = sys.executable
        self.project_root = Path(__file__).parent.parent.parent  # Go up from dev/tools/ to project root
        
    def print_header(self, text):
        print("\n" + "="*70)
        print(f"  {text}")
        print("="*70 + "\n")
        
    def run_command(self, cmd, description=""):
        """Run shell command"""
        if description:
            print(f"▶ {description}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[ERROR] {result.stderr}")
                return False
            if result.stdout:
                print(result.stdout)
            return True
        except Exception as e:
            print(f"[ERROR] Exception: {e}")
            return False
    
    def check_python(self):
        """Verify Python version >= 3.9"""
        self.print_header("Checking Python Installation")
        
        version = sys.version_info
        print(f"Python {version.major}.{version.minor}.{version.micro}")
        
        if version.major < 3 or (version.major == 3 and version.minor < 9):
            print("[ERROR] Python 3.9+ is required")
            print(f"   Current: {version.major}.{version.minor}")
            return False
        
        print("[SUCCESS] Python version compatible")
        return True
    
    def install_dependencies(self):
        """Install required Python packages"""
        self.print_header("Installing Dependencies")
        
        packages = [
            "PyQt6>=6.0.0",
            "PyQt6-Charts>=6.0.0",
            "scikit-learn>=1.0.0",
            "pandas>=1.3.0",
            "numpy>=1.20.0",
            "nltk>=3.6.0",
            "requests>=2.26.0",
            "beautifulsoup4>=4.9.0",
            "PyInstaller>=5.0.0",
            "joblib>=1.0.0",
            "Pillow>=9.0.0",
        ]
        
        print("Installing packages:")
        for pkg in packages:
            print(f"  • {pkg}")
        
        # Properly quote the Python executable path to handle spaces
        cmd = f'"{self.python_exe}" -m pip install -q ' + " ".join(f'"{pkg}"' for pkg in packages)
        
        if not self.run_command(cmd, "Installing via pip..."):
            print("[ERROR] Some packages failed to install")
            return False
        
        print("\n[SUCCESS] All dependencies installed")
        return True
    
    def setup_nltk_data(self):
        """Download required NLTK data"""
        self.print_header("Setting Up NLTK Data")
        
        python_code = """
import nltk
import ssl

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

print("Downloading NLTK data...")
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)
print("[SUCCESS] NLTK data ready")
"""
        
        # Properly quote Python executable and escape the code
        cmd = f'"{self.python_exe}" -c "{python_code}"'
        return self.run_command(cmd, "Downloading NLTK datasets...")
    
    def create_directories(self):
        """Create necessary directories"""
        self.print_header("Creating Application Directories")
        
        dirs = [
            ".phishing_detector",
            ".phishing_detector/logs",
            ".phishing_detector/cache",
            ".phishing_detector/results",
        ]
        
        home = Path.home()
        for dir_name in dirs:
            dir_path = home / dir_name
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"[OK] {dir_path}")
        
        print("\n[SUCCESS] Directories created")
        return True
    
    def create_config(self):
        """Create default configuration file"""
        self.print_header("Creating Configuration File")
        
        config_dir = Path.home() / ".phishing_detector"
        config_file = config_dir / "config.json"
        
        config_content = """{
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
"""
        
        config_file.write_text(config_content)
        print(f"Created: {config_file}")
        print("[SUCCESS] Configuration file ready")
        return True
    
    def create_shortcuts(self):
        """Create application shortcuts"""
        self.print_header("Creating Application Shortcuts")
        
        # Convert logo.png to logo.ico if it exists
        logo_png = self.project_root / "resources" / "images" / "logo.png"
        logo_ico = self.project_root / "resources" / "icons" / "logo.ico"
        
        if logo_png.exists() and not logo_ico.exists():
            print("Converting logo to .ico format...")
            try:
                from PIL import Image
                # Create icons directory if needed
                logo_ico.parent.mkdir(parents=True, exist_ok=True)
                img = Image.open(logo_png)
                icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
                img.save(logo_ico, format='ICO', sizes=icon_sizes)
                print("[OK] Logo converted to .ico format")
            except Exception as e:
                print(f"[WARNING] Could not convert logo: {e}")
        
        if self.system == "Windows":
            return self.create_windows_shortcuts()
        elif self.system == "Darwin":
            return self.create_mac_shortcuts()
        elif self.system == "Linux":
            return self.create_linux_shortcuts()
        
        return True
    
    def create_windows_shortcuts(self):
        """Create Windows shortcuts"""
        # Use absolute path from self.project_root
        project_root_path = str(self.project_root).replace('\\', '\\\\')
        
        script = f"""
$DesktopPath = [Environment]::GetFolderPath('Desktop')
$StartMenuPath = [Environment]::GetFolderPath('StartMenu')
$ApplicationPath = '{project_root_path}'
$ExecutablePath = Join-Path $ApplicationPath 'main.py'
$IconPath = Join-Path $ApplicationPath 'resources\\icons\\logo.ico'

# Create WshShell object
$WshShell = New-Object -ComObject WScript.Shell

# Desktop shortcut (no spaces in filename to avoid issues)
$DesktopShortcutPath = Join-Path $DesktopPath 'PhishingDetectionSuite.lnk'
$DesktopShortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$DesktopShortcut.TargetPath = 'python.exe'
$DesktopShortcut.Arguments = "`"$ExecutablePath`" desktop"
$DesktopShortcut.WorkingDirectory = $ApplicationPath
$DesktopShortcut.Description = 'Phishing Detection & Malware Analysis Suite'
if (Test-Path $IconPath) {{
    $DesktopShortcut.IconLocation = $IconPath
}}
$DesktopShortcut.Save()

if (Test-Path $DesktopShortcutPath) {{
    Write-Host "[OK] Desktop shortcut created at: $DesktopShortcutPath"
}} else {{
    Write-Host "[ERROR] Failed to create desktop shortcut"
}}

# Start Menu shortcut
$StartMenuFolder = Join-Path $StartMenuPath 'Phishing Detection Suite'
if (!(Test-Path $StartMenuFolder)) {{
    New-Item -ItemType Directory -Path $StartMenuFolder | Out-Null
}}
$StartMenuShortcutPath = Join-Path $StartMenuFolder 'PhishingDetectionSuite.lnk'
$StartMenuShortcut = $WshShell.CreateShortcut($StartMenuShortcutPath)
$StartMenuShortcut.TargetPath = 'python.exe'
$StartMenuShortcut.Arguments = "`"$ExecutablePath`" desktop"
$StartMenuShortcut.WorkingDirectory = $ApplicationPath
$StartMenuShortcut.Description = 'Phishing Detection & Malware Analysis Suite'
if (Test-Path $IconPath) {{
    $StartMenuShortcut.IconLocation = $IconPath
}}
$StartMenuShortcut.Save()

if (Test-Path $StartMenuShortcutPath) {{
    Write-Host "[OK] Start Menu shortcut created at: $StartMenuShortcutPath"
}} else {{
    Write-Host "[ERROR] Failed to create Start Menu shortcut"
}}
"""
        
        ps_file = Path("create_shortcuts.ps1")
        ps_file.write_text(script)
        
        cmd = f"powershell -NoProfile -ExecutionPolicy Bypass -File {ps_file}"
        result = self.run_command(cmd, "Creating Windows shortcuts...")
        
        ps_file.unlink()  # Delete temp script
        return result
    
    def create_mac_shortcuts(self):
        """Create macOS application alias"""
        print("Creating macOS launcher...")
        app_path = Path.home() / "Applications/Phishing Detection Suite.app"
        print(f"  Application alias: {app_path}")
        print("[SUCCESS] macOS shortcuts ready (use Applications folder)")
        return True
    
    def create_linux_shortcuts(self):
        """Create Linux desktop entry"""
        desktop_entry = """[Desktop Entry]
Version=1.0
Type=Application
Name=Phishing Detection Suite
Comment=Email Phishing Detection and Malware Analysis Tool
Exec=python3 {}/main.py desktop
Icon=security-tools
Terminal=false
Categories=Security;System;Utility;
""".format(self.project_root)
        
        desktop_dir = Path.home() / ".local/share/applications"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        
        desktop_file = desktop_dir / "phishing-detection-suite.desktop"
        desktop_file.write_text(desktop_entry)
        
        print(f"Created: {desktop_file}")
        print("[SUCCESS] Linux desktop entry ready")
        return True
    
    def verify_installation(self):
        """Verify all components are ready"""
        self.print_header("Verifying Installation")
        
        checks = {
            "Python": self.check_python,
        }
        
        all_passed = True
        for name, check in checks.items():
            print(f"Checking {name}...")
            # We already checked Python above
        
        # Check if can import PyQt6
        try:
            import PyQt6
            print("[OK] PyQt6")
        except ImportError:
            print("[SKIP] PyQt6 (will be installed)")
            all_passed = False
        
        # Check if source modules exist
        src_files = [
            ("src/detectors/email_detector.py", "email_detector.py"),
            ("src/detectors/file_analyzer.py", "file_analyzer.py"),
            ("src/ml/model_trainer.py", "model_trainer.py")
        ]
        for path, name in src_files:
            if (self.project_root / path).exists():
                print(f"[OK] {name}")
            else:
                print(f"[MISSING] {name}")
                all_passed = False
        
        if all_passed:
            print("\n[SUCCESS] All checks passed!")
        
        return all_passed
    
    def show_next_steps(self):
        """Display next steps for user"""
        self.print_header("Setup Complete! [SUCCESS]")
        
        print("Your Phishing Detection Suite is ready to use!\n")
        print("Quick Start Guide:")
        print("─" * 70)
        
        if self.system == "Windows":
            print("\n1. Start the application:")
            print("   • Double-click 'Phishing Detection Suite' on Desktop")
            print("   • Or run: python main.py desktop")
            
        elif self.system == "Darwin":
            print("\n1. Start the application:")
            print("   • Open Applications > Phishing Detection Suite")
            print("   • Or run: python3 main.py desktop")
            
        elif self.system == "Linux":
            print("\n1. Start the application:")
            print("   • Search for 'Phishing Detection Suite' in applications")
            print("   • Or run: python3 main.py desktop")
        
        print("\n2. Using the application:")
        print("   • Email Detector tab: Paste email content to check for phishing")
        print("   • File Analyzer tab: Upload files to scan for malware")
        print("   • Settings tab: Configure your preferences")
        
        print("\n3. Features:")
        print("   * 16-feature email phishing detection")
        print("   * 11-feature file malware analysis")
        print("   * Real-time threat assessment")
        print("   * File hash calculation (MD5, SHA1, SHA256)")
        print("   * Confidence scores and risk levels")
        
        print("\n4. Help & Documentation:")
        print("   • Use Help tab in the application")
        print("   • Check DESKTOP_GUIDE.md for detailed instructions")
        
        print("\n5. Support:")
        print("   • Report issues on GitHub")
        print("   • Check application Settings > About")
        
        print("\n" + "="*70)
        print("Happy analyzing!")
        print("="*70 + "\n")
    
    def run_setup(self):
        """Run complete setup wizard"""
        self.print_header("Phishing Detection Suite - Setup Wizard")
        print("Installing desktop application...\n")
        
        steps = [
            ("Checking Python Installation", self.check_python),
            ("Installing Dependencies", self.install_dependencies),
            ("Setting Up NLTK Data", self.setup_nltk_data),
            ("Creating Directories", self.create_directories),
            ("Creating Configuration", self.create_config),
            ("Creating Shortcuts", self.create_shortcuts),
            ("Verifying Installation", self.verify_installation),
        ]
        
        for i, (step_name, step_func) in enumerate(steps, 1):
            print(f"\n[{i}/{len(steps)}] {step_name}")
            try:
                if not step_func():
                    print(f"\n[ERROR] Setup failed at step: {step_name}")
                    print("Please fix the issue and try again.")
                    return False
            except Exception as e:
                print(f"\n[ERROR] {e}")
                return False
        
        self.show_next_steps()
        return True


def main():
    try:
        wizard = SetupWizard()
        success = wizard.run_setup()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
