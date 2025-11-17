"""
Quick build script for PhishingDetector.exe
Optimized for faster builds by excluding unnecessary packages
"""

import subprocess
import sys
from pathlib import Path

# Set UTF-8 encoding for console output
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

print("=" * 70)
print("[*] Building PhishingDetector.exe")
print("=" * 70)

# PyInstaller command with optimizations
cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--windowed",
    "--noconsole",
    "--name", "PhishingDetector",
    "--icon", "resources/icons/logo.ico",
    
    # Add essential data files
    "--add-data", "resources/images;resources/images",
    "--add-data", "resources/icons;resources/icons",
    "--add-data", "src;src",  # Include entire src package
    
    # Hidden imports (only essentials)
    "--hidden-import", "PyQt6.QtCore",
    "--hidden-import", "PyQt6.QtGui", 
    "--hidden-import", "PyQt6.QtWidgets",
    "--hidden-import", "sklearn.ensemble",
    "--hidden-import", "sklearn.tree",
    "--hidden-import", "nltk",
    "--hidden-import", "joblib",
    "--hidden-import", "src.detectors.email_detector",
    "--hidden-import", "src.detectors.file_analyzer",
    "--hidden-import", "src.detectors.hybrid_detector",
    "--hidden-import", "src.ml.model_trainer",
    "--hidden-import", "src.utils.language_detector",
    "--hidden-import", "pandas.plotting",
    "--hidden-import", "pandas.plotting._core",
    "--hidden-import", "pandas.plotting._matplotlib",
    
    # Exclude unnecessary packages to speed up build
    "--exclude-module", "matplotlib",
    "--exclude-module", "IPython",
    "--exclude-module", "jupyter",
    "--exclude-module", "notebook",
    
    # Clean build
    "--clean",
    
    # Entry point
    "apps/desktop/main.py"
]

print("\n[*] Running PyInstaller...")
print(f"Command: {' '.join(cmd)}\n")

result = subprocess.run(cmd)

if result.returncode == 0:
    exe_path = Path("dist/PhishingDetector.exe")
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1024 / 1024
        
        # Copy exe to root directory
        root_exe = Path("PhishingDetector.exe")
        import shutil
        try:
            shutil.copy2(exe_path, root_exe)
            copied = True
        except PermissionError:
            print("\n[!] WARNING: Could not copy to root directory (file in use)")
            print("[!] Please close PhishingDetector.exe and manually copy:")
            print(f"[!]   Copy-Item 'dist\\PhishingDetector.exe' -Destination 'PhishingDetector.exe' -Force")
            copied = False
        
        print("\n" + "=" * 70)
        print("[SUCCESS] BUILD SUCCESSFUL!")
        print("=" * 70)
        print(f"[*] Built EXE: {exe_path.absolute()}")
        if copied:
            print(f"[*] Copied to: {root_exe.absolute()}")
        else:
            print(f"[!] Manual copy needed to: {root_exe.absolute()}")
        print(f"[*] Size: {size_mb:.2f} MB")
        print("\n[*] Next steps:")
        if not copied:
            print("  1. Close running PhishingDetector.exe")
            print("  2. Copy-Item 'dist\\PhishingDetector.exe' -Destination 'PhishingDetector.exe' -Force")
            print("  3. Run: .\\PhishingDetector.exe")
        else:
            print("  1. Run: PhishingDetector.exe (double-click)")
            print("  2. Or test from terminal: .\\PhishingDetector.exe")
            print("  3. Copy to Desktop for easy access")
        print("\n[TIP] Right-click PhishingDetector.exe -> Send to -> Desktop")
        print("=" * 70)
    else:
        print("\n[ERROR] Build completed but exe not found!")
else:
    print("\n[ERROR] BUILD FAILED!")
    print(f"Exit code: {result.returncode}")
    sys.exit(1)
