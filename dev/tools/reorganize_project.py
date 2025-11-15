"""
Project Structure Reorganization Script
Organizes files into logical directories for better maintainability
"""

import os
import shutil
from pathlib import Path


def create_directory_structure():
    """Create organized directory structure"""
    
    directories = {
        # Core application files
        'app': 'Main application code',
        'app/gui': 'GUI components and desktop interface',
        'app/core': 'Core detection and analysis logic',
        'app/web': 'Web application files',
        
        # Resources
        'resources': 'Application resources',
        'resources/images': 'Logo and image files',
        'resources/icons': 'Icon files',
        'resources/templates': 'HTML templates',
        'resources/static': 'CSS, JS, and other static files',
        
        # Data
        'data': 'Data files and datasets',
        'data/raw': 'Raw data files',
        'data/processed': 'Processed data',
        'data/models': 'Trained ML models',
        
        # Configuration
        'config': 'Configuration files',
        
        # Documentation
        'docs': 'Project documentation',
        'docs/guides': 'User guides',
        'docs/api': 'API documentation',
        
        # Tests
        'tests': 'Test files',
        'tests/unit': 'Unit tests',
        'tests/integration': 'Integration tests',
        
        # Build and distribution
        'build': 'Build artifacts',
        'dist': 'Distribution files',
        
        # Installation
        'installers': 'Installation scripts and packages',
        'installers/windows': 'Windows installers',
        'installers/macos': 'macOS installers',
        'installers/linux': 'Linux installers',
        
        # Development
        'scripts': 'Utility scripts',
        'notebooks': 'Jupyter notebooks for analysis',
    }
    
    print("Creating directory structure...")
    for directory, description in directories.items():
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory:<30} - {description}")
    
    return directories


def create_file_organization_map():
    """Define file organization mapping"""
    
    file_map = {
        # Application files
        'desktop_app.py': 'app/gui/desktop_app.py',
        'app.py': 'app/web/app.py',
        'main.py': 'app/main.py',
        
        # Core modules
        'src/email_detector.py': 'app/core/email_detector.py',
        'src/file_analyzer.py': 'app/core/file_analyzer.py',
        'src/model_trainer.py': 'app/core/model_trainer.py',
        'src/__init__.py': 'app/core/__init__.py',
        
        # Resources
        'logo.png': 'resources/images/logo.png',
        'logo.ico': 'resources/icons/logo.ico',
        'templates/': 'resources/templates/',
        'static/': 'resources/static/',
        
        # Configuration
        'requirements.txt': 'config/requirements.txt',
        
        # Documentation
        'README.md': 'docs/README.md',
        'PROJECT_SUMMARY.md': 'docs/PROJECT_SUMMARY.md',
        'DESKTOP_GUIDE.md': 'docs/guides/DESKTOP_GUIDE.md',
        'DESKTOP_SUMMARY.md': 'docs/guides/DESKTOP_SUMMARY.md',
        'WEBAPP_GUIDE.md': 'docs/guides/WEBAPP_GUIDE.md',
        'WEBAPP_SUMMARY.md': 'docs/guides/WEBAPP_SUMMARY.md',
        'QUICKSTART.md': 'docs/guides/QUICKSTART.md',
        'QUICKSTART_DESKTOP.md': 'docs/guides/QUICKSTART_DESKTOP.md',
        
        # Tests
        'tests/test_email_detector.py': 'tests/unit/test_email_detector.py',
        'tests/test_file_analyzer.py': 'tests/unit/test_file_analyzer.py',
        'tests/__init__.py': 'tests/__init__.py',
        
        # Build and installation
        'setup.py': 'installers/setup.py',
        'setup.bat': 'installers/windows/setup.bat',
        'setup.sh': 'installers/linux/setup.sh',
        'build_installer.py': 'installers/build_installer.py',
        'convert_logo.py': 'scripts/convert_logo.py',
        
        # Spec files
        'desktop_app.spec': 'config/desktop_app.spec',
        'PhishingDetectionSuite.spec': 'config/PhishingDetectionSuite.spec',
    }
    
    return file_map


def create_init_files():
    """Create __init__.py files for Python packages"""
    
    init_files = [
        'app/__init__.py',
        'app/gui/__init__.py',
        'app/core/__init__.py',
        'app/web/__init__.py',
    ]
    
    print("\nCreating __init__.py files...")
    for init_file in init_files:
        Path(init_file).touch()
        print(f"  ✓ {init_file}")


def create_reorganization_plan():
    """Create a detailed reorganization plan document"""
    
    plan = """
# Project Structure Reorganization Plan

## Overview
This document outlines the new organized structure for the Phishing Detection Suite project.

## Directory Structure

```
Model_Phishing/
├── app/                          # Main application code
│   ├── __init__.py
│   ├── main.py                   # Application entry point
│   ├── gui/                      # Desktop GUI application
│   │   ├── __init__.py
│   │   └── desktop_app.py        # PyQt6 desktop interface
│   ├── core/                     # Core detection logic
│   │   ├── __init__.py
│   │   ├── email_detector.py     # Email phishing detection
│   │   ├── file_analyzer.py      # File malware analysis
│   │   └── model_trainer.py      # ML model training
│   └── web/                      # Web application
│       ├── __init__.py
│       └── app.py                # Flask web interface
│
├── resources/                    # Application resources
│   ├── images/                   # Image files
│   │   └── logo.png
│   ├── icons/                    # Icon files
│   │   └── logo.ico
│   ├── templates/                # HTML templates (Flask)
│   │   ├── index.html
│   │   ├── email_detector.html
│   │   └── file_analyzer.html
│   └── static/                   # Static files (CSS, JS)
│       └── style.css
│
├── data/                         # Data files
│   ├── raw/                      # Raw datasets
│   ├── processed/                # Processed data
│   └── models/                   # Trained ML models
│
├── config/                       # Configuration files
│   ├── requirements.txt          # Python dependencies
│   ├── desktop_app.spec          # PyInstaller spec
│   └── PhishingDetectionSuite.spec
│
├── docs/                         # Documentation
│   ├── README.md                 # Main documentation
│   ├── PROJECT_SUMMARY.md        # Project overview
│   ├── guides/                   # User guides
│   │   ├── DESKTOP_GUIDE.md
│   │   ├── WEBAPP_GUIDE.md
│   │   ├── QUICKSTART.md
│   │   └── QUICKSTART_DESKTOP.md
│   └── api/                      # API documentation
│
├── tests/                        # Test files
│   ├── __init__.py
│   ├── unit/                     # Unit tests
│   │   ├── test_email_detector.py
│   │   └── test_file_analyzer.py
│   └── integration/              # Integration tests
│
├── installers/                   # Installation scripts
│   ├── setup.py                  # Cross-platform setup
│   ├── build_installer.py        # Build executables
│   ├── windows/                  # Windows installers
│   │   └── setup.bat
│   ├── macos/                    # macOS installers
│   └── linux/                    # Linux installers
│       └── setup.sh
│
├── scripts/                      # Utility scripts
│   └── convert_logo.py           # Logo conversion
│
├── notebooks/                    # Jupyter notebooks
│   └── analysis.ipynb            # Data analysis
│
├── build/                        # Build artifacts (gitignore)
├── dist/                         # Distribution files (gitignore)
│
└── uploads/                      # Temporary uploads (gitignore)
```

## Benefits

### 1. **Clear Separation of Concerns**
   - Application logic separated from resources
   - GUI and web interfaces in separate modules
   - Core detection logic isolated

### 2. **Better Scalability**
   - Easy to add new features
   - Modular structure
   - Clear dependencies

### 3. **Improved Maintainability**
   - Logical file organization
   - Easy to locate files
   - Clear project structure

### 4. **Development Workflow**
   - Separate test directories
   - Documentation in one place
   - Build artifacts separated

### 5. **Deployment**
   - Clean distribution structure
   - Platform-specific installers organized
   - Configuration files grouped

## Migration Steps

1. **Backup Current Project**
   ```bash
   git commit -am "Backup before reorganization"
   ```

2. **Create New Structure**
   ```bash
   python scripts/reorganize_project.py --create-structure
   ```

3. **Move Files**
   ```bash
   python scripts/reorganize_project.py --move-files
   ```

4. **Update Import Paths**
   ```bash
   python scripts/reorganize_project.py --update-imports
   ```

5. **Test Application**
   ```bash
   python -m app.gui.desktop_app
   python -m app.web.app
   ```

## Import Path Changes

### Old Imports
```python
from src.email_detector import EmailPhishingDetector
from src.file_analyzer import MalwareAnalyzer
```

### New Imports
```python
from app.core.email_detector import EmailPhishingDetector
from app.core.file_analyzer import MalwareAnalyzer
```

## Configuration Updates

### requirements.txt
Now located at: `config/requirements.txt`

### PyInstaller Specs
Now located at: `config/desktop_app.spec`

## Notes

- All build artifacts should be in `build/` and `dist/`
- User data and logs: `~/.phishing_detector/`
- Temporary uploads: `uploads/` (add to .gitignore)
- Virtual environment: `venv/` (add to .gitignore)

## .gitignore Additions

```
# Build artifacts
build/
dist/
*.spec

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Virtual environment
venv/
env/

# IDE
.vscode/
.idea/
*.swp

# User data
uploads/
*.log

# OS
.DS_Store
Thumbs.db
```
"""
    
    Path('docs/REORGANIZATION_PLAN.md').parent.mkdir(parents=True, exist_ok=True)
    Path('docs/REORGANIZATION_PLAN.md').write_text(plan, encoding='utf-8')
    print("\n✓ Reorganization plan created: docs/REORGANIZATION_PLAN.md")


def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║   Project Structure Reorganization                       ║
║   Creating logical directory structure                   ║
╚═══════════════════════════════════════════════════════════╝
""")
    
    # Create directory structure
    create_directory_structure()
    
    # Create __init__.py files
    create_init_files()
    
    # Create reorganization plan document
    create_reorganization_plan()
    
    print("\n" + "="*70)
    print("✅ DIRECTORY STRUCTURE CREATED")
    print("="*70)
    print("\nNext Steps:")
    print("  1. Review the reorganization plan: docs/REORGANIZATION_PLAN.md")
    print("  2. Backup your current work: git commit -am 'Backup'")
    print("  3. Move files manually or run migration script")
    print("  4. Update import paths in Python files")
    print("  5. Test application: python -m app.gui.desktop_app")
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
