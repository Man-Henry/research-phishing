#!/usr/bin/env python3
"""
Phishing Detection Suite - Main Entry Point
Version 2.1.0 - Restructured
"""

import sys
import argparse
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Main entry point for all applications"""
    parser = argparse.ArgumentParser(
        description="Phishing Detection Suite v2.1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py desktop          Launch desktop GUI
  python main.py web              Launch web application  
  python main.py train            Train ML models
  python main.py test             Run tests

For more information, see docs/INDEX.md
        """
    )
    
    parser.add_argument(
        "mode",
        choices=["desktop", "web", "train", "test", "info"],
        help="Application mode to run"
    )
    
    args = parser.parse_args()
    
    if args.mode == "desktop":
        print("Launching Desktop Application...")
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from apps.desktop.main import main as desktop_main
            desktop_main()
        except ImportError as e:
            print(f"❌ Error importing desktop app: {e}")
            print("\n💡 Fix: pip install -r config/requirements.txt")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
    elif args.mode == "web":
        print("Launching Web Application...")
        print("Server will be available at: http://localhost:5000")
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from apps.web.app import app
            app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
        except ImportError as e:
            print(f"❌ Error importing web app: {e}")
            print("\n💡 Fix: pip install -r config/requirements.txt")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        
    elif args.mode == "train":
        print("Training Models...")
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from dev.scripts.train_model import main as train_main
            train_main()
        except ImportError as e:
            print(f"Error importing training script: {e}")
            print("Make sure all dependencies are installed: pip install -r config/requirements.txt")
        
    elif args.mode == "test":
        print("Running Tests...")
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from dev.tests.test_hybrid import main as test_main
            test_main()
        except ImportError as e:
            print(f"Error importing tests: {e}")
            print("Make sure all dependencies are installed: pip install -r config/requirements.txt")
        
    elif args.mode == "info":
        print_info()

def print_info():
    """Print project information"""
    print("""
Project Structure:
  apps/          - Applications (desktop, web)
  src/           - Core ML & detection logic
  data/          - Models, datasets, outputs
  dev/           - Scripts, tests, tools
  docs/          - Documentation
  resources/     - Static assets
  deployment/    - Deployment configs

Quick Start:
  python main.py desktop     Launch GUI application
  python main.py web         Launch web server
  python main.py train       Train ML models
  python main.py test        Run test suite

Documentation:
  docs/INDEX.md             - Complete documentation index
  docs/README.md            - Quick overview

Features:
  - 95.8% Accuracy (Hybrid Random Forest)
  - 3,340 emails/sec throughput
  - Multi-stage detection pipeline
  - Desktop & Web interfaces
    """)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_info()
    else:
        main()