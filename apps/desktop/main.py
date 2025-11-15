"""
Desktop Application for Email Phishing Detection and Malware Analysis
PyQt6-based GUI for easy installation and use on personal devices
Optimized with caching and lazy loading for better performance
"""

# Hide console window immediately on Windows (before GUI loads)
import sys
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
import threading
from functools import lru_cache

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QTextEdit, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QComboBox, QSpinBox, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap

# Import project modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.detectors.email_detector import EmailPhishingDetector
from src.detectors.file_analyzer import MalwareAnalyzer
from src.ml.model_trainer import ModelTrainer
import numpy as np
import traceback
import subprocess


# Lazy initialization cache for models
_detector_cache = None
_analyzer_cache = None


def create_desktop_shortcut():
    """Automatically create desktop shortcut if it doesn't exist"""
    try:
        # Only run on Windows
        if sys.platform != 'win32':
            return
        
        # Get Desktop path using PowerShell (handles all languages and OneDrive)
        ps_get_desktop = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Environment]::GetFolderPath('Desktop')"
        result = subprocess.run(
            ["powershell", "-Command", ps_get_desktop],
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8'
        )
        
        if result.returncode != 0:
            return
        
        desktop = Path(result.stdout.strip())
        if not desktop.exists():
            return
        
        shortcut_path = desktop / 'PhishingDetector.lnk'
        
        # Check if shortcut already exists
        if shortcut_path.exists():
            return  # Shortcut already exists, skip
        
        # Get exe path (works for both PyInstaller and Python)
        if getattr(sys, 'frozen', False):
            # Running as exe
            exe_path = Path(sys.executable)
        else:
            # Running as Python script - find exe in root
            project_root = Path(__file__).parent.parent.parent
            exe_path = project_root / 'PhishingDetector.exe'
            if not exe_path.exists():
                return  # Exe not found, skip
        
        # Get icon path
        icon_path = exe_path.parent / 'resources' / 'icons' / 'logo.ico'
        
        # Create shortcut using PowerShell
        ps_command = f"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut('{shortcut_path}')
$Shortcut.TargetPath = '{exe_path}'
$Shortcut.Arguments = 'desktop'
$Shortcut.WorkingDirectory = '{exe_path.parent}'
$Shortcut.Description = 'Phishing Detection Suite - Desktop App'
"""
        if icon_path.exists():
            ps_command += f"$Shortcut.IconLocation = '{icon_path}'\n"
        ps_command += "$Shortcut.Save()"
        
        # Execute PowerShell command
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10,
            encoding='utf-8'
        )
        
        if result.returncode == 0:
            # Silent success - don't print to console (encoding issues)
            pass
        
    except Exception as e:
        # Silent fail - don't interrupt app startup
        pass


def get_detector():
    """Lazy load email detector (singleton pattern)"""
    global _detector_cache
    if _detector_cache is None:
        _detector_cache = EmailPhishingDetector()
    return _detector_cache


def get_analyzer():
    """Lazy load file analyzer (singleton pattern)"""
    global _analyzer_cache
    if _analyzer_cache is None:
        _analyzer_cache = MalwareAnalyzer()
    return _analyzer_cache


class AnalysisWorker(QThread):
    """Optimized worker thread with result caching"""
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    # Class-level cache for recent analyses
    _result_cache = {}
    _cache_limit = 50  # Store last 50 results

    def __init__(self, analysis_type, data, use_cache=True):
        super().__init__()
        self.analysis_type = analysis_type
        self.data = data
        self.use_cache = use_cache

    def _get_cache_key(self):
        """Generate cache key from data"""
        if self.analysis_type == "email":
            return hashlib.md5(self.data.encode('utf-8', errors='ignore')).hexdigest()
        else:  # file
            return hashlib.md5(self.data.encode()).hexdigest()

    def run(self):
        try:
            # Check cache first
            cache_key = self._get_cache_key()
            if self.use_cache and cache_key in self._result_cache:
                self.progress.emit(100)
                self.finished.emit(self._result_cache[cache_key])
                return
            
            self.progress.emit(25)
            
            if self.analysis_type == "email":
                detector = get_detector()
                # Combined feature extraction and prediction
                prediction = detector.predict(self.data)
                self.progress.emit(75)
                
                result = {
                    "type": "email",
                    "is_phishing": prediction['is_phishing'],
                    "confidence": prediction['confidence'],
                    "features": prediction['features'],  # Already a dict from predict()
                    "risk_level": self._get_risk_level(prediction['confidence'], prediction['is_phishing']),
                    "cached": False
                }
                
            elif self.analysis_type == "file":
                if not os.path.exists(self.data):
                    self.error.emit("File not found")
                    return
                
                analyzer = get_analyzer()
                # Get file hash
                file_hash = analyzer.get_file_hash(self.data)
                self.progress.emit(50)
                
                # Extract features (returns numpy array, not dict)
                features_array = analyzer.analyze_file(self.data)
                self.progress.emit(75)
                
                # Classify using feature array
                prediction = analyzer.classify(features_array)
                
                # Build analysis dict for display
                # Since analyze_file returns array, we'll create a summary dict
                analysis_summary = {
                    'entropy': float(features_array[2]) if len(features_array) > 2 else 0.0,
                    'file_size': int(features_array[0]) if len(features_array) > 0 else 0,
                    'has_pe_header': bool(features_array[3]) if len(features_array) > 3 else False,
                    'has_elf_header': bool(features_array[4]) if len(features_array) > 4 else False,
                    'suspicious_strings': int(features_array[6]) if len(features_array) > 6 else 0,
                }
                
                result = {
                    "type": "file",
                    "filename": os.path.basename(self.data),
                    "file_hash": file_hash,
                    "is_malware": prediction['is_malware'],
                    "confidence": prediction['confidence'],
                    "analysis": analysis_summary,
                    "risk_level": self._get_risk_level(prediction['confidence'], prediction['is_malware']),
                    "cached": False
                }
            
            # Cache result (limit cache size)
            if self.use_cache:
                if len(self._result_cache) >= self._cache_limit:
                    # Remove oldest entry (FIFO)
                    self._result_cache.pop(next(iter(self._result_cache)))
                self._result_cache[cache_key] = result
            
            self.progress.emit(100)
            self.finished.emit(result)
            
        except Exception as e:
            import traceback
            error_details = f"{str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            self.error.emit(error_details)

    @staticmethod
    def _get_risk_level(confidence, is_threat):
        """
        Determine risk level from confidence score.
        Uses clearer thresholds to avoid misleading results.
        """
        if is_threat:
            # Phishing/Malware detected
            if confidence >= 0.8:
                return "Critical"
            elif confidence >= 0.6:
                return "High"
            elif confidence >= 0.4:
                return "Medium"
            else:
                return "Low"
        else:
            # Not detected as threat, but check confidence
            # Low confidence means "uncertain" not "safe"
            if confidence < 0.5:
                # Model is uncertain (less than 50% confidence it's legitimate)
                return "Uncertain"
            elif confidence < 0.7:
                return "Low Risk"
            else:
                return "Safe"


class EmailDetectorTab(QWidget):
    """Optimized tab for email phishing detection"""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Email Phishing Detector")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Input section
        layout.addWidget(QLabel("Paste email content below for analysis:"))
        self.email_input = QTextEdit()
        self.email_input.setPlaceholderText("Paste email content here...\nInclude: Subject, From, To, Body")
        self.email_input.setMinimumHeight(150)
        self.email_input.setMaximumHeight(200)  # Optimize screen space
        layout.addWidget(self.email_input)
        
        # Button
        self.analyze_btn = QPushButton("🔍 Analyze Email")
        self.analyze_btn.clicked.connect(self.analyze_email)
        layout.addWidget(self.analyze_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results section
        layout.addWidget(QLabel("Analysis Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(200)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
        
    def analyze_email(self):
        email_content = self.email_input.toPlainText().strip()
        if not email_content:
            QMessageBox.warning(self, "Input Error", "Please paste email content first")
            return
        
        # Disable button during analysis
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        # Run analysis in background thread with caching
        self.worker = AnalysisWorker("email", email_content, use_cache=True)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.display_email_results)
        self.worker.error.connect(self.show_error)
        self.worker.start()
        
    def display_email_results(self, result):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)  # Re-enable button
        
        # Determine display based on risk level
        risk_level = result['risk_level']
        is_phishing = result['is_phishing']
        confidence = result['confidence']
        
        # Choose appropriate message and color
        if is_phishing:
            threat_level = "🚨 PHISHING DETECTED"
            risk_color = "#e74c3c"
            bg_color = "#483D3F"
        elif risk_level == "Uncertain":
            threat_level = "⚠️ UNCERTAIN - Low Confidence"
            risk_color = "#f39c12"
            bg_color = "#4A4235"
        elif risk_level == "Low Risk":
            threat_level = "⚠️ POSSIBLY LEGITIMATE"
            risk_color = "#3498db"
            bg_color = "#354B5E"
        else:
            threat_level = "✅ LEGITIMATE EMAIL"
            risk_color = "#2ecc71"
            bg_color = "#3C4A4B"
        
        cached_tag = " (Cached)" if result.get('cached', False) else ""
        
        # Add confidence warning for low confidence results
        confidence_warning = ""
        if not is_phishing and confidence < 0.5:
            confidence_warning = f"""
            <div style="background-color: #f39c12; color: #2c3e50; padding: 8px; margin: 10px 0; border-radius: 4px;">
                <strong>⚠️ Warning:</strong> Độ tin cậy thấp ({confidence:.1%}). 
                Kết quả không chắc chắn - cần kiểm tra thêm!
            </div>
            """
        
        # Styled HTML output for dark theme
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #ecf0f1;">
            <div style="background-color: {risk_color}; color: white; padding: 10px; border-radius: 5px;">
                <strong>{threat_level}{cached_tag}</strong>
            </div>
            {confidence_warning}
            <div style="margin: 10px 0; padding: 8px; background-color: {bg_color}; border-left: 4px solid {risk_color}; border-radius: 4px;">
                <strong>Risk Level:</strong> {result['risk_level']}<br>
                <strong>Confidence:</strong> {result['confidence']:.1%}<br>
                <strong>Time:</strong> {datetime.now().strftime('%H:%M:%S')}
            </div>
            <div style="margin-top: 15px;">
                <strong>Key Features:</strong><br>
                <div style="margin: 5px 0; font-size: 12px; background-color: #34495e; padding: 8px; border-radius: 4px;">
                    • SPF Pass: {result['features'].get('spf_pass', 'N/A')}<br>
                    • URL Count: {result['features'].get('url_count', 0)}<br>
                    • Suspicious Keywords: {result['features'].get('suspicious_keyword_count', 0)}<br>
                    • Urgency Score: {result['features'].get('urgency_score', 0):.2f}<br>
                    • Has Shortener URLs: {'Yes' if result['features'].get('has_shortener_urls', 0) else 'No'}<br>
                    • Has IP URLs: {'Yes' if result['features'].get('has_ip_based_urls', 0) else 'No'}
                </div>
            </div>
        </body>
        </html>
        """
        self.results_text.setHtml(html)
        
    def show_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)  # Re-enable button
        QMessageBox.critical(self, "Analysis Error", f"Error: {error_msg}")


class FileAnalyzerTab(QWidget):
    """Optimized tab for malware file analysis"""
    
    def __init__(self):
        super().__init__()
        self.selected_file = None
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("File Malware Analyzer")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        file_layout.addWidget(self.file_label)
        
        browse_btn = QPushButton("📁 Browse...")
        browse_btn.setStyleSheet("background-color: #9b59b6;")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        # File info - removed, not essential
        
        # Analyze button
        self.analyze_btn = QPushButton("🔍 Analyze File")
        self.analyze_btn.clicked.connect(self.analyze_file)
        self.analyze_btn.setEnabled(False)  # Disabled until file selected
        layout.addWidget(self.analyze_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results
        layout.addWidget(QLabel("Analysis Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(250)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Analyze", "",
            "All Files (*);;Executables (*.exe *.elf);;Archives (*.zip *.rar)"
        )
        if file_path:
            self.selected_file = file_path
            file_size = os.path.getsize(file_path) / 1024 / 1024
            self.file_label.setText(f"📄 {os.path.basename(file_path)} ({file_size:.2f} MB)")
            self.analyze_btn.setEnabled(True)  # Enable analyze button
            
    def analyze_file(self):
        if not self.selected_file:
            QMessageBox.warning(self, "File Error", "Please select a file first")
            return
        
        # Check file size limit (50 MB)
        file_size_mb = os.path.getsize(self.selected_file) / 1024 / 1024
        if file_size_mb > 50:
            reply = QMessageBox.question(self, "Large File", 
                                        f"File is {file_size_mb:.1f} MB. Analysis may be slow. Continue?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return
            
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        self.worker = AnalysisWorker("file", self.selected_file, use_cache=True)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.display_file_results)
        self.worker.error.connect(self.show_error)
        self.worker.start()
        
    def display_file_results(self, result):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        threat_level = "🚨 MALWARE DETECTED" if result['is_malware'] else "✅ FILE APPEARS SAFE"
        risk_color = "#e74c3c" if result['is_malware'] else "#2ecc71"
        bg_color = "#483D3F" if result['is_malware'] else "#3C4A4B"
        cached_tag = " (Cached)" if result.get('cached', False) else ""
        
        # Styled HTML output for dark theme
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #ecf0f1;">
            <div style="background-color: {risk_color}; color: white; padding: 10px; border-radius: 5px;">
                <strong>{threat_level}{cached_tag}</strong>
            </div>
            <div style="margin: 10px 0; padding: 8px; background-color: {bg_color}; border-left: 4px solid {risk_color}; border-radius: 4px;">
                <strong>File:</strong> {result['filename']}<br>
                <strong>Risk:</strong> {result['risk_level']}<br>
                <strong>Confidence:</strong> {result['confidence']:.1%}
            </div>
            <div style="margin-top: 15px;">
                <strong>File Hashes:</strong><br>
                <div style="font-family: monospace; font-size: 11px; background-color: #34495e; padding: 8px; border-radius: 4px; word-break: break-all;">
                    MD5: {result['file_hash']['md5']}<br>
                    SHA1: {result['file_hash']['sha1']}<br>
                    SHA256: {result['file_hash']['sha256']}
                </div>
            </div>
            <div style="margin-top: 15px;">
                <strong>Key Metrics:</strong><br>
                <div style="font-size: 12px; background-color: #34495e; padding: 8px; border-radius: 4px;">
                    • Entropy: {result['analysis'].get('entropy', 0):.3f}<br>
                    • PE Header: {result['analysis'].get('has_pe_header', False)}<br>
                    • ELF Header: {result['analysis'].get('has_elf_header', False)}<br>
                    • Suspicious Strings: {result['analysis'].get('suspicious_strings', 0)}<br>
                    • File Size: {result['analysis'].get('file_size', 0)} bytes
                </div>
            </div>
        </body>
        </html>
        """
        self.results_text.setHtml(html)
        
    def show_error(self, error_msg):
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        # Display error in results area as well
        error_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #ecf0f1;">
            <div style="background-color: #e74c3c; color: white; padding: 10px; border-radius: 5px;">
                <strong>❌ Analysis Error</strong>
            </div>
            <div style="margin: 10px 0; padding: 8px; background-color: #483D3F; border-left: 4px solid #e74c3c; border-radius: 4px;">
                <pre style="white-space: pre-wrap; word-wrap: break-word;">{error_msg}</pre>
            </div>
        </body>
        </html>
        """
        self.results_text.setHtml(error_html)
        
        # Also show in message box for visibility
        QMessageBox.critical(self, "Analysis Error", f"Error analyzing file:\n\n{error_msg[:500]}")  # Limit message length


class SettingsTab(QWidget):
    """Tab for application settings and preferences"""
    
    def __init__(self):
        super().__init__()
        self.config_file = Path.home() / ".phishing_detector" / "config.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Settings")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Cache settings
        self.cache_enabled = QCheckBox("Enable result caching (faster repeat analyses)")
        self.cache_enabled.setChecked(True)
        layout.addWidget(self.cache_enabled)
        
        self.save_logs = QCheckBox("Save analysis logs")
        self.save_logs.setChecked(True)
        layout.addWidget(self.save_logs)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 Save Settings")
        save_btn.setStyleSheet("background-color: #27ae60;")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        clear_cache_btn = QPushButton("🗑️ Clear Cache")
        clear_cache_btn.setStyleSheet("background-color: #c0392b;")
        clear_cache_btn.clicked.connect(self.clear_cache)
        button_layout.addWidget(clear_cache_btn)
        
        layout.addLayout(button_layout)
        
        # Info section
        layout.addWidget(QLabel("\nAbout This Application:"))
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(120)
        info_text.setText(
            "Email Phishing Detection & Malware Analysis. \n\n"
            "A comprehensive desktop application for cybersecurity threat detection.\n"
            "Analyze emails for phishing attempts and files for malware signatures.\n\n"
            "© 2025 - Educational & Defensive Security Project"
        )
        layout.addWidget(info_text)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def load_settings(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.cache_enabled.setChecked(config.get('cache_enabled', True))
                    self.save_logs.setChecked(config.get('save_logs', True))
            except Exception:
                pass  # Use defaults
                
    def save_settings(self):
        config = {
            'cache_enabled': self.cache_enabled.isChecked(),
            'save_logs': self.save_logs.isChecked()
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            QMessageBox.information(self, "Saved", "Settings saved!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed: {e}")
    
    def clear_cache(self):
        """Clear analysis cache"""
        AnalysisWorker._result_cache.clear()
        QMessageBox.information(self, "Cache Cleared", "Analysis cache cleared!")


class TrainingWorker(QThread):
    """Worker thread for training models"""
    progress = pyqtSignal(int, str)  # Progress percentage and message
    finished = pyqtSignal(dict)  # Training results
    error = pyqtSignal(str)
    
    def __init__(self, training_type, data_files):
        super().__init__()
        self.training_type = training_type  # 'email' or 'file'
        self.data_files = data_files  # List of file paths
        
    def run(self):
        try:
            self.progress.emit(5, "Initializing model trainer...")
            trainer = ModelTrainer(model_dir='data/models')
            
            self.progress.emit(10, f"Loading {len(self.data_files)} data files...")
            
            # Load and prepare data
            if self.training_type == 'email':
                try:
                    X, y = self._load_email_data()
                    self.progress.emit(40, f"Loaded {len(X)} email samples ({X.shape[1]} features). Training model...")
                except Exception as load_error:
                    raise ValueError(f"Failed to load email data: {str(load_error)}\n\n"
                                   f"Common issues:\n"
                                   f"• CSV contains non-numeric columns (IDs, filenames)\n"
                                   f"• Missing 'label' column and filename doesn't indicate class\n"
                                   f"• Feature count mismatch (need 17 features for email)\n"
                                   f"• Data contains text values instead of numbers")
                
                # Train email model
                metrics = trainer.train_email_model(X, y, model_type='random_forest')
                
            elif self.training_type == 'file':
                try:
                    X, y = self._load_file_data()
                    self.progress.emit(40, f"Loaded {len(X)} file samples ({X.shape[1]} features). Training model...")
                except Exception as load_error:
                    raise ValueError(f"Failed to load file data: {str(load_error)}\n\n"
                                   f"Common issues:\n"
                                   f"• CSV contains non-numeric columns (IDs, filenames)\n"
                                   f"• Missing 'label' column and filename doesn't indicate class\n"
                                   f"• Feature count mismatch (need 11 features for file)\n"
                                   f"• Data contains text values instead of numbers")
                
                # Train file model
                metrics = trainer.train_file_model(X, y, model_type='random_forest')
            
            self.progress.emit(95, "Saving model...")
            
            # Add file count to metrics
            metrics['training_files'] = len(self.data_files)
            metrics['training_samples'] = len(X)
            
            self.progress.emit(100, "Training completed!")
            self.finished.emit(metrics)
            
        except Exception as e:
            error_msg = f"Training failed: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
            self.error.emit(error_msg)
    
    def _load_email_data(self):
        """Load email features and labels from CSV/NPY files"""
        X_list = []
        y_list = []
        
        for file_path in self.data_files:
            file_path = Path(file_path)
            
            if file_path.suffix == '.npy':
                # Load numpy array
                data = np.load(file_path, allow_pickle=True)
                if data.ndim == 1 and len(data) == 2:
                    # Format: [features, labels]
                    X_list.append(data[0])
                    y_list.append(data[1])
                else:
                    # Assume features only, infer label from filename
                    label = 1 if 'phishing' in file_path.name.lower() else 0
                    X_list.append(data)
                    y_list.extend([label] * len(data))
                    
            elif file_path.suffix == '.csv':
                # Load CSV
                import pandas as pd
                df = pd.read_csv(file_path)
                
                # Remove non-numeric columns that might be IDs or filenames
                non_feature_cols = []
                for col in df.columns:
                    # Check if column contains string data that looks like filenames
                    if df[col].dtype == 'object':
                        sample_val = str(df[col].iloc[0]) if len(df) > 0 else ''
                        # Remove if looks like filename/ID
                        if any(ext in sample_val.lower() for ext in ['.txt', '.exe', '.pdf', '.doc', '.csv']):
                            non_feature_cols.append(col)
                            continue
                        # Remove if column name suggests it's an ID
                        if any(id_name in col.lower() for id_name in ['id', 'name', 'file', 'path', 'email']):
                            non_feature_cols.append(col)
                
                # Drop non-feature columns
                if non_feature_cols:
                    df = df.drop(columns=non_feature_cols)
                
                # Find label column
                label_col = None
                if 'label' in df.columns:
                    label_col = 'label'
                elif 'is_phishing' in df.columns:
                    label_col = 'is_phishing'
                elif 'is_malware' in df.columns:
                    label_col = 'is_malware'
                elif 'class' in df.columns:
                    label_col = 'class'
                elif 'target' in df.columns:
                    label_col = 'target'
                
                if label_col:
                    # Extract features and labels
                    X_data = df.drop(label_col, axis=1)
                    y_data = df[label_col]
                else:
                    # No label column, infer from filename
                    label = 1 if 'phishing' in file_path.name.lower() or 'malware' in file_path.name.lower() else 0
                    X_data = df
                    y_data = pd.Series([label] * len(df))
                
                # Convert to numeric, coerce errors to NaN
                X_data = X_data.apply(pd.to_numeric, errors='coerce')
                
                # Fill NaN values with 0
                X_data = X_data.fillna(0)
                
                # Validate no infinite values
                X_data = X_data.replace([np.inf, -np.inf], 0)
                
                X_list.append(X_data.values)
                y_list.extend(y_data.values)
        
        # Concatenate all data
        if not X_list:
            raise ValueError("No valid data loaded from files")
        
        X = np.vstack(X_list)
        y = np.array(y_list)
        
        # Final validation
        if X.shape[0] == 0:
            raise ValueError("No samples found in data files")
        
        if X.shape[0] != len(y):
            raise ValueError(f"Feature count ({X.shape[0]}) doesn't match label count ({len(y)})")
        
        # Check for non-numeric data
        if not np.issubdtype(X.dtype, np.number):
            raise ValueError("Data contains non-numeric values. Please ensure all features are numeric.")
        
        # Check for NaN or Inf
        if np.any(np.isnan(X)):
            raise ValueError("Data contains NaN values after cleaning")
        
        if np.any(np.isinf(X)):
            raise ValueError("Data contains infinite values after cleaning")
        
        return X, y
    
    def _load_file_data(self):
        """Load file features and labels from CSV/NPY files"""
        # Similar to email data loading
        return self._load_email_data()


class TrainingTab(QWidget):
    """Tab for training custom models with user's data"""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.selected_files = []
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🎓 Train Custom Detection Models")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)
        layout.addWidget(header)
        
        # Instructions
        instructions = QLabel(
            "Train your own models with custom datasets:\n"
            "• Email Model: CSV/NPY files with 17 email features\n"
            "• File Model: CSV/NPY files with 11 file features\n"
            "• Files should contain features as columns and optional 'label' column"
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #95a5a6; padding: 10px;")
        layout.addWidget(instructions)
        
        # Model type selection
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("Model Type:"))
        self.model_type = QComboBox()
        self.model_type.addItems(["Email Phishing Detector", "File Malware Analyzer"])
        model_layout.addWidget(self.model_type)
        model_layout.addStretch()
        layout.addLayout(model_layout)
        
        # File selection
        file_layout = QHBoxLayout()
        self.select_files_btn = QPushButton("📁 Select Training Data Files")
        self.select_files_btn.clicked.connect(self.select_files)
        file_layout.addWidget(self.select_files_btn)
        
        self.file_count_label = QLabel("No files selected")
        self.file_count_label.setStyleSheet("color: #95a5a6;")
        file_layout.addWidget(self.file_count_label)
        file_layout.addStretch()
        layout.addLayout(file_layout)
        
        # Selected files list
        layout.addWidget(QLabel("Selected Files:"))
        self.files_list = QTextEdit()
        self.files_list.setReadOnly(True)
        self.files_list.setMaximumHeight(150)
        layout.addWidget(self.files_list)
        
        # Training button
        self.train_btn = QPushButton("🚀 Start Training")
        self.train_btn.setStyleSheet("background-color: #27ae60; font-size: 14px; padding: 12px;")
        self.train_btn.clicked.connect(self.start_training)
        self.train_btn.setEnabled(False)
        layout.addWidget(self.train_btn)
        
        # Progress section
        self.progress_label = QLabel("Ready to train")
        self.progress_label.setStyleSheet("color: #95a5a6;")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results section
        layout.addWidget(QLabel("Training Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(250)
        layout.addWidget(self.results_text)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def select_files(self):
        """Open file dialog to select training data files"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Training Data Files",
            "",
            "Data Files (*.csv *.npy);;All Files (*.*)"
        )
        
        if files:
            self.selected_files = files
            self.file_count_label.setText(f"{len(files)} file(s) selected")
            self.train_btn.setEnabled(True)
            
            # Display file list
            file_list = "\n".join([f"• {Path(f).name}" for f in files])
            self.files_list.setText(file_list)
    
    def start_training(self):
        """Start model training in background thread"""
        if not self.selected_files:
            QMessageBox.warning(self, "No Files", "Please select training data files first")
            return
        
        # Determine training type
        training_type = 'email' if self.model_type.currentIndex() == 0 else 'file'
        
        # Confirm training
        reply = QMessageBox.question(
            self,
            "Confirm Training",
            f"Start training {training_type} model with {len(self.selected_files)} file(s)?\n\n"
            f"This may take several minutes depending on dataset size.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Disable UI during training
        self.train_btn.setEnabled(False)
        self.select_files_btn.setEnabled(False)
        self.model_type.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        # Start training worker
        self.worker = TrainingWorker(training_type, self.selected_files)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.display_results)
        self.worker.error.connect(self.show_error)
        self.worker.start()
    
    def update_progress(self, value, message):
        """Update progress bar and label"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def display_results(self, metrics):
        """Display training results"""
        self.progress_bar.setVisible(False)
        self.train_btn.setEnabled(True)
        self.select_files_btn.setEnabled(True)
        self.model_type.setEnabled(True)
        self.progress_label.setText("Training completed successfully!")
        
        # Format results as HTML
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #ecf0f1;">
            <div style="background-color: #27ae60; color: white; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
                <strong>✅ Training Completed Successfully!</strong>
            </div>
            
            <div style="background-color: #34495e; padding: 15px; border-radius: 5px; margin-bottom: 10px;">
                <h3 style="color: #3498db; margin-top: 0;">Training Summary</h3>
                <table style="width: 100%; color: #ecf0f1;">
                    <tr>
                        <td><strong>Training Files:</strong></td>
                        <td>{metrics.get('training_files', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td><strong>Training Samples:</strong></td>
                        <td>{metrics.get('training_samples', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td><strong>Model Type:</strong></td>
                        <td>Random Forest</td>
                    </tr>
                </table>
            </div>
            
            <div style="background-color: #34495e; padding: 15px; border-radius: 5px;">
                <h3 style="color: #3498db; margin-top: 0;">Performance Metrics</h3>
                <table style="width: 100%; color: #ecf0f1;">
                    <tr>
                        <td><strong>Accuracy:</strong></td>
                        <td style="color: #2ecc71; font-weight: bold;">{metrics.get('accuracy', 0):.2%}</td>
                    </tr>
                    <tr>
                        <td><strong>Precision:</strong></td>
                        <td>{metrics.get('precision', 0):.2%}</td>
                    </tr>
                    <tr>
                        <td><strong>Recall:</strong></td>
                        <td>{metrics.get('recall', 0):.2%}</td>
                    </tr>
                    <tr>
                        <td><strong>F1-Score:</strong></td>
                        <td style="color: #3498db; font-weight: bold;">{metrics.get('f1', 0):.4f}</td>
                    </tr>
                    <tr>
                        <td><strong>ROC-AUC:</strong></td>
                        <td>{metrics.get('roc_auc', 0):.4f}</td>
                    </tr>
                </table>
            </div>
            
            <div style="margin-top: 15px; padding: 10px; background-color: #2c3e50; border-left: 4px solid #3498db; border-radius: 4px;">
                <strong>ℹ️ Note:</strong> Model saved to <code>data/models/</code> directory.<br>
                Restart the application to use the new model.
            </div>
        </body>
        </html>
        """
        
        self.results_text.setHtml(html)
        
        # Show success message
        QMessageBox.information(
            self,
            "Training Complete",
            f"Model trained successfully!\n\n"
            f"Accuracy: {metrics.get('accuracy', 0):.2%}\n"
            f"F1-Score: {metrics.get('f1', 0):.4f}\n\n"
            f"Model saved to data/models/ directory."
        )
    
    def show_error(self, error_message):
        """Display error message"""
        self.progress_bar.setVisible(False)
        self.train_btn.setEnabled(True)
        self.select_files_btn.setEnabled(True)
        self.model_type.setEnabled(True)
        self.progress_label.setText("Training failed")
        
        # Display error in results area
        html = f"""
        <html>
        <body style="font-family: 'Consolas', monospace; color: #ecf0f1; background-color: #2c3e50;">
            <div style="background-color: #c0392b; color: white; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
                <strong>❌ Training Failed</strong>
            </div>
            <pre style="color: #e74c3c; white-space: pre-wrap; word-wrap: break-word;">{error_message}</pre>
        </body>
        </html>
        """
        self.results_text.setHtml(html)
        
        # Show error dialog
        QMessageBox.critical(self, "Training Error", f"Training failed:\n\n{error_message[:500]}")


class MainWindow(QMainWindow):
    """Optimized main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ Phishing Detection & Malware Analysis Suite")
        
        # Set minimum size
        self.setMinimumSize(800, 600)
        self.init_ui()
        
    def init_ui(self):
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        # Logo
        logo_label = QLabel()
        logo_path = Path(__file__).parent.parent.parent / "resources" / "images" / "logo.png"
        if logo_path.exists():
            pixmap = QPixmap(str(logo_path))
            if not pixmap.isNull():
                # Scale logo to appropriate size (150x150)
                scaled_pixmap = pixmap.scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                logo_label.setPixmap(scaled_pixmap)
                logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(logo_label)
            else:
                # Pixmap failed to load - show placeholder
                logo_label.setText("🛡️")
                logo_label.setStyleSheet("font-size: 64px;")
                logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(logo_label)
        else:
            # Logo file not found - show placeholder
            logo_label.setText("🛡️")
            logo_label.setStyleSheet("font-size: 64px;")
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(logo_label)
        
        # Header
        header = QLabel("Phishing & Malware Detection Suite")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Tabs
        tabs = QTabWidget()
        tabs.addTab(EmailDetectorTab(), "📧 Email Detector")
        tabs.addTab(FileAnalyzerTab(), "🔒 File Analyzer")
        tabs.addTab(TrainingTab(), "🎓 Train Model")
        tabs.addTab(SettingsTab(), "⚙️ Settings")
        layout.addWidget(tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready • Defensive Security Tool")
        
        central_widget.setLayout(layout)
        
        # Set stylesheet
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
            }
            QLabel {
                color: #ecf0f1;
            }
            QTextEdit, QLineEdit {
                background-color: #34495e;
                color: #ecf0f1;
                border: 1px solid #566573;
                border-radius: 4px;
                padding: 5px;
            }
            QTextEdit:read-only {
                background-color: #283747;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #566573;
                color: #95a5a6;
            }
            QTabWidget::pane {
                border: 1px solid #566573;
                border-radius: 4px;
            }
            QTabBar::tab {
                background: #34495e;
                color: #ecf0f1;
                padding: 10px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #4a6278;
            }
            QProgressBar {
                border: 1px solid #566573;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2ecc71;
                width: 10px;
                margin: 0.5px;
            }
        """)


def main():
    try:
        # Auto-create desktop shortcut on first run
        create_desktop_shortcut()
        
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        window = MainWindow()
        # Show window maximized (fill screen)
        window.showMaximized()
        
        sys.exit(app.exec())
    except Exception as e:
        print(f"❌ Error starting desktop application: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
