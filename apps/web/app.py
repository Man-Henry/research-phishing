"""
Flask Web Application for Email Phishing & Malware Detection
Main application file
"""

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import sys
from pathlib import Path
import json
import hashlib

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.detectors.email_detector import EmailPhishingDetector, EmailHeaderParser
from src.detectors.file_analyzer import MalwareAnalyzer

# Initialize Flask app
app = Flask(__name__, 
            template_folder=str(Path(__file__).parent / 'templates'),
            static_folder=str(Path(__file__).parent / 'static'))

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'elf', 'zip', 'rar', 'pdf', 'doc', 'txt', 'docx'}

# Create upload folder
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)

# Initialize detectors with error handling
try:
    email_detector = EmailPhishingDetector()
    print("✓ Email detector initialized")
except Exception as e:
    print(f"⚠ Email detector error: {e}")
    email_detector = None

try:
    file_analyzer = MalwareAnalyzer()
    print("✓ File analyzer initialized")
except Exception as e:
    print(f"⚠ File analyzer error: {e}")
    file_analyzer = None

def allowed_file(filename):
    """Check if file type is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===================== EMAIL ROUTES =====================

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/email-detector')
def email_detector_page():
    """Email detector page."""
    return render_template('email_detector.html')

@app.route('/file-analyzer')
def file_analyzer_page():
    """File analyzer page."""
    return render_template('file_analyzer.html')

@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    """Analyze email for phishing."""
    try:
        # Check if email detector is initialized
        if email_detector is None:
            return jsonify({
                'error': 'Email detector service not available',
                'status': 'error'
            }), 503
        
        data = request.json
        
        if not data or 'email_content' not in data:
            return jsonify({'error': 'Email content required'}), 400
        
        email_content = data['email_content']
        email_headers = data.get('email_headers', {})
        
        # Extract features
        features = email_detector.extract_features(email_content, email_headers)
        
        # Make prediction
        prediction, confidence = email_detector.predict(features)
        
        # Prepare response
        result = {
            'status': 'success',
            'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
            'confidence': f'{confidence:.1%}',
            'confidence_numeric': float(confidence),
            'features': {
                'spf_pass': int(features[0]),
                'dkim_pass': int(features[1]),
                'dmarc_pass': int(features[2]),
                'url_count': int(features[4]),
                'has_shortener': int(features[5]),
                'suspicious_keywords': int(features[7]),
                'urgency_score': f'{features[9]:.2f}',
            },
            'recommendation': 'Be cautious with this email' if prediction == 1 else 'Appears to be legitimate'
        }
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

# ===================== FILE ROUTES =====================

@app.route('/api/analyze-file', methods=['POST'])
def analyze_file_api():
    """Analyze file for malware."""
    try:
        # Check if file analyzer is initialized
        if file_analyzer is None:
            return jsonify({
                'error': 'File analyzer service not available',
                'status': 'error'
            }), 503
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze file
            features = file_analyzer.analyze_file(filepath)
            hashes = file_analyzer.get_file_hash(filepath)
            
            # Make prediction
            prediction, confidence = file_analyzer.classify(features)
            
            # Prepare response
            result = {
                'status': 'success',
                'filename': filename,
                'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                'confidence': f'{confidence:.1%}',
                'confidence_numeric': float(confidence),
                'hashes': {
                    'md5': hashes['md5'],
                    'sha1': hashes['sha1'],
                    'sha256': hashes['sha256'],
                },
                'features': {
                    'entropy': f'{features[2]:.2f}',
                    'has_pe_header': bool(features[3]),
                    'has_elf_header': bool(features[4]),
                    'suspicious_strings': int(features[6]),
                },
                'recommendation': 'Quarantine this file' if prediction == 1 else 'File appears safe'
            }
            
            return jsonify(result), 200
        
        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)
    
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/hash-lookup', methods=['POST'])
def hash_lookup():
    """Lookup file hash (demonstration)."""
    try:
        data = request.json
        hash_value = data.get('hash', '')
        
        # This is a demonstration - in production, query VirusTotal API
        result = {
            'status': 'success',
            'hash': hash_value,
            'detections': 0,
            'status_message': 'Hash lookup would connect to VirusTotal API in production'
        }
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

# ===================== INFO ROUTES =====================

@app.route('/api/stats')
def get_stats():
    """Get system statistics."""
    return jsonify({
        'status': 'success',
        'email_features': 16,
        'file_features': 11,
        'models': ['Random Forest', 'Gradient Boosting', 'Heuristic'],
        'email_accuracy_range': '50-95%',
        'file_accuracy_range': '60-98%'
    })

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

@app.route('/help')
def help_page():
    """Help page."""
    return render_template('help.html')

# ===================== ERROR HANDLERS =====================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════╗
    ║  Email Phishing & Malware Detection System    ║
    ║  Web Application                              ║
    ║                                               ║
    ║  Starting server...                           ║
    ║  Open: http://localhost:5000                 ║
    ╚════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
