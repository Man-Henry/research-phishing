"""
Malware File Analysis Module

Analyzes files for malicious characteristics using:
- File header/magic number validation
- Binary feature extraction
- Entropy calculation
- Suspicious pattern detection
"""

import os
import hashlib
import struct
import numpy as np
from typing import Dict, Tuple, Optional
from pathlib import Path
import joblib


class MalwareAnalyzer:
    """Analyzes files for malware signatures and suspicious characteristics."""
    
    # Known malicious file signatures (magic bytes)
    MALICIOUS_SIGNATURES = {
        b'MZ': 'PE_EXECUTABLE',  # Windows EXE/DLL
        b'\x7fELF': 'ELF_EXECUTABLE',  # Linux executable
        b'PK\x03\x04': 'ZIP_ARCHIVE',  # ZIP files (often used for malware)
    }
    
    SUSPICIOUS_STRINGS = [
        b'CreateRemoteThread',
        b'WriteProcessMemory',
        b'SetWindowsHookEx',
        b'ShellExecute',
        b'WinExec',
        b'GetProcAddress',
        b'LoadLibrary',
    ]
    
    # Class-level cache for models (singleton pattern)
    _model_cache: Optional[Dict] = None
    
    def __init__(self, model_dir: str = 'data/models'):
        self.max_file_size = 100 * 1024 * 1024  # 100MB limit
        
        # Load ML model if available (with caching)
        self.model_dir = Path(model_dir)
        self._load_models()
    
    def _load_models(self):
        """
        Load pre-trained Random Forest model and scaler.
        Uses class-level caching to avoid reloading models multiple times.
        """
        # Check class-level cache first (singleton pattern)
        if MalwareAnalyzer._model_cache is not None:
            self.model = MalwareAnalyzer._model_cache.get('model')
            self.scaler = MalwareAnalyzer._model_cache.get('scaler')
            self.use_ml_model = self.model is not None and self.scaler is not None
            return
        
        # Try to load models from disk
        model_path = self.model_dir / 'malware_classifier.pkl'
        scaler_path = self.model_dir / 'file_scaler.pkl'
        
        try:
            if model_path.exists() and scaler_path.exists():
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.use_ml_model = True
                
                # Cache models at class level
                MalwareAnalyzer._model_cache = {
                    'model': self.model,
                    'scaler': self.scaler
                }
                
                print(f"[OK] Loaded optimized Random Forest file model from {model_path}")
            else:
                self.model = None
                self.scaler = None
                self.use_ml_model = False
                print(f"[WARNING] No pre-trained model found at {model_path}")
                print(f"  Using heuristic-based detection only.")
                print(f"  Run 'python train_pretrained_models.py' to train models.")
        except Exception as e:
            print(f"[WARNING] Error loading model: {e}")
            self.model = None
            self.scaler = None
            self.use_ml_model = False
    
    def analyze_file(self, file_path: str) -> np.ndarray:
        """
        Extract features from a file.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Feature vector as numpy array
        """
        features = {}
        
        try:
            # File metadata features
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            features['file_size'] = file_size
            features['file_extension'] = len(file_path.suffix) if file_path.suffix else 0
            
            # Read file for analysis
            with open(file_path, 'rb') as f:
                file_content = f.read(min(file_size, self.max_file_size))
            
            # Binary features
            features['entropy'] = self._calculate_entropy(file_content)
            features['has_pe_header'] = self._has_pe_header(file_content)
            features['has_elf_header'] = self._has_elf_header(file_content)
            features['null_byte_ratio'] = self._get_null_byte_ratio(file_content)
            
            # Suspicious pattern features
            features['suspicious_strings_count'] = self._count_suspicious_strings(file_content)
            features['has_zip_header'] = self._has_zip_header(file_content)
            features['has_executable_code'] = self._has_executable_code(file_content)
            
            # Byte frequency analysis
            features['avg_byte_value'] = np.mean(np.frombuffer(file_content, dtype=np.uint8))
            
            # Header analysis
            features['magic_number'] = self._get_magic_number_score(file_content)
            
            return np.array(list(features.values()), dtype=np.float32)
        
        except Exception as e:
            print(f"Error analyzing file: {e}")
            return np.array([0] * 11, dtype=np.float32)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of file.
        High entropy (7-8) = compressed/encrypted (suspicious)
        Low entropy (< 3) = plain text (less suspicious)
        """
        if len(data) == 0:
            return 0
        
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data[:10000], dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data[:10000])
        probabilities = probabilities[probabilities > 0]
        
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _has_pe_header(self, data: bytes) -> int:
        """Check for PE (Windows executable) header."""
        return 1 if data.startswith(b'MZ') else 0
    
    def _has_elf_header(self, data: bytes) -> int:
        """Check for ELF (Linux executable) header."""
        return 1 if data.startswith(b'\x7fELF') else 0
    
    def _get_null_byte_ratio(self, data: bytes) -> float:
        """Calculate ratio of null bytes (common in binaries)."""
        if len(data) == 0:
            return 0
        null_count = data.count(b'\x00')
        return null_count / len(data)
    
    def _count_suspicious_strings(self, data: bytes) -> int:
        """Count occurrences of suspicious API/function strings."""
        count = 0
        for suspicious_str in self.SUSPICIOUS_STRINGS:
            count += data.count(suspicious_str)
        return count
    
    def _has_zip_header(self, data: bytes) -> int:
        """Check for ZIP archive header (often used for obfuscation)."""
        return 1 if data.startswith(b'PK\x03\x04') else 0
    
    def _has_executable_code(self, data: bytes) -> int:
        """Check for executable code patterns."""
        # Common executable opcodes
        executable_opcodes = [b'\x90', b'\x55', b'\x89', b'\x83', b'\xC3', b'\xC9']
        return 1 if any(opcode in data[:1000] for opcode in executable_opcodes) else 0
    
    def _get_magic_number_score(self, data: bytes) -> int:
        """
        Score based on file magic number.
        Executable formats are more suspicious.
        """
        if len(data) < 4:
            return 0
        
        magic = data[:4]
        if magic.startswith(b'MZ'):
            return 10  # PE executable - high risk
        elif magic.startswith(b'\x7fELF'):
            return 10  # ELF executable - high risk
        elif magic.startswith(b'PK'):
            return 5  # Archive - medium risk
        else:
            return 0  # Unknown/text - low risk
    
    def get_file_hash(self, file_path: str) -> Dict[str, str]:
        """
        Calculate cryptographic hashes of file.
        
        Returns:
            Dictionary with MD5, SHA1, SHA256 hashes
        """
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        except Exception as e:
            print(f"Error calculating hash: {e}")
        
        return hashes
    
    def classify(self, features: np.ndarray, model=None) -> Dict:
        """
        Classify file as malicious or benign.
        
        Args:
            features: Feature vector from analyze_file()
            model: Trained ML model (optional, uses self.model if available)
            
        Returns:
            Dictionary with 'is_malware' (bool) and 'confidence' (float)
            0 = benign, 1 = malicious
        """
        # Use provided model, or fall back to loaded model, or use heuristics
        active_model = model if model is not None else (self.model if self.use_ml_model else None)
        
        if active_model is not None:
            # Use Random Forest model
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            prediction = int(active_model.predict(features_scaled)[0])
            proba = active_model.predict_proba(features_scaled)[0]
            confidence = float(proba[1])  # Probability of malware
        else:
            # Heuristic scoring (fallback)
            score = self._heuristic_score(features)
            prediction = 1 if score > 0.5 else 0
            # Ensure confidence is between 0 and 1
            confidence = float(max(0, min(1, abs(score))))
        
        return {
            'is_malware': bool(prediction),
            'confidence': confidence
        }
    
    def classify_from_features(self, features: np.ndarray, model=None) -> Tuple[int, float]:
        """
        Classify from features (legacy method returning tuple).
        
        Args:
            features: Feature vector from analyze_file()
            model: Trained ML model (if None, uses heuristics)
            
        Returns:
            Tuple of (prediction, confidence_score)
            0 = benign, 1 = malicious
        """
        if model is not None:
            # Use trained ML model
            return model.predict(features.reshape(1, -1))[0], \
                   model.predict_proba(features.reshape(1, -1))[0].max()
        else:
            # Heuristic scoring
            score = self._heuristic_score(features)
            prediction = 1 if score > 0.5 else 0
            # Ensure confidence is between 0 and 1
            confidence = max(0, min(1, abs(score)))
            return prediction, confidence
    
    def _heuristic_score(self, features: np.ndarray) -> float:
        """Calculate malware probability using heuristics."""
        score = 0.0
        
        # High entropy = compressed/encrypted (suspicious)
        if features[2] > 7.0:
            score += 0.25
        
        # Executable headers
        if features[3] == 1:  # PE header
            score += 0.30
        if features[4] == 1:  # ELF header
            score += 0.30
        
        # Suspicious strings
        if features[6] > 5:
            score += 0.20
        
        # ZIP in executable (obfuscation)
        if features[7] == 1:
            score += 0.15
        
        # Executable code patterns
        if features[8] == 1:
            score += 0.15
        
        # Magic number score
        if features[10] >= 10:
            score += 0.30
        elif features[10] >= 5:
            score += 0.10
        
        # File size anomalies
        if features[0] < 100:  # Too small
            score -= 0.05
        if features[0] > 50 * 1024 * 1024:  # > 50MB
            score += 0.10
        
        return min(1.0, score)


class FileHashDatabase:
    """Database for known malware file hashes (VirusTotal-like)."""
    
    def __init__(self):
        self.known_malicious_hashes = set()
        self.known_benign_hashes = set()
    
    def add_malicious_hash(self, hash_value: str):
        """Add known malicious file hash."""
        self.known_malicious_hashes.add(hash_value.lower())
    
    def add_benign_hash(self, hash_value: str):
        """Add known benign file hash."""
        self.known_benign_hashes.add(hash_value.lower())
    
    def check_hash(self, hash_value: str) -> str:
        """
        Check file hash against database.
        
        Returns:
            'malicious', 'benign', or 'unknown'
        """
        hash_value = hash_value.lower()
        if hash_value in self.known_malicious_hashes:
            return 'malicious'
        elif hash_value in self.known_benign_hashes:
            return 'benign'
        else:
            return 'unknown'
