"""
Email Phishing Detection Module

Analyzes email headers, content, and metadata to detect phishing attempts.
Features include:
- Header validation (SPF, DKIM, DMARC)
- URL and link analysis
- Sender reputation checking
- Content-based suspicion scoring
"""

import re
import numpy as np
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from pathlib import Path
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import sys
# Add parent directory to path for both development and PyInstaller
if getattr(sys, 'frozen', False):
    # Running as compiled exe
    import os
    base_path = sys._MEIPASS
    sys.path.insert(0, os.path.join(base_path, 'src'))
else:
    # Running as script
    sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from utils.language_detector import LanguageDetector
except ImportError:
    # Fallback for PyInstaller
    from src.utils.language_detector import LanguageDetector

# Download required NLTK data (with error handling)
try:
    nltk.data.find('tokenizers/punkt_tab')
except LookupError:
    try:
        nltk.download('punkt_tab', quiet=True)
    except:
        pass  # Continue without punkt_tab
    
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    try:
        nltk.download('stopwords', quiet=True)
    except:
        pass  # Continue without stopwords


class EmailPhishingDetector:
    """Detects phishing emails using feature extraction and ML models."""
    
    # Class-level cache for models (singleton pattern)
    _model_cache: Optional[Dict] = None
    
    def __init__(self, model_dir: str = 'data/models'):
        self.stop_words = set(stopwords.words('english'))
        self.suspicious_keywords = [
            'verify', 'confirm', 'urgent', 'act now', 'click here',
            'update password', 'validate', 'suspended', 'locked',
            'unauthorized access', 'unusual activity', 'confirm identity',
            're-enter', 'reactivate', 'limited time'
        ]
        self.phishing_patterns = {
            'url_shortener': r'(bit\.ly|tinyurl|goo\.gl|short\.link)',
            'ip_address': r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'suspicious_domain': r'@[a-z0-9]*-[a-z0-9]*\.[a-z]+',
        }
        
        # Initialize language detector
        self.language_detector = LanguageDetector()
        
        # Load ML model if available (with caching)
        self.model_dir = Path(model_dir)
        self._load_models()
    
    def _load_models(self):
        """
        Load pre-trained Random Forest model and scaler.
        Uses class-level caching to avoid reloading models multiple times.
        """
        # Check class-level cache first (singleton pattern)
        if EmailPhishingDetector._model_cache is not None:
            self.model = EmailPhishingDetector._model_cache.get('model')
            self.scaler = EmailPhishingDetector._model_cache.get('scaler')
            self.n_features = EmailPhishingDetector._model_cache.get('n_features', 17)
            self.use_ml_model = self.model is not None and self.scaler is not None
            return
        
        # Try to load models from disk
        model_path = self.model_dir / 'email_phishing_detector.pkl'
        scaler_path = self.model_dir / 'email_scaler.pkl'
        metadata_path = self.model_dir / 'email_metadata.pkl'
        
        try:
            if model_path.exists() and scaler_path.exists():
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                
                # Load feature count from metadata
                if metadata_path.exists():
                    metadata = joblib.load(metadata_path)
                    self.n_features = metadata.get('n_features', 17)
                else:
                    self.n_features = 17  # Default for backward compatibility
                
                self.use_ml_model = True
                
                # Cache models at class level
                EmailPhishingDetector._model_cache = {
                    'model': self.model,
                    'scaler': self.scaler,
                    'n_features': self.n_features
                }
                
                print(f"[OK] Loaded optimized Random Forest email model from {model_path}")
                print(f"[OK] Model expects {self.n_features} features")
            else:
                self.model = None
                self.scaler = None
                self.n_features = 17
                self.use_ml_model = False
                print(f"[WARNING] No pre-trained model found at {model_path}")
                print(f"  Using heuristic-based detection only.")
                print(f"  Run 'python train_pretrained_models.py' to train models.")
        except Exception as e:
            print(f"[WARNING] Error loading model: {e}")
            self.model = None
            self.scaler = None
            self.use_ml_model = False
    
    def extract_features(self, email_content: str, email_headers: Dict = None) -> np.ndarray:
        """
        Extract features from email content and headers.
        
        Args:
            email_content: Body text of the email
            email_headers: Dictionary of email headers
            
        Returns:
            Feature vector as numpy array
        """
        features_dict = self._extract_feature_dict(email_content, email_headers)
        return np.array(list(features_dict.values()), dtype=np.float32)
    
    def _extract_feature_dict(self, email_content: str, email_headers: Dict = None) -> Dict:
        """
        Extract features as dictionary (internal method).
        
        Args:
            email_content: Body text of the email
            email_headers: Dictionary of email headers
            
        Returns:
            Dictionary of features
        """
        features = {}
        
        # Header-based features
        if email_headers:
            features['spf_pass'] = self._check_spf(email_headers)
            features['dkim_pass'] = self._check_dkim(email_headers)
            features['dmarc_pass'] = self._check_dmarc(email_headers)
            features['sender_domain_age'] = self._get_domain_age(email_headers.get('From', ''))
        else:
            features['spf_pass'] = 0
            features['dkim_pass'] = 0
            features['dmarc_pass'] = 0
            features['sender_domain_age'] = 0
        
        # Content-based features
        features['url_count'] = self._count_urls(email_content)
        features['has_shortener_urls'] = self._has_suspicious_urls(email_content)
        features['has_ip_based_urls'] = self._has_ip_urls(email_content)
        features['suspicious_keyword_count'] = self._count_suspicious_keywords(email_content)
        features['urgency_score'] = self._calculate_urgency_score(email_content)
        features['capitalization_ratio'] = self._get_capitalization_ratio(email_content)
        features['special_char_ratio'] = self._get_special_char_ratio(email_content)
        features['html_tag_count'] = email_content.count('<') + email_content.count('>')
        features['has_email_form'] = self._has_email_form(email_content)
        
        # Text analysis features
        features['avg_word_length'] = self._get_avg_word_length(email_content)
        features['unique_word_ratio'] = self._get_unique_word_ratio(email_content)
        features['has_urgency_words'] = len(re.findall(r'\b(urgent|immediately|now|asap)\b', 
                                                       email_content, re.IGNORECASE)) > 0
        
        return features
    
    def _check_spf(self, headers: Dict) -> int:
        """Check if SPF record passed."""
        return 1 if headers.get('SPF-Result') == 'pass' else 0
    
    def _check_dkim(self, headers: Dict) -> int:
        """Check if DKIM signature verified."""
        return 1 if headers.get('DKIM-Signature') else 0
    
    def _check_dmarc(self, headers: Dict) -> int:
        """Check if DMARC passed."""
        return 1 if headers.get('DMARC-Result') == 'pass' else 0
    
    def _get_domain_age(self, sender: str) -> int:
        """Estimate domain age (0-10 scale). New domains are more suspicious."""
        # Extract domain from email
        match = re.search(r'@([a-zA-Z0-9.-]+)', sender)
        if not match:
            return 0
        # Simplified: just return 5 as placeholder
        # In production, query WHOIS database
        return 5
    
    def _count_urls(self, content: str) -> int:
        """Count number of URLs in email."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return len(re.findall(url_pattern, content))
    
    def _has_suspicious_urls(self, content: str) -> int:
        """Check for URL shorteners or suspicious patterns."""
        return 1 if re.search(self.phishing_patterns['url_shortener'], content) else 0
    
    def _has_ip_urls(self, content: str) -> int:
        """Check for IP-based URLs (suspicious)."""
        return 1 if re.search(self.phishing_patterns['ip_address'], content) else 0
    
    def _count_suspicious_keywords(self, content: str) -> int:
        """Count suspicious phishing-related keywords."""
        content_lower = content.lower()
        count = 0
        for keyword in self.suspicious_keywords:
            count += len(re.findall(r'\b' + keyword + r'\b', content_lower))
        return count
    
    def _calculate_urgency_score(self, content: str) -> float:
        """Calculate urgency level (0-1)."""
        urgency_indicators = ['!', 'urgent', 'immediate', 'act now', 'asap', 'limited time']
        content_lower = content.lower()
        exclamation_count = content.count('!')
        keyword_count = sum(1 for word in urgency_indicators 
                          if word in content_lower)
        return min(1.0, (exclamation_count + keyword_count * 2) / 10.0)
    
    def _get_capitalization_ratio(self, content: str) -> float:
        """Calculate ratio of capitalized letters (excessive caps = suspicious)."""
        if len(content) == 0:
            return 0
        capitals = sum(1 for c in content if c.isupper())
        return capitals / len(content)
    
    def _get_special_char_ratio(self, content: str) -> float:
        """Calculate ratio of special characters."""
        if len(content) == 0:
            return 0
        special = sum(1 for c in content if not c.isalnum() and not c.isspace())
        return special / len(content)
    
    def _has_email_form(self, content: str) -> int:
        """Check if email requests user to enter email/password."""
        form_keywords = ['enter your', 'confirm your', 'verify your', 'click here', 'login']
        return 1 if any(keyword in content.lower() for keyword in form_keywords) else 0
    
    def _get_avg_word_length(self, content: str) -> float:
        """Calculate average word length."""
        words = word_tokenize(content)
        if len(words) == 0:
            return 0
        return np.mean([len(word) for word in words if word.isalnum()])
    
    def _get_unique_word_ratio(self, content: str) -> float:
        """Calculate ratio of unique words to total words."""
        words = [w.lower() for w in word_tokenize(content) if w.isalnum()]
        if len(words) == 0:
            return 0
        return len(set(words)) / len(words)
    
    def predict(self, email_content: str, email_headers: Dict = None, model=None) -> Dict:
        """
        Analyze email and predict if it's phishing.
        
        Args:
            email_content: Email body text or full content
            email_headers: Optional dictionary of email headers
            model: Trained ML model (optional, uses self.model if available)
            
        Returns:
            Dictionary with 'is_phishing' (bool), 'confidence' (float), and 'features' (dict)
        """
        # Extract features as dictionary
        features_dict = self._extract_feature_dict(email_content, email_headers)
        # Convert to array for prediction
        features = np.array(list(features_dict.values()), dtype=np.float32)
        
        # Auto-padding: if model expects more features, pad with zeros
        if hasattr(self, 'n_features') and len(features) < self.n_features:
            padding = np.zeros(self.n_features - len(features))
            features = np.hstack([features, padding])
            print(f"[INFO] Padded features from {len(features_dict)} to {self.n_features}")
        
        # Use provided model, or fall back to loaded model, or use heuristics
        active_model = model if model is not None else (self.model if self.use_ml_model else None)
        
        # Always calculate heuristic score for validation
        heuristic_score = self._heuristic_score(features[:len(features_dict)])  # Use original features for heuristics
        
        if active_model is not None:
            # Use Random Forest model
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            ml_prediction = int(active_model.predict(features_scaled)[0])
            proba = active_model.predict_proba(features_scaled)[0]
            ml_phishing_prob = float(proba[1])  # Probability of phishing
            
            # Combine ML and heuristics (weighted average)
            # Calculate combined phishing score
            combined_phishing_score = ml_phishing_prob * 0.6 + heuristic_score * 0.4
            
            # Decision with clear threshold
            if combined_phishing_score >= 0.5:
                # Phishing detected
                prediction = 1
                confidence = combined_phishing_score
            else:
                # Legitimate (but confidence should reflect certainty)
                prediction = 0
                # Confidence for legitimate = 1 - phishing_score
                confidence = 1.0 - combined_phishing_score
            
            # Override logic for very strong heuristic signals
            if heuristic_score > 0.7:
                # Strong phishing indicators
                prediction = 1
                confidence = max(confidence, heuristic_score)
            elif heuristic_score < 0.1 and ml_phishing_prob < 0.3:
                # Very clearly legitimate
                prediction = 0
                confidence = max(confidence, 0.8)
        else:
            # Heuristic scoring only (fallback)
            prediction = 1 if heuristic_score > 0.5 else 0
            confidence = float(heuristic_score)
        
        return {
            'is_phishing': bool(prediction),
            'confidence': confidence,
            'features': features_dict
        }
    
    def predict_from_features(self, features: np.ndarray, model=None) -> Tuple[int, float]:
        """
        Predict from pre-extracted features (legacy method).
        
        Args:
            features: Feature vector
            model: Trained ML model (if None, uses heuristic scoring)
            
        Returns:
            Tuple of (prediction, confidence_score)
        """
        if model is not None:
            # Use trained ML model
            return model.predict(features.reshape(1, -1))[0], \
                   model.predict_proba(features.reshape(1, -1))[0].max()
        else:
            # Heuristic scoring
            score = self._heuristic_score(features)
            prediction = 1 if score > 0.5 else 0
            return prediction, score
    
    def _heuristic_score(self, features: np.ndarray) -> float:
        """Calculate phishing probability using heuristics."""
        score = 0.0
        
        # Failed authentication (high weight)
        if features[0] == 0:  # SPF fail
            score += 0.20
        if features[1] == 0:  # DKIM fail
            score += 0.15
        if features[2] == 0:  # DMARC fail
            score += 0.15
        
        # URL features (CRITICAL indicators)
        if features[5] == 1:  # Has URL shortener (bit.ly, tinyurl)
            score += 0.30  # Very suspicious
        if features[6] == 1:  # Has IP-based URL
            score += 0.35  # Extremely suspicious
        
        # Multiple URLs
        url_count = features[4]
        if url_count > 5:
            score += 0.15
        elif url_count > 2:
            score += 0.10
        
        # Suspicious keywords
        keyword_count = features[7]
        if keyword_count > 5:
            score += 0.20
        elif keyword_count > 2:
            score += 0.10
        
        # Content features
        urgency = features[8]
        if urgency > 0.6:  # High urgency
            score += 0.20
        elif urgency > 0.3:
            score += 0.10
        
        if features[9] > 0.4:  # Excessive CAPS
            score += 0.10
        if features[10] > 0.2:  # Too many special chars
            score += 0.10
        if features[12] == 1:  # Email form present
            score += 0.25
        
        return min(1.0, score)
    
    def analyze_multilingual_email(self, email_content: str, email_headers: Dict = None) -> Dict:
        """
        Enhanced analysis with LANGUAGE DETECTION and TRANSLATION support.
        
        Args:
            email_content: Body text of the email
            email_headers: Optional email headers (From, Subject, etc.)
            
        Returns:
            Dictionary with detection results + language analysis + translation
        """
        # Ensure email_headers is a dict
        if email_headers is None:
            email_headers = {}
        
        # Step 1: Language analysis
        language_analysis = self.language_detector.analyze_email_language(email_content)
        
        # Step 2: Use translated text if needed for better feature extraction
        content_for_analysis = email_content
        if language_analysis['translation']['translated_text']:
            content_for_analysis = language_analysis['translation']['translated_text']
        
        # Step 3: Extract features from (possibly translated) content
        features = self.extract_features(content_for_analysis, email_headers)
        
        # Step 4: ML prediction
        if self.use_ml_model:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            ml_prediction = self.model.predict(features_scaled)[0]
            ml_proba = self.model.predict_proba(features_scaled)[0]
            ml_phishing_prob = float(ml_proba[1])
        else:
            ml_prediction = None
            ml_phishing_prob = None
        
        # Step 5: Heuristic scoring (with language risk factor)
        heuristic_score = self._heuristic_score(features)
        
        # Apply language risk multiplier
        language_risk = language_analysis['phishing']['risk_factor']
        heuristic_score = min(heuristic_score * language_risk, 1.0)
        
        # Add multilingual phishing keyword score
        if language_analysis['phishing']['keyword_count'] > 0:
            heuristic_score = min(
                heuristic_score + language_analysis['phishing']['score'],
                1.0
            )
        
        # Step 6: Hybrid prediction (ML 60% + Heuristics 40%)
        if self.use_ml_model and ml_phishing_prob is not None:
            combined_score = (ml_phishing_prob * 0.6) + (heuristic_score * 0.4)
            prediction = 1 if combined_score >= 0.5 else 0
            
            if prediction == 1:
                confidence = combined_score
            else:
                confidence = 1.0 - combined_score
            
            # Override for strong signals
            if heuristic_score > 0.7:
                prediction = 1
                confidence = max(confidence, heuristic_score)
            elif heuristic_score < 0.1 and ml_phishing_prob < 0.3:
                prediction = 0
                confidence = max(confidence, 0.8)
        else:
            prediction = 1 if heuristic_score > 0.5 else 0
            confidence = float(heuristic_score)
        
        return {
            'is_phishing': bool(prediction),
            'confidence': confidence,
            'features': features,
            'language': {
                'primary': language_analysis['language']['primary'],
                'confidence': language_analysis['language']['confidence'],
                'is_multilingual': language_analysis['language']['is_multilingual'],
                'all_detected': language_analysis['language']['all_detected']
            },
            'multilingual_phishing': {
                'detected': language_analysis['phishing']['keyword_count'] > 0,
                'keywords': language_analysis['phishing']['keywords_found'],
                'keyword_count': language_analysis['phishing']['keyword_count'],
                'risk_multiplier': language_risk,
                'score': language_analysis['phishing']['score']
            },
            'translation': {
                'needed': language_analysis['translation']['needed'],
                'translated_text': language_analysis['translation']['translated_text']
            }
        }


class EmailHeaderParser:
    """Parses and validates email headers."""
    
    @staticmethod
    def parse_headers(header_string: str) -> Dict:
        """Parse email headers from string."""
        headers = {}
        for line in header_string.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    @staticmethod
    def extract_sender_domain(sender_email: str) -> str:
        """Extract domain from sender email."""
        match = re.search(r'@([a-zA-Z0-9.-]+)', sender_email)
        return match.group(1) if match else ''
    
    @staticmethod
    def validate_sender_domain(sender_domain: str, from_header: str) -> bool:
        """Check if sender domain matches From header."""
        return sender_domain.lower() in from_header.lower()
