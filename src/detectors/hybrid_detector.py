"""
Hybrid Phishing Detection System
Combines fast heuristic screening with Random Forest deep analysis
"""

import numpy as np
from typing import Dict, Optional
import sys

# Handle imports for both development and PyInstaller
try:
    from .email_detector import EmailPhishingDetector
    from .file_analyzer import MalwareAnalyzer
except ImportError:
    from src.detectors.email_detector import EmailPhishingDetector
    from src.detectors.file_analyzer import MalwareAnalyzer


class HybridEmailDetector:
    """
    Hybrid email phishing detector with multi-stage analysis.
    
    Stage 1: Fast heuristic screening (catches obvious cases)
    Stage 2: Random Forest deep analysis (complex patterns)
    Stage 3: Ensemble voting (combines both methods)
    """
    
    def __init__(self, model_dir: str = 'data/models'):
        self.detector = EmailPhishingDetector(model_dir=model_dir)
        self.use_fast_screening = True
        self.ensemble_weights = {'rf': 0.7, 'heuristic': 0.3}
        
        # Statistics
        self.stats = {
            'total_predictions': 0,
            'fast_path_count': 0,
            'ml_path_count': 0,
            'ensemble_count': 0
        }
    
    def predict(self, email_content: str, email_headers: Dict = None) -> Dict:
        """
        Predict if email is phishing using hybrid approach.
        
        Args:
            email_content: Email body text
            email_headers: Optional email headers dict
            
        Returns:
            Dict with prediction results and metadata
        """
        self.stats['total_predictions'] += 1
        
        # Stage 1: Extract features
        features_dict = self.detector._extract_feature_dict(email_content, email_headers)
        features = np.array(list(features_dict.values()), dtype=np.float32)
        
        # Stage 2: Fast screening for obvious cases
        if self.use_fast_screening:
            fast_result = self._fast_screening(features_dict)
            if fast_result is not None:
                self.stats['fast_path_count'] += 1
                fast_result['features'] = features_dict
                fast_result['detection_stage'] = 'fast_screening'
                fast_result['stats'] = self._get_stats()
                return fast_result
        
        # Stage 3: Calculate heuristic score
        heuristic_score = self.detector._heuristic_score(features)
        
        # Stage 4: Random Forest analysis (if model available)
        if self.detector.use_ml_model:
            self.stats['ml_path_count'] += 1
            rf_result = self._random_forest_analysis(features)
            
            # Stage 5: Ensemble voting
            self.stats['ensemble_count'] += 1
            final_result = self._ensemble_decision(heuristic_score, rf_result)
            final_result['detection_stage'] = 'ensemble'
            final_result['rf_confidence'] = rf_result['confidence']
        else:
            # Fallback to heuristic only
            final_result = {
                'is_phishing': heuristic_score > 0.5,
                'confidence': heuristic_score,
                'detection_stage': 'heuristic_only'
            }
        
        # Add metadata
        final_result['features'] = features_dict
        final_result['heuristic_score'] = float(heuristic_score)
        final_result['stats'] = self._get_stats()
        
        return final_result
    
    def _fast_screening(self, features: Dict) -> Optional[Dict]:
        """
        Fast screening for obvious phishing cases.
        Returns result if confidence is very high, None otherwise.
        
        Critical Red Flags:
        1. IP URL + credential form = 95% phishing
        2. Failed all auth + many suspicious keywords = 90% phishing
        3. IP URL + high urgency + form = 92% phishing
        """
        # Red Flag 1: IP URL + credential request
        if features['has_ip_based_urls'] == 1 and features['has_email_form'] == 1:
            return {
                'is_phishing': True,
                'confidence': 0.95,
                'method': 'fast_screening',
                'reason': 'IP-based URL + credential request detected',
                'risk_level': 'CRITICAL'
            }
        
        # Red Flag 2: All authentication failed + suspicious content
        if (features['spf_pass'] == 0 and 
            features['dkim_pass'] == 0 and 
            features['dmarc_pass'] == 0 and
            features['suspicious_keyword_count'] > 5):
            return {
                'is_phishing': True,
                'confidence': 0.90,
                'method': 'fast_screening',
                'reason': 'Failed all authentication + high suspicious keywords',
                'risk_level': 'CRITICAL'
            }
        
        # Red Flag 3: IP URL + high urgency + any form
        if (features['has_ip_based_urls'] == 1 and
            features['urgency_score'] > 0.7 and
            features['has_email_form'] == 1):
            return {
                'is_phishing': True,
                'confidence': 0.92,
                'method': 'fast_screening',
                'reason': 'IP URL + high urgency + form',
                'risk_level': 'CRITICAL'
            }
        
        # Red Flag 4: URL shortener + failed auth + urgency
        if (features['has_shortener_urls'] == 1 and
            features['spf_pass'] == 0 and
            features['urgency_score'] > 0.6):
            return {
                'is_phishing': True,
                'confidence': 0.85,
                'method': 'fast_screening',
                'reason': 'URL shortener + failed SPF + urgency',
                'risk_level': 'HIGH'
            }
        
        # Not obvious enough, needs deeper analysis
        return None
    
    def _random_forest_analysis(self, features: np.ndarray) -> Dict:
        """
        Deep analysis using optimized Random Forest model.
        
        Returns:
            Dict with prediction, confidence, and method
        """
        # Scale features
        features_scaled = self.detector.scaler.transform(features.reshape(1, -1))
        
        # Get prediction
        prediction = self.detector.model.predict(features_scaled)[0]
        proba = self.detector.model.predict_proba(features_scaled)[0]
        
        # Calculate tree consensus (what % of trees vote phishing)
        try:
            tree_predictions = np.array([
                tree.predict(features_scaled)[0] 
                for tree in self.detector.model.estimators_[:20]  # Sample 20 trees
            ])
            consensus = np.mean(tree_predictions)
        except:
            consensus = proba[1]
        
        return {
            'prediction': int(prediction),
            'confidence': float(proba[1]),  # Phishing probability
            'consensus': float(consensus),   # % trees voting phishing
            'method': 'random_forest'
        }
    
    def _ensemble_decision(self, heuristic_score: float, rf_result: Dict) -> Dict:
        """
        Combine heuristic and Random Forest predictions with weighted voting.
        
        Weights:
        - Random Forest: 70% (more accurate, captures complex patterns)
        - Heuristic: 30% (domain knowledge, interpretable rules)
        
        Agreement bonus: +10% if both methods agree
        """
        rf_conf = rf_result['confidence']
        
        # Weighted average
        final_confidence = (
            rf_conf * self.ensemble_weights['rf'] + 
            heuristic_score * self.ensemble_weights['heuristic']
        )
        
        # Check agreement
        rf_pred = rf_result['prediction']
        heur_pred = 1 if heuristic_score > 0.5 else 0
        agreement = (rf_pred == heur_pred)
        
        # Agreement bonus (both methods agree = more confident)
        if agreement:
            final_confidence = min(1.0, final_confidence + 0.1)
        
        # Determine risk level
        if final_confidence >= 0.8:
            risk_level = 'CRITICAL'
        elif final_confidence >= 0.6:
            risk_level = 'HIGH'
        elif final_confidence >= 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'is_phishing': final_confidence > 0.5,
            'confidence': float(final_confidence),
            'agreement': agreement,
            'consensus': rf_result.get('consensus', rf_conf),
            'risk_level': risk_level
        }
    
    def _get_stats(self) -> Dict:
        """Get prediction statistics."""
        total = self.stats['total_predictions']
        if total == 0:
            return {
                'fast_path_ratio': 0.0,
                'ml_path_ratio': 0.0,
                'ensemble_ratio': 0.0
            }
        
        return {
            'total_predictions': total,
            'fast_path_count': self.stats['fast_path_count'],
            'fast_path_ratio': self.stats['fast_path_count'] / total,
            'ml_path_count': self.stats['ml_path_count'],
            'ml_path_ratio': self.stats['ml_path_count'] / total,
            'ensemble_count': self.stats['ensemble_count']
        }
    
    def get_feature_importance(self) -> Optional[Dict]:
        """
        Get feature importance from Random Forest model.
        
        Returns:
            Dict mapping feature names to importance scores
        """
        if not self.detector.use_ml_model:
            return None
        
        try:
            importances = self.detector.model.feature_importances_
            feature_names = [
                'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_age',
                'url_count', 'has_shortener_urls', 'has_ip_based_urls',
                'suspicious_keyword_count', 'urgency_score', 'capitalization_ratio',
                'special_char_ratio', 'html_tag_count', 'has_email_form',
                'avg_word_length', 'unique_word_ratio', 'has_urgency_words'
            ]
            
            # Sort by importance
            importance_dict = dict(zip(feature_names, importances))
            sorted_importance = dict(
                sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
            )
            
            return sorted_importance
        except Exception as e:
            print(f"Error getting feature importance: {e}")
            return None


class HybridFileAnalyzer:
    """
    Hybrid file malware analyzer with multi-stage detection.
    Similar architecture to email detector.
    """
    
    def __init__(self, model_dir: str = 'data/models'):
        self.analyzer = MalwareAnalyzer(model_dir=model_dir)
        self.use_fast_screening = True
        self.ensemble_weights = {'rf': 0.7, 'heuristic': 0.3}
        
        self.stats = {
            'total_predictions': 0,
            'fast_path_count': 0,
            'ml_path_count': 0
        }
    
    def analyze(self, file_path: str) -> Dict:
        """
        Analyze file for malware using hybrid approach.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dict with analysis results
        """
        self.stats['total_predictions'] += 1
        
        # Extract features
        features = self.analyzer.analyze_file(file_path)
        
        # Fast screening
        if self.use_fast_screening:
            fast_result = self._fast_screening_file(features)
            if fast_result is not None:
                self.stats['fast_path_count'] += 1
                fast_result['detection_stage'] = 'fast_screening'
                return fast_result
        
        # Calculate heuristic score
        heuristic_score = self.analyzer._heuristic_score(features)
        
        # ML analysis
        if self.analyzer.use_ml_model:
            self.stats['ml_path_count'] += 1
            features_scaled = self.analyzer.scaler.transform(features.reshape(1, -1))
            prediction = self.analyzer.model.predict(features_scaled)[0]
            proba = self.analyzer.model.predict_proba(features_scaled)[0]
            
            rf_conf = float(proba[1])
            final_confidence = (rf_conf * 0.7) + (heuristic_score * 0.3)
            
            # Agreement bonus
            if (prediction == 1) == (heuristic_score > 0.5):
                final_confidence = min(1.0, final_confidence + 0.1)
            
            result = {
                'is_malware': final_confidence > 0.5,
                'confidence': final_confidence,
                'rf_confidence': rf_conf,
                'heuristic_score': float(heuristic_score),
                'detection_stage': 'ensemble'
            }
        else:
            result = {
                'is_malware': heuristic_score > 0.5,
                'confidence': float(heuristic_score),
                'detection_stage': 'heuristic_only'
            }
        
        return result
    
    def _fast_screening_file(self, features: np.ndarray) -> Optional[Dict]:
        """Fast screening for obvious malware."""
        # High entropy + PE header + many suspicious strings
        if features[2] > 7.5 and features[1] == 1 and features[4] > 20:
            return {
                'is_malware': True,
                'confidence': 0.95,
                'reason': 'High entropy + PE header + suspicious strings',
                'risk_level': 'CRITICAL'
            }
        
        return None


# Convenience functions
def detect_phishing_email(email_content: str, email_headers: Dict = None) -> Dict:
    """
    Quick function to detect phishing email.
    
    Usage:
        result = detect_phishing_email(email_text)
        if result['is_phishing']:
            print(f"PHISHING detected! Confidence: {result['confidence']:.1%}")
    """
    detector = HybridEmailDetector()
    return detector.predict(email_content, email_headers)


def analyze_file_malware(file_path: str) -> Dict:
    """
    Quick function to analyze file for malware.
    
    Usage:
        result = analyze_file_malware('suspicious.exe')
        if result['is_malware']:
            print(f"MALWARE detected! Confidence: {result['confidence']:.1%}")
    """
    analyzer = HybridFileAnalyzer()
    return analyzer.analyze(file_path)
