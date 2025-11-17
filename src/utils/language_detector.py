"""
Language Detection and Translation Module
Phát hiện ngôn ngữ và dịch nội dung email để nhận dạng lừa đảo đa ngôn ngữ

Supported Languages:
- English
- Vietnamese (Tiếng Việt)
- Chinese (中文)

Features:
- Detect language of email content
- Translate non-English content to English for analysis
- Detect language-specific phishing patterns
- Support multilingual keyword detection
"""

import re
from typing import Dict, Tuple, Optional, List
from collections import Counter


class LanguageDetector:
    """Detect and analyze language patterns in email content"""
    
    def __init__(self):
        # Language-specific character patterns (English, Vietnamese, Chinese only)
        self.language_patterns = {
            'vietnamese': {
                'chars': r'[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]',
                'words': ['không', 'của', 'và', 'có', 'được', 'trong', 'cho', 'này', 'đã', 'với'],
                'phishing_keywords': [
                    'xác nhận tài khoản', 'cập nhật thông tin', 'khẩn cấp',
                    'bảo mật', 'đăng nhập lại', 'tài khoản bị khóa',
                    'xác minh danh tính', 'nhấp vào đây', 'truy cập ngay',
                    'hoạt động bất thường', 'phát hiện đăng nhập lạ',
                    'bảo vệ tài khoản', 'cảnh báo', 'hạn chế quyền truy cập'
                ]
            },
            'english': {
                'chars': r'[a-zA-Z]',
                'words': ['the', 'and', 'is', 'in', 'to', 'of', 'a', 'for', 'you', 'your'],
                'phishing_keywords': [
                    'verify account', 'update information', 'urgent',
                    'confirm identity', 'suspended account', 'unusual activity',
                    'click here', 'act now', 'limited time', 'security alert',
                    'unauthorized access', 'validate credentials', 're-enter password'
                ]
            },
            'chinese': {
                'chars': r'[\u4e00-\u9fff]',
                'words': ['的', '是', '在', '了', '和', '有', '我', '你', '他', '这'],
                'phishing_keywords': [
                    '验证账户', '更新信息', '紧急', '确认身份',
                    '账户被锁', '异常活动', '点击这里', '立即行动',
                    '安全警报', '未经授权的访问'
                ]
            }
        }
        
        # Common phishing URL patterns (language-independent)
        self.url_phishing_patterns = [
            r'login[.-]',
            r'secure[.-]',
            r'account[.-]',
            r'verify[.-]',
            r'update[.-]',
            r'confirm[.-]',
            r'-login\.',
            r'-secure\.',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        ]
    
    def detect_language(self, text: str) -> Tuple[str, float]:
        """
        Detect primary language of text
        
        Args:
            text: Email content to analyze
            
        Returns:
            Tuple of (language_code, confidence_score)
        """
        if not text or len(text.strip()) < 10:
            return 'unknown', 0.0
        
        text_lower = text.lower()
        scores = {}
        
        # Calculate character-based scores
        for lang, patterns in self.language_patterns.items():
            # Count language-specific characters
            char_matches = len(re.findall(patterns['chars'], text))
            char_score = char_matches / max(len(text), 1)
            
            # Count language-specific common words
            word_score = 0
            for word in patterns['words']:
                word_score += text_lower.count(word.lower())
            word_score = word_score / max(len(text.split()), 1)
            
            # Combined score (weighted)
            scores[lang] = (char_score * 0.7) + (word_score * 0.3)
        
        # Get language with highest score
        if scores:
            detected_lang = max(scores, key=scores.get)
            confidence = scores[detected_lang]
            
            # Require minimum confidence
            if confidence > 0.1:
                return detected_lang, min(confidence, 1.0)
        
        return 'unknown', 0.0
    
    def detect_multilingual_phishing(self, text: str) -> Dict:
        """
        Detect phishing patterns across multiple languages
        
        Args:
            text: Email content to analyze
            
        Returns:
            Dictionary with detection results
        """
        # Detect primary language
        primary_lang, confidence = self.detect_language(text)
        
        result = {
            'primary_language': primary_lang,
            'language_confidence': confidence,
            'detected_phishing_keywords': [],
            'phishing_score': 0.0,
            'languages_detected': [],
            'is_multilingual': False
        }
        
        text_lower = text.lower()
        total_keywords = 0
        detected_langs = []
        
        # Check for phishing keywords in all languages
        for lang, patterns in self.language_patterns.items():
            lang_keywords = []
            for keyword in patterns['phishing_keywords']:
                if keyword.lower() in text_lower:
                    lang_keywords.append(keyword)
                    total_keywords += 1
            
            if lang_keywords:
                detected_langs.append(lang)
                result['detected_phishing_keywords'].extend([
                    {'language': lang, 'keyword': kw} for kw in lang_keywords
                ])
        
        result['languages_detected'] = detected_langs
        result['is_multilingual'] = len(detected_langs) > 1
        
        # Calculate phishing score based on keywords found
        if total_keywords > 0:
            result['phishing_score'] = min(total_keywords * 0.15, 1.0)
        
        # Check for suspicious URLs (language-independent)
        url_suspicion = self._check_suspicious_urls(text)
        result['phishing_score'] = min(
            result['phishing_score'] + url_suspicion * 0.2,
            1.0
        )
        
        return result
    
    def _check_suspicious_urls(self, text: str) -> int:
        """Count suspicious URL patterns"""
        count = 0
        for pattern in self.url_phishing_patterns:
            count += len(re.findall(pattern, text, re.IGNORECASE))
        return count
    
    def translate_to_english(self, text: str, source_lang: str) -> str:
        """
        Simple rule-based translation for common phishing phrases
        (Note: For production, integrate with Google Translate API or similar)
        
        Args:
            text: Text to translate
            source_lang: Source language code
            
        Returns:
            Translated text (or original if translation not available)
        """
        if source_lang not in self.language_patterns:
            return text
        
        # Simple keyword translation (for common phishing terms)
        translation_map = {
            'vietnamese': {
                'xác nhận tài khoản': 'verify account',
                'cập nhật thông tin': 'update information',
                'khẩn cấp': 'urgent',
                'bảo mật': 'security',
                'đăng nhập lại': 'login again',
                'tài khoản bị khóa': 'account locked',
                'xác minh danh tính': 'verify identity',
                'nhấp vào đây': 'click here',
                'hoạt động bất thường': 'unusual activity',
                'cảnh báo': 'warning',
            },
            'chinese': {
                '验证账户': 'verify account',
                '更新信息': 'update information',
                '紧急': 'urgent',
                '确认身份': 'confirm identity',
                '账户被锁': 'account locked',
                '异常活动': 'unusual activity',
                '点击这里': 'click here',
            }
        }
        
        if source_lang in translation_map:
            translated = text
            for src_phrase, eng_phrase in translation_map[source_lang].items():
                translated = translated.replace(src_phrase, eng_phrase)
            return translated
        
        return text
    
    def get_language_risk_factor(self, lang: str, is_multilingual: bool) -> float:
        """
        Calculate risk factor based on language characteristics
        
        Args:
            lang: Detected language
            is_multilingual: Whether email contains multiple languages
            
        Returns:
            Risk multiplier (0.0 - 2.0)
        """
        # Multilingual emails are more suspicious
        base_risk = 1.3 if is_multilingual else 1.0
        
        # Vietnamese and Chinese are more targeted by phishing
        high_risk_langs = ['vietnamese', 'chinese']
        if lang in high_risk_langs:
            base_risk *= 1.2
        
        return min(base_risk, 2.0)
    
    def analyze_email_language(self, email_content: str) -> Dict:
        """
        Complete language analysis of email
        
        Args:
            email_content: Full email text
            
        Returns:
            Complete analysis dictionary
        """
        # Detect language
        primary_lang, lang_confidence = self.detect_language(email_content)
        
        # Detect multilingual phishing
        phishing_analysis = self.detect_multilingual_phishing(email_content)
        
        # Calculate risk factor
        risk_factor = self.get_language_risk_factor(
            primary_lang,
            phishing_analysis['is_multilingual']
        )
        
        # Attempt translation if needed
        translated_text = None
        if primary_lang not in ['english', 'unknown']:
            translated_text = self.translate_to_english(email_content, primary_lang)
        
        return {
            'language': {
                'primary': primary_lang,
                'confidence': lang_confidence,
                'is_multilingual': phishing_analysis['is_multilingual'],
                'all_detected': phishing_analysis['languages_detected']
            },
            'phishing': {
                'keywords_found': phishing_analysis['detected_phishing_keywords'],
                'keyword_count': len(phishing_analysis['detected_phishing_keywords']),
                'score': phishing_analysis['phishing_score'],
                'risk_factor': risk_factor
            },
            'translation': {
                'needed': primary_lang not in ['english', 'unknown'],
                'translated_text': translated_text
            }
        }


# Convenience function for quick language detection
def detect_email_language(email_content: str) -> Dict:
    """
    Quick language detection and phishing analysis
    
    Usage:
        result = detect_email_language("Xác nhận tài khoản của bạn...")
        print(result['language']['primary'])  # 'vietnamese'
        print(result['phishing']['score'])     # 0.45
    """
    detector = LanguageDetector()
    return detector.analyze_email_language(email_content)
