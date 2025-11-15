"""
Comprehensive Test Suite for Phishing Detection Suite
Tests all core components: Email Detector, File Analyzer, Models
"""

import unittest
import numpy as np
import os
import tempfile
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.detectors.email_detector import EmailPhishingDetector
from src.detectors.file_analyzer import MalwareAnalyzer
from src.ml.model_trainer import ModelTrainer


class TestEmailDetector(unittest.TestCase):
    """Test cases for email phishing detection"""
    
    @classmethod
    def setUpClass(cls):
        """Set up detector once for all tests"""
        cls.detector = EmailPhishingDetector()
    
    def test_phishing_email_obvious(self):
        """Test detection of obvious phishing email"""
        phishing_email = """
        From: admin@paypa1.com
        Subject: Urgent Account Verification Required!!!
        
        Dear Customer,
        
        Your account has been LOCKED due to suspicious activity!
        Click here IMMEDIATELY to verify your account:
        http://bit.ly/verify-paypal-123
        
        Act now or your account will be permanently suspended!
        This is your FINAL WARNING!
        
        Verify Now: http://192.168.1.1/verify
        """
        
        result = self.detector.predict(phishing_email)
        
        # Assertions
        self.assertTrue(result['is_phishing'], 
                       "Should detect obvious phishing email")
        self.assertGreater(result['confidence'], 0.7,
                          "Confidence should be high for obvious phishing")
        self.assertIn(result['risk_level'], ['High', 'Critical'])
        
        # Check feature detection
        features = result['features']
        self.assertGreater(features['url_count'], 0,
                          "Should detect URLs")
        self.assertGreater(features['suspicious_keyword_count'], 3,
                          "Should detect suspicious keywords")
        self.assertGreater(features['urgency_score'], 0.5,
                          "Should detect urgency language")
    
    def test_legitimate_email(self):
        """Test detection of legitimate email"""
        legit_email = """
        From: newsletter@github.com
        Subject: Your weekly GitHub digest
        
        Hi there,
        
        Here are the trending repositories this week:
        
        1. awesome-python - A curated list of Python frameworks
        2. tensorflow - Machine learning framework
        
        Happy coding!
        GitHub Team
        """
        
        result = self.detector.predict(legit_email)
        
        # Should be classified as legitimate (or low risk if phishing)
        if result['is_phishing']:
            self.assertLess(result['confidence'], 0.5,
                          "Confidence should be low for false positive")
            self.assertIn(result['risk_level'], ['Safe', 'Low'])
        else:
            self.assertEqual(result['risk_level'], 'Safe')
    
    def test_shortener_url_detection(self):
        """Test detection of URL shorteners"""
        email_with_shortener = """
        Click here: http://bit.ly/secret123
        Or here: https://tinyurl.com/xyz
        """
        
        result = self.detector.predict(email_with_shortener)
        features = result['features']
        
        self.assertEqual(features['has_shortener_urls'], 1,
                        "Should detect URL shorteners")
        self.assertGreater(features['url_count'], 0,
                          "Should count URLs")
    
    def test_ip_based_url_detection(self):
        """Test detection of IP-based URLs"""
        email_with_ip = """
        Login here: http://192.168.1.100/login
        Or here: http://10.0.0.1/verify
        """
        
        result = self.detector.predict(email_with_ip)
        features = result['features']
        
        self.assertEqual(features['has_ip_based_urls'], 1,
                        "Should detect IP-based URLs")
    
    def test_suspicious_keywords(self):
        """Test suspicious keyword detection"""
        keywords = ['verify', 'confirm', 'urgent', 'act now', 
                   'suspended', 'locked', 'unauthorized']
        
        for keyword in keywords:
            email = f"Your account requires {keyword} action."
            result = self.detector.predict(email)
            features = result['features']
            
            self.assertGreater(features['suspicious_keyword_count'], 0,
                             f"Should detect keyword: {keyword}")
    
    def test_feature_extraction(self):
        """Test feature extraction returns correct shape"""
        email = "Test email content"
        features_dict = self.detector._extract_feature_dict(email)
        
        # Should have exactly 16 features
        self.assertEqual(len(features_dict), 16,
                        "Should extract 16 features")
        
        # All features should be numeric
        for key, value in features_dict.items():
            self.assertIsInstance(value, (int, float),
                                f"Feature {key} should be numeric")
    
    def test_empty_email(self):
        """Test handling of empty email"""
        result = self.detector.predict("")
        
        # Should not crash
        self.assertIsInstance(result, dict)
        self.assertIn('is_phishing', result)
        self.assertIn('confidence', result)
    
    def test_long_email(self):
        """Test handling of very long email"""
        long_email = "Test " * 10000  # 50,000 characters
        
        result = self.detector.predict(long_email)
        
        # Should handle without error
        self.assertIsInstance(result, dict)
        features = result['features']
        self.assertGreater(features['text_length'], 10000)


class TestFileAnalyzer(unittest.TestCase):
    """Test cases for file malware analysis"""
    
    @classmethod
    def setUpClass(cls):
        """Set up analyzer once for all tests"""
        cls.analyzer = MalwareAnalyzer()
        cls.temp_dir = tempfile.mkdtemp()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(cls.temp_dir)
    
    def create_test_file(self, filename: str, content: bytes) -> str:
        """Helper to create test file"""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        return filepath
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation"""
        # Low entropy: repetitive data
        low_entropy_data = b'AAAA' * 100
        low_entropy = self.analyzer._calculate_entropy(low_entropy_data)
        self.assertLess(low_entropy, 1.0,
                       "Repetitive data should have low entropy")
        
        # High entropy: random data
        high_entropy_data = os.urandom(400)
        high_entropy = self.analyzer._calculate_entropy(high_entropy_data)
        self.assertGreater(high_entropy, 7.0,
                          "Random data should have high entropy")
    
    def test_pe_header_detection(self):
        """Test Windows PE header detection"""
        # Create file with PE header
        pe_content = b'MZ\x90\x00' + b'\x00' * 56 + b'\x40\x00\x00\x00'
        pe_content += b'\x00' * (0x40 - len(pe_content)) + b'PE\x00\x00'
        
        filepath = self.create_test_file('test.exe', pe_content)
        features = self.analyzer.analyze_file(filepath)
        
        # Feature index 3 is has_pe_header
        self.assertEqual(features[3], 1,
                        "Should detect PE header")
    
    def test_elf_header_detection(self):
        """Test Linux ELF header detection"""
        # Create file with ELF header
        elf_content = b'\x7fELF' + b'\x00' * 100
        
        filepath = self.create_test_file('test.elf', elf_content)
        features = self.analyzer.analyze_file(filepath)
        
        # Feature index 4 is has_elf_header
        self.assertEqual(features[4], 1,
                        "Should detect ELF header")
    
    def test_zip_header_detection(self):
        """Test ZIP archive header detection"""
        # Create file with ZIP header
        zip_content = b'PK\x03\x04' + b'\x00' * 100
        
        filepath = self.create_test_file('test.zip', zip_content)
        features = self.analyzer.analyze_file(filepath)
        
        # Feature index 7 is has_zip_header
        self.assertEqual(features[7], 1,
                        "Should detect ZIP header")
    
    def test_suspicious_strings_detection(self):
        """Test detection of suspicious API calls"""
        suspicious_apis = [
            b'CreateRemoteThread',
            b'WriteProcessMemory',
            b'SetWindowsHookEx'
        ]
        
        content = b'\x00'.join(suspicious_apis) + b'\x00' * 100
        filepath = self.create_test_file('suspicious.bin', content)
        features = self.analyzer.analyze_file(filepath)
        
        # Feature index 6 is suspicious_strings_count
        self.assertGreater(features[6], 0,
                          "Should detect suspicious strings")
    
    def test_feature_extraction_shape(self):
        """Test feature extraction returns correct shape"""
        filepath = self.create_test_file('test.bin', b'\x00' * 1000)
        features = self.analyzer.analyze_file(filepath)
        
        # Should have exactly 11 features
        self.assertEqual(len(features), 11,
                        "Should extract 11 features")
        
        # All features should be numeric
        self.assertTrue(all(isinstance(f, (int, float, np.number)) 
                           for f in features),
                       "All features should be numeric")
    
    def test_file_hash_generation(self):
        """Test file hash generation"""
        content = b'Test content for hashing'
        filepath = self.create_test_file('hashtest.txt', content)
        
        hashes = self.analyzer.get_file_hash(filepath)
        
        # Should have MD5, SHA1, SHA256
        self.assertIn('md5', hashes)
        self.assertIn('sha1', hashes)
        self.assertIn('sha256', hashes)
        
        # Verify MD5 length (32 hex chars)
        self.assertEqual(len(hashes['md5']), 32)
        # Verify SHA1 length (40 hex chars)
        self.assertEqual(len(hashes['sha1']), 40)
        # Verify SHA256 length (64 hex chars)
        self.assertEqual(len(hashes['sha256']), 64)
    
    def test_nonexistent_file(self):
        """Test handling of non-existent file"""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.analyze_file('nonexistent.file')
    
    def test_empty_file(self):
        """Test handling of empty file"""
        filepath = self.create_test_file('empty.txt', b'')
        features = self.analyzer.analyze_file(filepath)
        
        # Should handle gracefully
        self.assertEqual(features[0], 0,  # file_size should be 0
                        "Empty file should have size 0")


class TestModelTrainer(unittest.TestCase):
    """Test cases for model training pipeline"""
    
    def test_data_split(self):
        """Test train/validation split"""
        # Create dummy data
        X = np.random.rand(100, 16)
        y = np.random.randint(0, 2, 100)
        
        from sklearn.model_selection import train_test_split
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Check split ratio
        self.assertEqual(len(X_train), 80)
        self.assertEqual(len(X_val), 20)
        self.assertEqual(len(y_train), 80)
        self.assertEqual(len(y_val), 20)
    
    def test_feature_scaling(self):
        """Test StandardScaler normalization"""
        from sklearn.preprocessing import StandardScaler
        
        # Create data with different scales
        X = np.array([[1, 1000], [2, 2000], [3, 3000]])
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Mean should be ~0, std should be ~1
        self.assertAlmostEqual(X_scaled.mean(), 0, places=1)
        self.assertAlmostEqual(X_scaled.std(), 1, places=1)
    
    def test_model_initialization(self):
        """Test Random Forest initialization"""
        from sklearn.ensemble import RandomForestClassifier
        
        model = RandomForestClassifier(
            n_estimators=10,
            random_state=42
        )
        
        # Should initialize without error
        self.assertEqual(model.n_estimators, 10)
        self.assertEqual(model.random_state, 42)


class TestIntegration(unittest.TestCase):
    """Integration tests for end-to-end workflows"""
    
    def test_email_analysis_workflow(self):
        """Test complete email analysis workflow"""
        detector = EmailPhishingDetector()
        
        # Analyze email
        email = "Urgent: Verify your account at http://bit.ly/verify"
        result = detector.predict(email)
        
        # Check result structure
        self.assertIn('is_phishing', result)
        self.assertIn('confidence', result)
        self.assertIn('features', result)
        self.assertIn('risk_level', result)
        
        # Check value types
        self.assertIsInstance(result['is_phishing'], bool)
        self.assertIsInstance(result['confidence'], float)
        self.assertIsInstance(result['features'], dict)
        self.assertIsInstance(result['risk_level'], str)
        
        # Check value ranges
        self.assertGreaterEqual(result['confidence'], 0.0)
        self.assertLessEqual(result['confidence'], 1.0)
    
    def test_file_analysis_workflow(self):
        """Test complete file analysis workflow"""
        analyzer = MalwareAnalyzer()
        
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'MZ\x90\x00' * 100)
            temp_path = f.name
        
        try:
            # Analyze file
            features = analyzer.analyze_file(temp_path)
            
            # Check features
            self.assertEqual(len(features), 11)
            self.assertTrue(all(isinstance(f, (int, float, np.number)) 
                               for f in features))
            
            # Classify
            prediction = analyzer.classify(features)
            
            # Check prediction structure
            self.assertIn('is_malware', prediction)
            self.assertIn('confidence', prediction)
            
        finally:
            os.unlink(temp_path)


def run_tests():
    """Run all tests with detailed output"""
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEmailDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestFileAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestModelTrainer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
