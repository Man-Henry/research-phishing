"""
Model Training Pipeline

Trains and evaluates machine learning models for:
- Email phishing detection
- File malware classification
"""

import numpy as np
from typing import Tuple
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, roc_auc_score, confusion_matrix, 
                             classification_report, roc_curve)
import joblib
from pathlib import Path


class ModelTrainer:
    """Trains and evaluates ML models for security threat detection."""
    
    def __init__(self, model_dir: str = 'models'):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        
        self.email_model = None
        self.file_model = None
        self.email_scaler = None
        self.file_scaler = None
        self.metrics = {}
    
    def train_email_model(self, X_train: np.ndarray, y_train: np.ndarray, 
                         model_type: str = 'random_forest') -> dict:
        """
        Train email phishing detection model.
        
        Args:
            X_train: Training features
            y_train: Training labels (0=benign, 1=phishing)
            model_type: 'random_forest', 'gradient_boosting', or 'neural_network'
            
        Returns:
            Dictionary of metrics
        """
        print("Training email phishing detection model...")
        
        # Scale features
        self.email_scaler = StandardScaler()
        X_train_scaled = self.email_scaler.fit_transform(X_train)
        
        # Split data
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_scaled, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        # Train model with optimized hyperparameters
        if model_type == 'random_forest':
            self.email_model = RandomForestClassifier(
                n_estimators=200,           # Tăng số cây (100 → 200) để cải thiện accuracy
                max_depth=15,               # Tăng độ sâu (10 → 15) cho phép học phức tạp hơn
                min_samples_split=4,        # Giảm (5 → 4) để tạo thêm split points
                min_samples_leaf=2,         # Giữ nguyên để tránh overfitting
                max_features='sqrt',        # Tối ưu: sqrt(n_features) cho mỗi split
                bootstrap=True,             # Bootstrap sampling
                oob_score=True,             # Out-of-bag score để đánh giá
                random_state=42,
                n_jobs=-1,                  # Dùng tất cả CPU cores
                class_weight='balanced',    # Cân bằng classes cho dữ liệu không đồng đều
                verbose=0                   # Tắt output chi tiết
            )
        elif model_type == 'gradient_boosting':
            self.email_model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        self.email_model.fit(X_train_split, y_train_split)
        
        # Evaluate
        metrics = self._evaluate_model(self.email_model, X_val, y_val, 'Email Detection')
        
        # Cross-validation
        cv_scores = cross_val_score(self.email_model, X_train_scaled, y_train, 
                                    cv=5, scoring='f1')
        print(f"Cross-validation F1 scores: {cv_scores}")
        print(f"Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # Save model
        self._save_model(self.email_model, 'email_phishing_detector.pkl')
        self._save_model(self.email_scaler, 'email_scaler.pkl')
        
        return metrics
    
    def train_file_model(self, X_train: np.ndarray, y_train: np.ndarray,
                        model_type: str = 'random_forest') -> dict:
        """
        Train malware file classification model.
        
        Args:
            X_train: Training features
            y_train: Training labels (0=benign, 1=malicious)
            model_type: 'random_forest' or 'gradient_boosting'
            
        Returns:
            Dictionary of metrics
        """
        print("Training malware file classification model...")
        
        # Scale features
        self.file_scaler = StandardScaler()
        X_train_scaled = self.file_scaler.fit_transform(X_train)
        
        # Split data
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_scaled, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        # Train model with optimized hyperparameters
        if model_type == 'random_forest':
            self.file_model = RandomForestClassifier(
                n_estimators=200,           # Tăng số cây để cải thiện độ chính xác
                max_depth=15,               # Tăng độ sâu cho file analysis phức tạp hơn
                min_samples_split=4,        # Tối ưu splitting
                min_samples_leaf=2,         
                max_features='sqrt',        # Tối ưu feature selection
                bootstrap=True,
                oob_score=True,             # Out-of-bag validation
                random_state=42,
                n_jobs=-1,                  # Parallel processing
                class_weight='balanced',    # Handle imbalanced data
                verbose=0
            )
        elif model_type == 'gradient_boosting':
            self.file_model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        self.file_model.fit(X_train_split, y_train_split)
        
        # Evaluate
        metrics = self._evaluate_model(self.file_model, X_val, y_val, 'Malware Detection')
        
        # Cross-validation
        cv_scores = cross_val_score(self.file_model, X_train_scaled, y_train,
                                    cv=5, scoring='f1')
        print(f"Cross-validation F1 scores: {cv_scores}")
        print(f"Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # Save model
        self._save_model(self.file_model, 'malware_classifier.pkl')
        self._save_model(self.file_scaler, 'file_scaler.pkl')
        
        return metrics
    
    def _evaluate_model(self, model, X_test: np.ndarray, y_test: np.ndarray, 
                       model_name: str) -> dict:
        """Evaluate model performance."""
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
        }
        
        print(f"\n{model_name} Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1']:.4f}")
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print(f"\nConfusion Matrix:")
        print(f"  True Negatives:  {cm[0, 0]}")
        print(f"  False Positives: {cm[0, 1]}")
        print(f"  False Negatives: {cm[1, 0]}")
        print(f"  True Positives:  {cm[1, 1]}")
        
        # Classification report
        print(f"\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Malicious/Phishing']))
        
        return metrics
    
    def load_email_model(self, model_path: str = None):
        """Load trained email detection model."""
        if model_path is None:
            model_path = self.model_dir / 'email_phishing_detector.pkl'
        
        self.email_model = joblib.load(model_path)
        self.email_scaler = joblib.load(self.model_dir / 'email_scaler.pkl')
        print(f"Loaded email model from {model_path}")
    
    def load_file_model(self, model_path: str = None):
        """Load trained malware detection model."""
        if model_path is None:
            model_path = self.model_dir / 'malware_classifier.pkl'
        
        self.file_model = joblib.load(model_path)
        self.file_scaler = joblib.load(self.model_dir / 'file_scaler.pkl')
        print(f"Loaded file model from {model_path}")
    
    def _save_model(self, model, filename: str):
        """Save model to disk."""
        model_path = self.model_dir / filename
        joblib.dump(model, model_path)
        print(f"Saved model to {model_path}")
    
    def get_feature_importance(self, model_type: str = 'email') -> np.ndarray:
        """Get feature importance scores from trained model."""
        if model_type == 'email' and self.email_model:
            return self.email_model.feature_importances_
        elif model_type == 'file' and self.file_model:
            return self.file_model.feature_importances_
        else:
            return None


class DatasetLoader:
    """Utility for loading and preparing datasets."""
    
    @staticmethod
    def load_email_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load email dataset from CSV.
        
        Expected format:
        content, subject, sender, is_phishing
        """
        try:
            import pandas as pd
            df = pd.read_csv(csv_path)
            X = df[['content', 'subject', 'sender']].values
            y = df['is_phishing'].values
            return X, y
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return None, None
    
    @staticmethod
    def load_file_dataset(data_dir: str) -> Tuple[list, np.ndarray]:
        """
        Load file dataset from directory.
        
        Directory structure:
        data_dir/
          ├── benign/
          │   ├── file1
          │   ├── file2
          │   └── ...
          └── malicious/
              ├── file1
              ├── file2
              └── ...
        """
        files = []
        labels = []
        
        benign_dir = Path(data_dir) / 'benign'
        malicious_dir = Path(data_dir) / 'malicious'
        
        # Load benign files
        if benign_dir.exists():
            for file_path in benign_dir.iterdir():
                if file_path.is_file():
                    files.append(str(file_path))
                    labels.append(0)
        
        # Load malicious files
        if malicious_dir.exists():
            for file_path in malicious_dir.iterdir():
                if file_path.is_file():
                    files.append(str(file_path))
                    labels.append(1)
        
        return files, np.array(labels)
