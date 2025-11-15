"""
Train Email Phishing Detection Model
Train model with email-specific features (16 features)
"""
import argparse
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (average_precision_score, classification_report,
                              confusion_matrix, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Email feature schema (16 features)
EMAIL_FEATURE_COLUMNS = [
    'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_age',
    'url_count', 'has_shortener_urls', 'has_ip_based_urls',
    'suspicious_keyword_count', 'urgency_score', 'capitalization_ratio',
    'special_char_ratio', 'html_tag_count', 'has_email_form',
    'avg_word_length', 'unique_word_ratio', 'has_urgency_words'
]


def load_email_dataset(path):
    """Load email dataset from CSV"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    df = pd.read_csv(path)
    print(f"✓ Loaded {path}")
    print(f"  Shape: {df.shape}")
    return df


def prepare_email_data(df):
    """Prepare X, y for email model training"""
    
    # Find label column
    if 'label' in df.columns:
        label_col = 'label'
    elif 'Label' in df.columns:
        label_col = 'Label'
    else:
        label_col = df.columns[-1]
    
    print(f"  Label column: '{label_col}'")
    
    # Extract labels
    y = df[label_col].values
    
    # Convert string labels to binary
    if not np.issubdtype(y.dtype, np.number):
        mapping = {'spam': 1, 'phishing': 1, 'ham': 0, 'legitimate': 0}
        y = pd.Series(y).map(lambda x: mapping.get(str(x).lower(), x)).values
    
    print(f"  Label distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for val, count in zip(unique, counts):
        label_name = "Phishing/Spam" if val == 1 else "Legitimate/Ham"
        print(f"    {label_name}: {count} ({count/len(y)*100:.1f}%)")
    
    # Extract features
    present_features = [f for f in EMAIL_FEATURE_COLUMNS if f in df.columns]
    missing_features = [f for f in EMAIL_FEATURE_COLUMNS if f not in df.columns]
    
    if missing_features:
        print(f"  ⚠ Missing features: {missing_features}")
    
    if not present_features:
        raise ValueError("No email features found in dataset!")
    
    print(f"  ✓ Using {len(present_features)} features")
    
    X = df[present_features].copy()
    
    # Convert to numeric
    X = X.apply(pd.to_numeric, errors='coerce')
    
    # Handle NaN
    imputer = SimpleImputer(strategy='mean')
    X = pd.DataFrame(imputer.fit_transform(X), columns=present_features)
    
    return X, y, present_features


def train_email_model(X, y, features):
    """Train Random Forest classifier for email phishing"""
    
    print("\n" + "=" * 70)
    print("  TRAINING EMAIL PHISHING MODEL")
    print("=" * 70)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"\nDataset split:")
    print(f"  Training: {len(X_train)} samples")
    print(f"  Testing: {len(X_test)} samples")
    
    # Standardize features
    print("\nStandardizing features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    print("\nTraining Random Forest (200 trees)...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    clf.fit(X_train_scaled, y_train)
    print("✓ Training complete")
    
    # Evaluate
    print("\n" + "=" * 70)
    print("  MODEL EVALUATION")
    print("=" * 70)
    
    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)[:, 1]
    
    # Metrics
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, 
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  True Negatives:  {cm[0][0]:>5}")
    print(f"  False Positives: {cm[0][1]:>5}")
    print(f"  False Negatives: {cm[1][0]:>5}")
    print(f"  True Positives:  {cm[1][1]:>5}")
    
    # ROC AUC
    if len(np.unique(y_test)) > 1:
        auc = roc_auc_score(y_test, y_proba)
        ap = average_precision_score(y_test, y_proba)
        print(f"\nROC AUC Score: {auc:.4f}")
        print(f"Average Precision: {ap:.4f}")
    
    # Feature importance
    print("\nTop 10 Important Features:")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for i, idx in enumerate(indices, 1):
        feat_name = features[idx]
        print(f"  {i:2}. {feat_name:25} {importances[idx]:.4f}")
    
    return clf, scaler


def save_email_model(clf, scaler, features, output_path):
    """Save trained model and metadata"""
    
    print("\n" + "=" * 70)
    print("  SAVING MODEL")
    print("=" * 70)
    
    # Create model package
    model_data = {
        'model': clf,
        'scaler': scaler,
        'features': features,
        'model_type': 'email_phishing',
        'n_features': len(features)
    }
    
    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model_data, output_path)
    
    print(f"\n✓ Model saved to: {output_path}")
    print(f"  Features: {len(features)}")
    print(f"  Model type: Random Forest")
    print(f"  Trees: {clf.n_estimators}")
    
    # File size
    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"  File size: {size_mb:.2f} MB")


def main():
    """Main training workflow"""
    
    parser = argparse.ArgumentParser(
        description='Train Email Phishing Detection Model'
    )
    parser.add_argument(
        '-d', '--data',
        required=True,
        help='Path to email features CSV (spam_features.csv)'
    )
    parser.add_argument(
        '-o', '--output',
        default='data/models/email_phishing_detector.pkl',
        help='Output model path'
    )
    
    args = parser.parse_args()
    
    try:
        print("=" * 70)
        print("  EMAIL PHISHING MODEL TRAINER")
        print("=" * 70)
        
        # Load dataset
        print("\n[1/4] Loading dataset...")
        df = load_email_dataset(args.data)
        
        # Prepare data
        print("\n[2/4] Preparing data...")
        X, y, features = prepare_email_data(df)
        
        # Train model
        print("\n[3/4] Training model...")
        clf, scaler = train_email_model(X, y, features)
        
        # Save model
        print("\n[4/4] Saving model...")
        save_email_model(clf, scaler, features, args.output)
        
        print("\n" + "=" * 70)
        print("  ✅ SUCCESS!")
        print("=" * 70)
        print("\nNext steps:")
        print("  1. Test model with real emails")
        print("  2. Update EmailPhishingDetector to use new model")
        print("  3. Compare accuracy with old model")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
