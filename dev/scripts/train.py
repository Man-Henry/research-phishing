"""
Unified Training Script for Phishing Detection Models
Supports: Email (16 features), URL (12 features), Synthetic data generation
"""
import argparse
import glob
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
from src.utils.schema import FEATURE_COLUMNS, normalize_labels, resolve_label_column

# Email feature schema (16 features)
EMAIL_FEATURE_COLUMNS = [
    'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_age',
    'url_count', 'has_shortener_urls', 'has_ip_based_urls',
    'suspicious_keyword_count', 'urgency_score', 'capitalization_ratio',
    'special_char_ratio', 'html_tag_count', 'has_email_form',
    'avg_word_length', 'unique_word_ratio', 'has_urgency_words'
]

# URL feature schema (12 features)
URL_FEATURE_COLUMNS = [
    'url_length', 'domain_length', 'tld_length', 'num_digits',
    'num_special_chars', 'num_subdomains', 'has_ip', 'has_at',
    'has_double_slash', 'has_dash', 'num_dots', 'entropy'
]

# File analysis features (8 features)
FILE_FEATURE_COLUMNS = [
    'file_size', 'has_pe_header', 'entropy', 'null_byte_ratio',
    'suspicious_strings', 'has_zip_header', 'has_executable_code',
    'magic_number_score'
]


# ============================================================================
# SYNTHETIC DATA GENERATION
# ============================================================================

def generate_email_samples(n_samples=2000):
    """Generate synthetic email samples for training"""
    print(f"Generating {n_samples} synthetic email samples...")
    np.random.seed(42)
    
    X, y = [], []
    
    # Phishing emails (50%)
    for _ in range(n_samples // 2):
        features = np.array([
            np.random.choice([0, 1], p=[0.7, 0.3]),  # spf_pass
            np.random.choice([0, 1], p=[0.6, 0.4]),  # dkim_pass
            np.random.choice([0, 1], p=[0.6, 0.4]),  # dmarc_pass
            np.random.randint(0, 3),                  # sender_domain_age
            np.random.randint(2, 10),                 # url_count
            np.random.choice([0, 1], p=[0.4, 0.6]),  # has_shortener_urls
            np.random.choice([0, 1], p=[0.3, 0.7]),  # has_ip_based_urls
            np.random.randint(3, 15),                 # suspicious_keyword_count
            np.random.uniform(0.6, 1.0),              # urgency_score
            np.random.uniform(0.2, 0.5),              # capitalization_ratio
            np.random.uniform(0.1, 0.3),              # special_char_ratio
            np.random.randint(10, 50),                # html_tag_count
            np.random.choice([0, 1], p=[0.3, 0.7]),  # has_email_form
            np.random.uniform(4, 7),                  # avg_word_length
            np.random.uniform(0.3, 0.6),              # unique_word_ratio
            1                                         # has_urgency_words
        ], dtype=np.float32)
        X.append(features)
        y.append(1)
    
    # Legitimate emails (50%)
    for _ in range(n_samples // 2):
        features = np.array([
            np.random.choice([0, 1], p=[0.2, 0.8]),  # spf_pass
            np.random.choice([0, 1], p=[0.2, 0.8]),  # dkim_pass
            np.random.choice([0, 1], p=[0.2, 0.8]),  # dmarc_pass
            np.random.randint(5, 10),                 # sender_domain_age
            np.random.randint(0, 3),                  # url_count
            0, 0,                                     # no shorteners/IP URLs
            np.random.randint(0, 3),                  # suspicious_keyword_count
            np.random.uniform(0.0, 0.3),              # urgency_score
            np.random.uniform(0.0, 0.15),             # capitalization_ratio
            np.random.uniform(0.0, 0.1),              # special_char_ratio
            np.random.randint(0, 20),                 # html_tag_count
            0,                                        # has_email_form
            np.random.uniform(4, 6),                  # avg_word_length
            np.random.uniform(0.6, 0.9),              # unique_word_ratio
            0                                         # has_urgency_words
        ], dtype=np.float32)
        X.append(features)
        y.append(0)
    
    # Shuffle
    indices = np.random.permutation(len(X))
    X = np.array(X)[indices]
    y = np.array(y)[indices]
    
    print(f"✓ Generated {len(X)} email samples")
    print(f"  Phishing: {sum(y)} | Legitimate: {len(y)-sum(y)}")
    return X, y


def generate_file_samples(n_samples=2000):
    """Generate synthetic file samples for training"""
    print(f"\nGenerating {n_samples} synthetic file samples...")
    np.random.seed(42)
    
    X, y = [], []
    
    # Malware (50%)
    for _ in range(n_samples // 2):
        features = np.array([
            np.random.randint(5000, 500000),          # file_size
            np.random.choice([1, 0], p=[0.8, 0.2]),  # has_pe_header
            np.random.uniform(7.0, 8.0),              # entropy
            np.random.uniform(0.0, 0.1),              # null_byte_ratio
            np.random.randint(10, 50),                # suspicious_strings
            np.random.choice([1, 0], p=[0.3, 0.7]),  # has_zip_header
            np.random.choice([1, 0], p=[0.8, 0.2]),  # has_executable_code
            np.random.randint(2, 5)                   # magic_number_score
        ], dtype=np.float32)
        X.append(features)
        y.append(1)
    
    # Benign (50%)
    for _ in range(n_samples // 2):
        features = np.array([
            np.random.randint(100, 10000),            # file_size
            np.random.choice([1, 0], p=[0.2, 0.8]),  # has_pe_header
            np.random.uniform(4.0, 6.0),              # entropy
            np.random.uniform(0.1, 0.3),              # null_byte_ratio
            np.random.randint(0, 5),                  # suspicious_strings
            np.random.choice([1, 0], p=[0.5, 0.5]),  # has_zip_header
            np.random.choice([1, 0], p=[0.1, 0.9]),  # has_executable_code
            np.random.randint(0, 2)                   # magic_number_score
        ], dtype=np.float32)
        X.append(features)
        y.append(0)
    
    # Shuffle
    indices = np.random.permutation(len(X))
    X = np.array(X)[indices]
    y = np.array(y)[indices]
    
    print(f"✓ Generated {len(X)} file samples")
    print(f"  Malware: {sum(y)} | Benign: {len(y)-sum(y)}")
    return X, y


# ============================================================================
# DATA LOADING
# ============================================================================

def load_dataset(path=None, auto_detect=True):
    """Load dataset from CSV with auto-detection"""
    candidates = []
    
    if path:
        candidates.append(path)
    
    if os.environ.get("TRAIN_DATA_PATH"):
        candidates.append(os.environ["TRAIN_DATA_PATH"])
    
    if auto_detect:
        candidates += [
            "data/training_samples/spam_features.csv",
            "data/training_samples/email_combined_dataset.csv",
            "dataset_full.csv",
            "url_features.csv"
        ]
        
        for f in glob.glob("*.csv"):
            if "phish" in f.lower() or "spam" in f.lower():
                candidates.insert(0, f)
    
    for p in candidates:
        if p and os.path.exists(p):
            df = pd.read_csv(p)
            print(f"✓ Loaded: {p}")
            print(f"  Shape: {df.shape}")
            return df, p
    
    raise FileNotFoundError(
        "No dataset found. Use --data <path> or set TRAIN_DATA_PATH"
    )


def detect_dataset_type(df):
    """Detect if dataset is email, URL, or file-based"""
    cols = set(df.columns)
    
    email_match = len(cols & set(EMAIL_FEATURE_COLUMNS))
    url_match = len(cols & set(URL_FEATURE_COLUMNS))
    file_match = len(cols & set(FILE_FEATURE_COLUMNS))
    
    if email_match >= 8:
        return 'email', EMAIL_FEATURE_COLUMNS
    elif url_match >= 6:
        return 'url', URL_FEATURE_COLUMNS
    elif file_match >= 4:
        return 'file', FILE_FEATURE_COLUMNS
    else:
        return 'unknown', []


# ============================================================================
# DATA PREPARATION
# ============================================================================

def prepare_data(df, feature_columns=None):
    """Prepare X, y from DataFrame"""
    
    # Find label column
    if 'label' in df.columns:
        label_col = 'label'
    elif 'Label' in df.columns:
        label_col = 'Label'
    else:
        label_col = resolve_label_column(df)
    
    print(f"  Label column: '{label_col}'")
    
    # Extract labels
    y = df[label_col].values
    
    # Convert string labels to binary
    if not np.issubdtype(y.dtype, np.number):
        mapping = {
            'spam': 1, 'phishing': 1, 'malicious': 1, 'bad': 1,
            'ham': 0, 'legitimate': 0, 'benign': 0, 'good': 0
        }
        y = pd.Series(y).map(lambda x: mapping.get(str(x).lower(), x)).values
    
    y = y.astype(int)
    
    # Label distribution
    unique, counts = np.unique(y, return_counts=True)
    print(f"  Label distribution:")
    for val, count in zip(unique, counts):
        label_name = "Threat" if val == 1 else "Safe"
        print(f"    {label_name}: {count} ({count/len(y)*100:.1f}%)")
    
    # Extract features
    if feature_columns:
        present = [f for f in feature_columns if f in df.columns]
        missing = [f for f in feature_columns if f not in df.columns]
        
        if missing:
            print(f"  ⚠ Missing {len(missing)} features: {', '.join(missing[:5])}...")
        
        if not present:
            raise ValueError("No matching features found!")
        
        print(f"  ✓ Using {len(present)} features")
        X = df[present].copy()
    else:
        # Use all numeric columns except label
        X = df.drop(columns=[label_col]).select_dtypes(include=[np.number])
        present = X.columns.tolist()
        print(f"  ✓ Using all {len(present)} numeric features")
    
    # Convert to numeric
    X = X.apply(pd.to_numeric, errors='coerce')
    
    # Handle NaN
    if X.isnull().any().any():
        imputer = SimpleImputer(strategy='mean')
        X = pd.DataFrame(imputer.fit_transform(X), columns=X.columns)
        print(f"  ✓ Imputed missing values")
    
    return X, y, present


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_model(X, y, features, use_scaler=True):
    """Train Random Forest classifier"""
    
    print("\n" + "=" * 70)
    print("  TRAINING RANDOM FOREST MODEL")
    print("=" * 70)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"\nDataset split:")
    print(f"  Training: {len(X_train)} samples")
    print(f"  Testing: {len(X_test)} samples")
    
    # Standardize features (optional)
    scaler = None
    if use_scaler:
        print("\nStandardizing features...")
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)
    
    # Train model
    print("\nTraining Random Forest...")
    print("  • Trees: 200")
    print("  • Max depth: 20")
    print("  • Min samples split: 5")
    
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    clf.fit(X_train, y_train)
    print("✓ Training complete")
    
    # Evaluate
    print("\n" + "=" * 70)
    print("  MODEL EVALUATION")
    print("=" * 70)
    
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    
    # Classification report
    print("\nClassification Report:")
    target_names = ['Safe', 'Threat']
    print(classification_report(y_test, y_pred, 
                                target_names=target_names,
                                digits=4))
    
    # Confusion matrix
    print("Confusion Matrix:")
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


# ============================================================================
# MODEL SAVING
# ============================================================================

def save_model(clf, scaler, features, output_path, model_type='generic'):
    """Save trained model with metadata"""
    
    print("\n" + "=" * 70)
    print("  SAVING MODEL")
    print("=" * 70)
    
    # Create model package
    model_data = {
        'model': clf,
        'scaler': scaler,
        'features': features,
        'model_type': model_type,
        'n_features': len(features)
    }
    
    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model_data, output_path)
    
    print(f"\n✓ Model saved to: {output_path}")
    print(f"  Model type: {model_type}")
    print(f"  Features: {len(features)}")
    print(f"  Trees: {clf.n_estimators}")
    
    # File size
    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"  File size: {size_mb:.2f} MB")


# ============================================================================
# MAIN WORKFLOW
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Unified Training Script for Phishing Detection Models',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train with real data
  python train.py -d data/training_samples/spam_features.csv
  
  # Generate synthetic email data and train
  python train.py --synthetic email -o models/email_model.pkl
  
  # Generate synthetic file data and train
  python train.py --synthetic file -o models/file_model.pkl
  
  # Auto-detect dataset type
  python train.py -d dataset.csv --auto-detect
        """
    )
    
    parser.add_argument(
        '-d', '--data',
        help='Path to training dataset CSV'
    )
    parser.add_argument(
        '-o', '--output',
        default='data/models/trained_model.pkl',
        help='Output model path (default: data/models/trained_model.pkl)'
    )
    parser.add_argument(
        '--synthetic',
        choices=['email', 'file'],
        help='Generate synthetic data (email or file)'
    )
    parser.add_argument(
        '--type',
        choices=['email', 'url', 'file'],
        help='Force dataset type (overrides auto-detection)'
    )
    parser.add_argument(
        '--no-scaler',
        action='store_true',
        help='Disable feature standardization'
    )
    parser.add_argument(
        '--samples',
        type=int,
        default=2000,
        help='Number of synthetic samples (default: 2000)'
    )
    
    args = parser.parse_args()
    
    try:
        print("=" * 70)
        print("  UNIFIED MODEL TRAINER")
        print("=" * 70)
        
        # Step 1: Get data
        if args.synthetic:
            print(f"\n[1/4] Generating synthetic {args.synthetic} data...")
            if args.synthetic == 'email':
                X, y = generate_email_samples(args.samples)
                features = EMAIL_FEATURE_COLUMNS
                model_type = 'email'
            else:
                X, y = generate_file_samples(args.samples)
                features = FILE_FEATURE_COLUMNS
                model_type = 'file'
            
            X = pd.DataFrame(X, columns=features)
            y = pd.Series(y, name='label')
            
        else:
            print("\n[1/4] Loading dataset...")
            df, data_path = load_dataset(args.data)
            
            # Detect type
            if args.type:
                print(f"  Forced type: {args.type}")
                if args.type == 'email':
                    model_type, feature_cols = 'email', EMAIL_FEATURE_COLUMNS
                elif args.type == 'url':
                    model_type, feature_cols = 'url', URL_FEATURE_COLUMNS
                else:
                    model_type, feature_cols = 'file', FILE_FEATURE_COLUMNS
            else:
                model_type, feature_cols = detect_dataset_type(df)
                print(f"  Detected type: {model_type}")
            
            # Prepare data
            print("\n[2/4] Preparing data...")
            X, y, features = prepare_data(df, feature_cols)
        
        # Step 2: Train
        print("\n[3/4] Training model...")
        clf, scaler = train_model(X, y, features, use_scaler=not args.no_scaler)
        
        # Step 3: Save
        print("\n[4/4] Saving model...")
        save_model(clf, scaler, features, args.output, model_type)
        
        # Done
        print("\n" + "=" * 70)
        print("  ✅ TRAINING COMPLETE!")
        print("=" * 70)
        print("\nNext steps:")
        print("  1. Test model with real data")
        print("  2. Deploy to production app")
        print("  3. Monitor performance metrics")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
