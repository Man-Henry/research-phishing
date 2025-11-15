"""
Convert Spam Dataset to Feature-based Format
Chuyển đổi spam.csv (text) sang format 16 features cho model
"""
import pandas as pd
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.detectors.email_detector import EmailPhishingDetector

def convert_spam_dataset():
    """
    Đọc spam.csv và trích xuất 16 features cho mỗi email
    """
    print("=" * 70)
    print("  CONVERTING SPAM DATASET TO FEATURES")
    print("=" * 70)
    
    # Load spam.csv
    print("\n[1/4] Loading spam.csv...")
    df = pd.read_csv('data/training_samples/spam.csv', encoding='latin-1')
    print(f"✓ Loaded {len(df)} emails")
    print(f"  - Ham: {(df['v1']=='ham').sum()}")
    print(f"  - Spam: {(df['v1']=='spam').sum()}")
    
    # Initialize detector
    print("\n[2/4] Initializing feature extractor...")
    detector = EmailPhishingDetector()
    print("✓ Detector ready")
    
    # Extract features
    print("\n[3/4] Extracting features (this may take a while)...")
    features_list = []
    labels = []
    
    for idx, row in df.iterrows():
        if idx % 500 == 0:
            print(f"  Processing email {idx}/{len(df)}...")
        
        try:
            # Extract features from email text
            email_text = str(row['v2'])
            features = detector.extract_features(email_text, email_headers=None)
            
            # Add to list
            features_list.append(features)
            
            # Label: spam=1, ham=0
            label = 1 if row['v1'] == 'spam' else 0
            labels.append(label)
            
        except Exception as e:
            print(f"  Warning: Error processing email {idx}: {e}")
            continue
    
    print(f"✓ Extracted features from {len(features_list)} emails")
    
    # Create DataFrame
    print("\n[4/4] Creating feature dataset...")
    
    feature_names = [
        'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_age',
        'url_count', 'has_shortener_urls', 'has_ip_based_urls',
        'suspicious_keyword_count', 'urgency_score', 'capitalization_ratio',
        'special_char_ratio', 'html_tag_count', 'has_email_form',
        'avg_word_length', 'unique_word_ratio', 'has_urgency_words'
    ]
    
    # Convert to DataFrame
    import numpy as np
    features_array = np.array(features_list)
    
    df_features = pd.DataFrame(features_array, columns=feature_names)
    df_features['label'] = labels
    
    # Save
    output_file = 'data/training_samples/spam_features.csv'
    df_features.to_csv(output_file, index=False)
    
    print(f"✓ Saved to: {output_file}")
    print(f"\nDataset shape: {df_features.shape}")
    print(f"Features: {len(feature_names)}")
    print(f"\nLabel distribution:")
    print(df_features['label'].value_counts())
    
    print("\n" + "=" * 70)
    print("  ✅ CONVERSION COMPLETE!")
    print("=" * 70)
    print(f"\nNext steps:")
    print(f"  1. Train model: python dev/scripts/train_model.py --data {output_file}")
    print(f"  2. Or use GUI training tab")
    
    return df_features


if __name__ == "__main__":
    try:
        convert_spam_dataset()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
