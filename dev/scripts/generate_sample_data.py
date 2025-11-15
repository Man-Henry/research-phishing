"""
Generate Sample Training Data
Tạo dữ liệu mẫu để test chức năng training trong app
"""
import numpy as np
import pandas as pd
from pathlib import Path
import sys

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def generate_email_training_data(output_dir='data/training_samples', n_samples=1000):
    """
    Generate sample email training data in CSV format
    
    Args:
        output_dir: Output directory for training files
        n_samples: Number of samples per file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating email training data...")
    print(f"Output directory: {output_dir}")
    
    np.random.seed(42)
    
    # Feature names (17 features for email detection)
    feature_names = [
        'spf_pass', 'dkim_pass', 'dmarc_pass', 'sender_domain_age',
        'url_count', 'has_shortener_urls', 'has_ip_based_urls',
        'suspicious_keyword_count', 'urgency_score', 'capitalization_ratio',
        'special_char_ratio', 'html_tag_count', 'has_email_form',
        'avg_word_length', 'unique_word_ratio', 'has_urgency_words', 'additional_feature'
    ]
    
    # Generate phishing emails
    print(f"\nGenerating {n_samples} phishing email samples...")
    phishing_data = []
    for _ in range(n_samples):
        features = {
            'spf_pass': np.random.choice([0, 1], p=[0.7, 0.3]),  # 70% fail
            'dkim_pass': np.random.choice([0, 1], p=[0.6, 0.4]),
            'dmarc_pass': np.random.choice([0, 1], p=[0.6, 0.4]),
            'sender_domain_age': np.random.randint(0, 3),  # Young domains
            'url_count': np.random.randint(2, 10),  # Many URLs
            'has_shortener_urls': np.random.choice([0, 1], p=[0.4, 0.6]),  # 60% yes
            'has_ip_based_urls': np.random.choice([0, 1], p=[0.3, 0.7]),  # 70% yes
            'suspicious_keyword_count': np.random.randint(3, 15),
            'urgency_score': np.random.uniform(0.6, 1.0),  # High urgency
            'capitalization_ratio': np.random.uniform(0.2, 0.5),  # Many caps
            'special_char_ratio': np.random.uniform(0.1, 0.3),
            'html_tag_count': np.random.randint(10, 50),
            'has_email_form': np.random.choice([0, 1], p=[0.3, 0.7]),  # 70% yes
            'avg_word_length': np.random.uniform(4, 7),
            'unique_word_ratio': np.random.uniform(0.3, 0.6),
            'has_urgency_words': 1,
            'additional_feature': np.random.uniform(0, 1),
            'label': 1  # Phishing
        }
        phishing_data.append(features)
    
    phishing_df = pd.DataFrame(phishing_data)
    phishing_file = output_dir / 'email_phishing_samples.csv'
    phishing_df.to_csv(phishing_file, index=False)
    print(f"✓ Saved to: {phishing_file}")
    
    # Generate legitimate emails
    print(f"\nGenerating {n_samples} legitimate email samples...")
    legitimate_data = []
    for _ in range(n_samples):
        features = {
            'spf_pass': np.random.choice([0, 1], p=[0.2, 0.8]),  # 80% pass
            'dkim_pass': np.random.choice([0, 1], p=[0.2, 0.8]),
            'dmarc_pass': np.random.choice([0, 1], p=[0.2, 0.8]),
            'sender_domain_age': np.random.randint(5, 10),  # Older domains
            'url_count': np.random.randint(0, 3),  # Few URLs
            'has_shortener_urls': 0,  # No shorteners
            'has_ip_based_urls': 0,  # No IP URLs
            'suspicious_keyword_count': np.random.randint(0, 3),  # Low
            'urgency_score': np.random.uniform(0.0, 0.3),  # Low urgency
            'capitalization_ratio': np.random.uniform(0.0, 0.15),  # Normal
            'special_char_ratio': np.random.uniform(0.0, 0.1),
            'html_tag_count': np.random.randint(0, 20),
            'has_email_form': 0,  # No forms
            'avg_word_length': np.random.uniform(4, 6),
            'unique_word_ratio': np.random.uniform(0.6, 0.9),
            'has_urgency_words': 0,
            'additional_feature': np.random.uniform(0, 1),
            'label': 0  # Legitimate
        }
        legitimate_data.append(features)
    
    legitimate_df = pd.DataFrame(legitimate_data)
    legitimate_file = output_dir / 'email_legitimate_samples.csv'
    legitimate_df.to_csv(legitimate_file, index=False)
    print(f"✓ Saved to: {legitimate_file}")
    
    # Generate combined file
    print(f"\nGenerating combined dataset...")
    combined_df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    combined_file = output_dir / 'email_combined_dataset.csv'
    combined_df.to_csv(combined_file, index=False)
    print(f"✓ Saved to: {combined_file}")
    
    print(f"\n{'='*60}")
    print(f"✓ Email training data generated successfully!")
    print(f"{'='*60}")
    print(f"\nFiles created:")
    print(f"  1. {phishing_file.name} - {n_samples} phishing samples")
    print(f"  2. {legitimate_file.name} - {n_samples} legitimate samples")
    print(f"  3. {combined_file.name} - {n_samples*2} combined samples")
    print(f"\nTotal samples: {n_samples * 2}")
    print(f"Features: {len(feature_names)}")
    print(f"\nThese files can be used in the 'Train Model' tab of the desktop app.")


def generate_file_training_data(output_dir='data/training_samples', n_samples=1000):
    """
    Generate sample file training data in CSV format
    
    Args:
        output_dir: Output directory for training files
        n_samples: Number of samples per file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"Generating file training data...")
    print(f"{'='*60}")
    print(f"Output directory: {output_dir}")
    
    np.random.seed(43)
    
    # Feature names (11 features for file analysis)
    feature_names = [
        'file_size', 'file_extension', 'entropy', 'has_pe_header',
        'has_elf_header', 'null_byte_ratio', 'suspicious_strings_count',
        'has_zip_header', 'has_executable_code', 'avg_byte_value', 'magic_number'
    ]
    
    # Generate malware files
    print(f"\nGenerating {n_samples} malware file samples...")
    malware_data = []
    for _ in range(n_samples):
        features = {
            'file_size': np.random.uniform(10000, 5000000),  # 10KB - 5MB
            'file_extension': np.random.choice([1, 2, 3, 4]),  # exe, dll, bat, etc.
            'entropy': np.random.uniform(7.0, 8.0),  # High entropy (encrypted/packed)
            'has_pe_header': np.random.choice([0, 1], p=[0.3, 0.7]),  # 70% yes
            'has_elf_header': 0,
            'null_byte_ratio': np.random.uniform(0.0, 0.05),  # Low null bytes
            'suspicious_strings_count': np.random.randint(10, 50),  # Many suspicious strings
            'has_zip_header': np.random.choice([0, 1], p=[0.7, 0.3]),
            'has_executable_code': np.random.choice([0, 1], p=[0.2, 0.8]),  # 80% yes
            'avg_byte_value': np.random.uniform(100, 150),
            'magic_number': np.random.randint(0, 10),
            'label': 1  # Malware
        }
        malware_data.append(features)
    
    malware_df = pd.DataFrame(malware_data)
    malware_file = output_dir / 'file_malware_samples.csv'
    malware_df.to_csv(malware_file, index=False)
    print(f"✓ Saved to: {malware_file}")
    
    # Generate benign files
    print(f"\nGenerating {n_samples} benign file samples...")
    benign_data = []
    for _ in range(n_samples):
        features = {
            'file_size': np.random.uniform(1000, 1000000),  # 1KB - 1MB
            'file_extension': np.random.choice([0, 5, 6, 7]),  # txt, jpg, pdf, etc.
            'entropy': np.random.uniform(4.0, 6.5),  # Lower entropy
            'has_pe_header': 0,
            'has_elf_header': 0,
            'null_byte_ratio': np.random.uniform(0.1, 0.3),  # More null bytes
            'suspicious_strings_count': np.random.randint(0, 5),  # Few suspicious strings
            'has_zip_header': np.random.choice([0, 1], p=[0.8, 0.2]),
            'has_executable_code': 0,
            'avg_byte_value': np.random.uniform(50, 100),
            'magic_number': np.random.randint(10, 20),
            'label': 0  # Benign
        }
        benign_data.append(features)
    
    benign_df = pd.DataFrame(benign_data)
    benign_file = output_dir / 'file_benign_samples.csv'
    benign_df.to_csv(benign_file, index=False)
    print(f"✓ Saved to: {benign_file}")
    
    # Generate combined file
    print(f"\nGenerating combined dataset...")
    combined_df = pd.concat([malware_df, benign_df], ignore_index=True)
    combined_df = combined_df.sample(frac=1, random_state=43).reset_index(drop=True)  # Shuffle
    combined_file = output_dir / 'file_combined_dataset.csv'
    combined_df.to_csv(combined_file, index=False)
    print(f"✓ Saved to: {combined_file}")
    
    print(f"\n{'='*60}")
    print(f"✓ File training data generated successfully!")
    print(f"{'='*60}")
    print(f"\nFiles created:")
    print(f"  1. {malware_file.name} - {n_samples} malware samples")
    print(f"  2. {benign_file.name} - {n_samples} benign samples")
    print(f"  3. {combined_file.name} - {n_samples*2} combined samples")
    print(f"\nTotal samples: {n_samples * 2}")
    print(f"Features: {len(feature_names)}")
    print(f"\nThese files can be used in the 'Train Model' tab of the desktop app.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample training data')
    parser.add_argument('--type', choices=['email', 'file', 'both'], default='both',
                       help='Type of data to generate')
    parser.add_argument('--samples', type=int, default=1000,
                       help='Number of samples per class (default: 1000)')
    parser.add_argument('--output', type=str, default='data/training_samples',
                       help='Output directory (default: data/training_samples)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("Sample Training Data Generator")
    print("="*60)
    
    if args.type in ['email', 'both']:
        generate_email_training_data(args.output, args.samples)
    
    if args.type in ['file', 'both']:
        generate_file_training_data(args.output, args.samples)
    
    print(f"\n{'='*60}")
    print("ALL DONE!")
    print(f"{'='*60}")
    print(f"\nTo use these files:")
    print(f"1. Open the desktop app: python main.py desktop")
    print(f"2. Go to the 'Train Model' tab")
    print(f"3. Click 'Select Training Data Files'")
    print(f"4. Select the CSV files from {args.output}/")
    print(f"5. Click 'Start Training'")
