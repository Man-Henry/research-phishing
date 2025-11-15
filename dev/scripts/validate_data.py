"""
Validate and Clean Training Data
Kiểm tra và làm sạch dữ liệu training trước khi train model
"""
import pandas as pd
import numpy as np
from pathlib import Path
import sys

def validate_csv(file_path, model_type='email'):
    """
    Validate and clean a CSV training file
    
    Args:
        file_path: Path to CSV file
        model_type: 'email' or 'file'
    
    Returns:
        DataFrame with cleaned data and validation report
    """
    print(f"\n{'='*60}")
    print(f"Validating: {Path(file_path).name}")
    print(f"{'='*60}")
    
    # Load CSV
    try:
        df = pd.read_csv(file_path)
        print(f"✓ Loaded {len(df)} rows, {len(df.columns)} columns")
    except Exception as e:
        print(f"❌ Failed to load CSV: {e}")
        return None, []
    
    issues = []
    cleaned_df = df.copy()
    
    # Check 1: Identify non-numeric columns
    print(f"\n1. Checking for non-numeric columns...")
    non_numeric_cols = []
    for col in cleaned_df.columns:
        if cleaned_df[col].dtype == 'object':
            sample = str(cleaned_df[col].iloc[0]) if len(cleaned_df) > 0 else ''
            print(f"   ⚠️  Column '{col}' is text: {sample[:50]}...")
            
            # Check if it's a filename column
            if any(ext in sample.lower() for ext in ['.txt', '.exe', '.pdf', '.doc', '.csv']):
                non_numeric_cols.append(col)
                print(f"      → Looks like filename, will remove")
            # Check if it's an ID column
            elif any(id_name in col.lower() for id_name in ['id', 'name', 'file', 'path', 'email', 'url']):
                non_numeric_cols.append(col)
                print(f"      → Looks like ID/name column, will remove")
            else:
                # Try to convert to numeric
                try:
                    pd.to_numeric(cleaned_df[col], errors='raise')
                    print(f"      → Can convert to numeric, will keep")
                except:
                    non_numeric_cols.append(col)
                    print(f"      → Cannot convert to numeric, will remove")
    
    if non_numeric_cols:
        issues.append(f"Removed {len(non_numeric_cols)} non-numeric columns: {non_numeric_cols}")
    
    # Check 2: Find label column
    print(f"\n2. Looking for label column...")
    label_col = None
    possible_label_cols = ['label', 'is_phishing', 'is_malware', 'class', 'target', 'y']
    
    for col in possible_label_cols:
        if col in cleaned_df.columns:
            label_col = col
            print(f"   ✓ Found label column: '{col}'")
            unique_labels = cleaned_df[col].unique()
            print(f"      Labels: {unique_labels}")
            break
    
    if not label_col:
        print(f"   ⚠️  No label column found")
        print(f"      Will infer from filename: ", end='')
        if 'phishing' in Path(file_path).name.lower() or 'malware' in Path(file_path).name.lower():
            print("POSITIVE (1)")
        else:
            print("NEGATIVE (0)")
        issues.append("No label column - inferring from filename")
    
    # Remove non-feature columns
    cols_to_drop = non_numeric_cols.copy()
    if label_col:
        # Keep label column for now
        cols_to_drop = [c for c in cols_to_drop if c != label_col]
    
    if cols_to_drop:
        cleaned_df = cleaned_df.drop(columns=cols_to_drop)
        print(f"\n   Dropped columns: {cols_to_drop}")
    
    # Check 3: Convert to numeric
    print(f"\n3. Converting to numeric...")
    feature_cols = [c for c in cleaned_df.columns if c != label_col]
    
    for col in feature_cols:
        before_type = cleaned_df[col].dtype
        cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce')
        if before_type != cleaned_df[col].dtype:
            print(f"   ✓ Converted '{col}': {before_type} → {cleaned_df[col].dtype}")
    
    # Check 4: Handle missing values
    print(f"\n4. Checking for missing values...")
    missing_counts = cleaned_df.isnull().sum()
    has_missing = missing_counts[missing_counts > 0]
    
    if len(has_missing) > 0:
        print(f"   ⚠️  Found missing values:")
        for col, count in has_missing.items():
            print(f"      - {col}: {count} ({count/len(cleaned_df)*100:.1f}%)")
        
        cleaned_df = cleaned_df.fillna(0)
        print(f"   ✓ Filled missing values with 0")
        issues.append(f"Filled {len(has_missing)} columns with missing values")
    else:
        print(f"   ✓ No missing values")
    
    # Check 5: Handle infinite values
    print(f"\n5. Checking for infinite values...")
    inf_count = np.isinf(cleaned_df.select_dtypes(include=[np.number]).values).sum()
    
    if inf_count > 0:
        print(f"   ⚠️  Found {inf_count} infinite values")
        cleaned_df = cleaned_df.replace([np.inf, -np.inf], 0)
        print(f"   ✓ Replaced infinite values with 0")
        issues.append(f"Replaced {inf_count} infinite values")
    else:
        print(f"   ✓ No infinite values")
    
    # Check 6: Verify feature count
    print(f"\n6. Checking feature count...")
    expected_features = 17 if model_type == 'email' else 11
    feature_count = len(feature_cols)
    
    if feature_count == expected_features:
        print(f"   ✓ Feature count correct: {feature_count}")
    else:
        print(f"   ⚠️  Feature count mismatch:")
        print(f"      Expected: {expected_features} features")
        print(f"      Found: {feature_count} features")
        issues.append(f"Feature count: {feature_count} (expected {expected_features})")
    
    # Check 7: Check label distribution
    if label_col:
        print(f"\n7. Checking label distribution...")
        label_counts = cleaned_df[label_col].value_counts()
        print(f"   Label distribution:")
        for label, count in label_counts.items():
            print(f"      {label}: {count} ({count/len(cleaned_df)*100:.1f}%)")
        
        # Check balance
        if len(label_counts) == 2:
            ratio = label_counts.min() / label_counts.max()
            if ratio < 0.3:
                print(f"   ⚠️  Imbalanced dataset (ratio: {ratio:.2f})")
                issues.append("Dataset is imbalanced")
            else:
                print(f"   ✓ Reasonably balanced (ratio: {ratio:.2f})")
    
    # Summary
    print(f"\n{'='*60}")
    if len(issues) == 0:
        print(f"✅ VALIDATION PASSED - Data is clean!")
    else:
        print(f"⚠️  VALIDATION COMPLETED WITH {len(issues)} ISSUES:")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
    print(f"{'='*60}")
    
    # Final shape
    print(f"\nFinal data shape: {cleaned_df.shape}")
    print(f"Ready for training: {len(cleaned_df)} samples, {len(feature_cols)} features")
    
    return cleaned_df, issues


def save_cleaned_data(df, original_path):
    """Save cleaned data to new file"""
    original_path = Path(original_path)
    cleaned_path = original_path.parent / f"{original_path.stem}_cleaned.csv"
    
    df.to_csv(cleaned_path, index=False)
    print(f"\n✓ Saved cleaned data to: {cleaned_path}")
    return cleaned_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate and clean training data')
    parser.add_argument('file', type=str, help='CSV file to validate')
    parser.add_argument('--type', choices=['email', 'file'], default='email',
                       help='Model type (default: email)')
    parser.add_argument('--save', action='store_true',
                       help='Save cleaned data to new file')
    parser.add_argument('--fix', action='store_true',
                       help='Fix issues and overwrite original file')
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"❌ File not found: {args.file}")
        sys.exit(1)
    
    # Validate
    cleaned_df, issues = validate_csv(args.file, args.type)
    
    if cleaned_df is None:
        print("\n❌ Validation failed - could not load file")
        sys.exit(1)
    
    # Save if requested
    if args.save or args.fix:
        if args.fix:
            cleaned_df.to_csv(args.file, index=False)
            print(f"\n✓ Fixed and saved to: {args.file}")
        else:
            saved_path = save_cleaned_data(cleaned_df, args.file)
            print(f"\nUse this file for training: {saved_path}")
    
    # Print instructions
    print(f"\n{'='*60}")
    print("NEXT STEPS:")
    print(f"{'='*60}")
    
    if len(issues) > 0:
        if not args.fix:
            print("\n1. Review the issues above")
            print("2. Run with --fix to automatically fix:")
            print(f"   python dev/scripts/validate_data.py {args.file} --fix")
        else:
            print("\n✓ Issues have been fixed!")
    
    print("\n3. Use the cleaned file in the Training Tab:")
    print("   • Open desktop app")
    print("   • Go to 'Train Model' tab")
    print("   • Select the (cleaned) CSV file")
    print("   • Start training")


if __name__ == "__main__":
    # If no args, show example usage
    if len(sys.argv) == 1:
        print("="*60)
        print("Training Data Validator")
        print("="*60)
        print("\nUsage:")
        print("  python dev/scripts/validate_data.py <file.csv>")
        print("\nOptions:")
        print("  --type email|file   Model type (default: email)")
        print("  --save              Save cleaned data to new file")
        print("  --fix               Fix issues and overwrite original")
        print("\nExamples:")
        print("  python dev/scripts/validate_data.py data/my_data.csv")
        print("  python dev/scripts/validate_data.py data/my_data.csv --fix")
        print("  python dev/scripts/validate_data.py data/my_data.csv --save --type file")
        sys.exit(0)
    
    main()
