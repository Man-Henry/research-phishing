"""
Feature schema definitions for URL phishing detection
"""

# Feature columns used in URL phishing detection
FEATURE_COLUMNS = [
    'url_length', 'domain_length', 'tld_length', 'num_digits',
    'num_special_chars', 'num_subdomains', 'has_ip', 'has_at',
    'has_double_slash', 'has_dash', 'num_dots', 'entropy'
]

# Non-numeric columns that need encoding
NON_NUMERIC_COLUMNS = ['tld', 'protocol']

def normalize_labels(series):
    """Normalize label column to binary 0/1"""
    if series.dtype == 'object':
        # Convert string labels
        mapping = {
            'phishing': 1, 'malicious': 1, 'bad': 1, '1': 1, 1: 1,
            'legitimate': 0, 'benign': 0, 'good': 0, '0': 0, 0: 0
        }
        return series.map(lambda x: mapping.get(str(x).lower(), x))
    return series

def resolve_label_column(df):
    """Find the label column in the dataframe"""
    possible_labels = ['label', 'class', 'target', 'phishing', 'result']
    for col in possible_labels:
        if col in df.columns:
            return col
    # Default to last column
    return df.columns[-1]
