"""
Feature Engineering for Phishing Detection
Extracts 35+ security-relevant features from URLs
"""

import pandas as pd
import re
import numpy as np
from urllib.parse import urlparse
import tldextract
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def extract_url_features(url):
    """Extract comprehensive features from a single URL"""
    features = {}
    
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        
        # Character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Domain features
        features['domain_length'] = len(extracted.domain)
        features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
        features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
        
        # Subdomain count
        if extracted.subdomain:
            features['subdomain_count'] = len(extracted.subdomain.split('.'))
        else:
            features['subdomain_count'] = 0
        
        # Path depth
        path_parts = [x for x in parsed.path.split('/') if x]
        features['path_depth'] = len(path_parts)
        
        # Query parameters
        features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
        
        # Suspicious patterns
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        features['has_port'] = 1 if re.search(r':\d+', parsed.netloc) else 0
        features['is_https'] = 1 if url.startswith('https') else 0
        
        # Entropy
        features['entropy'] = calculate_entropy(url)
        
        # Suspicious keywords
        suspicious_keywords = [
            'login', 'verify', 'account', 'update', 'secure', 'banking',
            'confirm', 'suspend', 'restrict', 'click', 'urgent', 'bonus'
        ]
        features['suspicious_word_count'] = sum(
            1 for word in suspicious_keywords if word in url.lower()
        )
        
        # Brand impersonation
        brands = [
            'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
            'netflix', 'ebay', 'instagram', 'twitter', 'linkedin', 'chase'
        ]
        subdomain_lower = extracted.subdomain.lower() if extracted.subdomain else ''
        path_lower = parsed.path.lower()
        
        features['brand_in_subdomain'] = any(brand in subdomain_lower for brand in brands)
        features['brand_in_path'] = any(brand in path_lower for brand in brands)
        
        # Suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'review']
        features['suspicious_tld'] = extracted.suffix in suspicious_tlds if extracted.suffix else False
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        features['is_shortened'] = any(short in extracted.domain for short in shorteners)
        
        # Special character ratio
        special_chars = sum(not c.isalnum() for c in url)
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        # Convert booleans to integers
        for key in features:
            if isinstance(features[key], bool):
                features[key] = int(features[key])
        
    except Exception as e:
        print(f"⚠️  Error parsing URL: {url[:50]}...")
        return {key: 0 for key in ['url_length', 'hostname_length', 'path_length', 
                'query_length', 'num_dots', 'num_hyphens', 'num_underscores', 
                'num_slashes', 'num_questionmarks', 'num_equals', 'num_at', 
                'num_ampersand', 'num_percent', 'num_digits', 'domain_length', 
                'subdomain_length', 'tld_length', 'subdomain_count', 'path_depth', 
                'num_params', 'has_ip', 'has_port', 'is_https', 'entropy', 
                'suspicious_word_count', 'brand_in_subdomain', 'brand_in_path', 
                'suspicious_tld', 'is_shortened', 'special_char_ratio']}
    
    return features

def calculate_entropy(string):
    """Calculate Shannon entropy"""
    if not string or len(string) == 0:
        return 0
    
    char_freq = {}
    for char in string:
        char_freq[char] = char_freq.get(char, 0) + 1
    
    entropy = 0
    length = len(string)
    
    for freq in char_freq.values():
        probability = freq / length
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy

def process_dataset(input_file, output_file):
    """Process entire dataset and extract features"""
    print("=" * 60)
    print("FEATURE ENGINEERING - AI PHISHING DETECTOR")
    print("=" * 60)
    
    print(f"\n📂 Loading dataset from: {input_file}")
    df = pd.read_csv(input_file)
    print(f"✅ Loaded {len(df)} URLs")
    
    print("\n🔧 Extracting features from URLs...")
    features_list = []
    total = len(df)
    
    for idx, row in df.iterrows():
        if (idx + 1) % 100 == 0 or idx == 0:
            progress = ((idx + 1) / total) * 100
            print(f"   Progress: {idx + 1}/{total} ({progress:.1f}%)")
        
        url = row['url']
        features = extract_url_features(url)
        features['label'] = row['label']
        features_list.append(features)
    
    features_df = pd.DataFrame(features_list)
    
    print(f"\n💾 Saving features to: {output_file}")
    features_df.to_csv(output_file, index=False)
    
    print("\n" + "=" * 60)
    print("✅ FEATURE EXTRACTION COMPLETE!")
    print("=" * 60)
    print(f"\nDataset shape: {features_df.shape}")
    print(f"Features extracted: {features_df.shape[1] - 1}")
    
    print("\n📊 Feature List:")
    feature_cols = [col for col in features_df.columns if col != 'label']
    for i, col in enumerate(feature_cols, 1):
        print(f"   {i:2d}. {col}")
    
    return features_df

def main():
    start_time = datetime.now()
    print(f"\nStarted: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    features_df = process_dataset(
        input_file='data/processed/dataset.csv',
        output_file='data/processed/features.csv'
    )
    
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 60)
    print(f"⏱️  Time taken: {elapsed:.2f} seconds")
    print("=" * 60)
    
    print("\n🎯 Next step: Model training")
    print("   Run: python src/train_model.py")

if __name__ == "__main__":
    main()
