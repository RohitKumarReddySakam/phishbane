"""
PHISHBANE — ML-Powered Phishing URL Detection Engine
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 2.0.0

ML-powered phishing URL detection using Random Forest classifier
with 30+ URL feature extraction for real-time threat analysis.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import tldextract
import re
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishbane-dev-key-2025")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "data", "models", "phishing_detector.pkl")
model = None


def load_model():
    """Load the trained Random Forest model."""
    global model
    try:
        model = joblib.load(MODEL_PATH)
        logger.info("Phishing detection model loaded")
    except Exception as e:
        logger.warning(f"Model not found, running in feature-only mode: {e}")

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

def extract_features(url):
    """Extract features from URL for prediction"""
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
        
        features['brand_in_subdomain'] = int(any(brand in subdomain_lower for brand in brands))
        features['brand_in_path'] = int(any(brand in path_lower for brand in brands))
        
        # Suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'review']
        features['suspicious_tld'] = int(extracted.suffix in suspicious_tlds if extracted.suffix else False)
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        features['is_shortened'] = int(any(short in extracted.domain for short in shorteners))
        
        # Special character ratio
        special_chars = sum(not c.isalnum() for c in url)
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
    except Exception as e:
        logger.warning(f"Feature extraction failed for URL: {e}")
        return None
    
    return features

@app.route('/')
def home():
    """Render home page"""
    return render_template('index.html')

@app.route('/api/predict', methods=['POST'])
def predict():
    """API endpoint for URL prediction"""
    if model is None:
        return jsonify({'error': 'Model not loaded. Run training pipeline first.'}), 503

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON body provided'}), 400
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        features = extract_features(url)

        if features is None:
            return jsonify({'error': 'Invalid URL format'}), 400

        features_df = pd.DataFrame([features])

        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]

        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'is_phishing': bool(prediction == 1),
            'confidence': float(max(probability) * 100),
            'probability_legitimate': float(probability[0] * 100),
            'probability_phishing': float(probability[1] * 100),
            'risk_level': get_risk_level(probability[1]),
            'features': features,
        }

        return jsonify(result)

    except Exception as e:
        logger.error(f"Prediction error: {e}", exc_info=True)
        return jsonify({'error': 'Prediction failed'}), 500
        return jsonify({
            'error': f'Prediction failed: {str(e)}'
        }), 500

def get_risk_level(phishing_prob):
    """Determine risk level based on probability"""
    if phishing_prob >= 0.9:
        return 'CRITICAL'
    elif phishing_prob >= 0.7:
        return 'HIGH'
    elif phishing_prob >= 0.5:
        return 'MEDIUM'
    elif phishing_prob >= 0.3:
        return 'LOW'
    else:
        return 'SAFE'

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'version': '2.0.0'
    })


def create_app():
    load_model()
    return app


if __name__ == '__main__':
    create_app()
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
