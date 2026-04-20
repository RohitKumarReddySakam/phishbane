#!/bin/bash
set -e

echo "=== PHISHBANE Setup ==="

python -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

mkdir -p data/{raw,processed,models} static/{css,js}

if [ ! -f data/models/phishing_detector.pkl ]; then
    echo "No trained model found. Run training pipeline:"
    echo "  python src/collect_data.py"
    echo "  python src/extract_features.py"
    echo "  python src/train_model.py"
fi

echo "PHISHBANE setup complete. Start with: python app.py"
