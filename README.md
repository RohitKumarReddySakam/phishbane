<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=700&amp;lines=PHISHBANE;98.9%25+Accuracy+%7C+Zero+False+Positives;Random+Forest+%7C+30+Security+Features;Real-time+URL+Classification" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Random Forest classifier detecting phishing URLs with 98.9% accuracy using 30 engineered security features.**

<br/>

[![Accuracy](https://img.shields.io/badge/Accuracy-98.90%25-64ffda?style=flat-square)](.)
[![Precision](https://img.shields.io/badge/Precision-100%25-64ffda?style=flat-square)](.)
[![False_Positives](https://img.shields.io/badge/False_Positives-Zero-22c55e?style=flat-square)](.)
[![Inference](https://img.shields.io/badge/Inference-%3C200ms-64ffda?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Overview

Phishing is the **#1 initial access vector** in enterprise breaches. PHISHBANE provides real-time URL classification using a trained Random Forest model with **30 security-relevant features** — achieving zero false positives on legitimate sites while catching **97.78% of phishing attempts**.

| Metric | Score | Benchmark |
|--------|-------|-----------|
| **Accuracy** | **98.90%** | Industry avg: 92–95% |
| **Precision** | **100.00%** | Zero false positives |
| **Recall** | **97.78%** | Catches 97.78% of phishing |
| **F1-Score** | **98.88%** | — |
| **Cross-Val Mean** | **99.44%** | 5-fold validation |
| **Inference Speed** | **< 200ms** | Per URL |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
URL Input
    │
    ▼
┌─────────────────────────────────────┐
│         Feature Extractor           │
│   30 security-relevant features     │
│   URL structure │ entropy │ patterns│
└──────────────────┬──────────────────┘
                   │
    ┌──────────────▼──────────────┐
    │  Random Forest Classifier   │
    │  100 estimators             │
    │  Trained on 902 URLs        │
    │  5-fold cross-validated     │
    └──────────────┬──────────────┘
                   │
    ┌──────────────▼──────────────┐
    │   REST API (Flask)          │
    │   POST /api/predict         │
    │   503 guard if no model     │
    │   JSON response + confidence│
    └─────────────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔧 Feature Engineering — 30 Features

<details>
<summary><b>📐 URL Structure (10 features)</b></summary>

- URL length, hostname length, path length, query length
- Number of dots, slashes, hyphens, underscores
- Subdomain depth, path depth

</details>

<details>
<summary><b>🚨 Suspicious Patterns (8 features)</b></summary>

- IP address in hostname (`http://192.168.1.1/login`)
- Non-standard port usage
- URL shortener domains (bit.ly, tinyurl, t.co…)
- Shannon entropy — detects obfuscated/random URLs

</details>

<details>
<summary><b>🎭 Brand Impersonation (7 features)</b></summary>

- Brand keywords: paypal, apple, amazon, microsoft, google, chase, wellsfargo…
- Suspicious action keywords: login, verify, secure, account, update, confirm
- TLD risk scoring

</details>

<details>
<summary><b>🔒 Security Indicators (5 features)</b></summary>

- HTTPS vs HTTP usage
- `@` symbol in URL (credential embedding)
- Special character ratios
- Query parameter depth

</details>

### Top Feature Importance

```
Path Length          ████████████████████████████████  30.72%
Number of Slashes    ██████████████████████            23.90%
Shannon Entropy      █████████████                     13.53%
URL Length           ████████                           7.94%
Path Depth           ████████                           7.44%
Other (25 features)  ████████████████                  16.47%
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/phishbane.git
cd phishbane

# Create virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
cp .env.example .env

# Train the model (first run only)
python src/collect_data.py
python src/train_model.py

# Start the API server
python app.py
# → http://localhost:8000
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/phishbane.git
cd phishbane
docker build -t phishbane .
docker run -p 8000:8000 phishbane
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Predict a URL
POST /api/predict
Content-Type: application/json

{"url": "http://paypal-secure-login.xyz/verify"}

# Response
{
  "url": "http://paypal-secure-login.xyz/verify",
  "prediction": "phishing",
  "confidence": 94.7,
  "probability_phishing": 94.7,
  "probability_legitimate": 5.3,
  "features_extracted": 30
}

# Health check
GET /health
→ {"status": "healthy", "model_loaded": true}
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
phishbane/
├── app.py                    # Flask REST API
├── wsgi.py                   # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── src/
│   ├── collect_data.py       # Dataset collection pipeline
│   ├── extract_features.py   # 30-feature extractor
│   ├── train_model.py        # Random Forest training + evaluation
│   └── prediction.py         # Inference engine
│
├── data/
│   ├── raw/                  # Original URL datasets
│   ├── processed/            # Feature matrices
│   └── models/               # Trained .pkl model
│
├── notebooks/                # Jupyter analysis notebooks
└── tests/                    # pytest test suite
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"30 well-engineered features outperform complex deep learning models for URL classification — fast, interpretable, and deployable on any hardware."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/phishbane?style=social)](https://github.com/RohitKumarReddySakam/phishbane)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
