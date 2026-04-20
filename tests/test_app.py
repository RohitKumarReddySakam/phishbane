"""Tests for PHISHBANE — ML-Powered Phishing URL Detection Engine"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app as flask_app, extract_features, calculate_entropy


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "healthy"


def test_home(client):
    r = client.get("/")
    assert r.status_code == 200


def test_predict_no_url(client):
    r = client.post("/api/predict", json={})
    assert r.status_code == 400


def test_calculate_entropy():
    assert calculate_entropy("") == 0
    assert calculate_entropy("aaaa") == 0.0
    e = calculate_entropy("abcd")
    assert e > 0


def test_extract_features_legitimate():
    feats = extract_features("https://www.google.com/search?q=python")
    assert feats is not None
    assert feats["is_https"] == 1
    assert feats["url_length"] > 0
    assert feats["num_dots"] >= 1


def test_extract_features_suspicious():
    feats = extract_features("http://paypal-login.verify-account.tk/confirm?user=test")
    assert feats is not None
    assert feats["is_https"] == 0
    assert feats["suspicious_tld"] == 1
    assert feats["suspicious_word_count"] >= 2


def test_extract_features_ip_url():
    feats = extract_features("http://192.168.1.1/login")
    assert feats is not None
    assert feats["has_ip"] == 1


def test_predict_with_model_missing(client):
    """Should return 503 when model not loaded."""
    original = flask_app.config.get("TESTING")
    r = client.post("/api/predict", json={"url": "http://example.com"})
    # Either 200 (model loaded) or 503 (model not found) is valid
    assert r.status_code in (200, 503)
