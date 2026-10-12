"""Integration unit tests for C1 FastAPI endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "c1-url-domain-analyzer"
    assert data["component"] == "C1_URL_DOMAIN"


def test_analyze_url_endpoint():
    payload = {"url": "https://login.paypal.verify-account.com/security/login.php"}
    response = client.post("/analyze-url", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["component"] == "C1_URL_DOMAIN"
    assert data["status"] == "success"
    assert "score" in data
    assert "features" in data
    assert data["features"]["hostname"] == "login.paypal.verify-account.com"
    assert data["features"]["has_suspicious_keyword"] is True


def test_extract_features_endpoint():
    payload = {"url": "http://192.168.1.1/admin"}
    response = client.post("/api/v1/extract-features", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["is_ip_address"] is True
    assert data["ip_type"] == "ipv4"
    assert data["is_private_ip"] is True


def test_analyze_url_empty_payload():
    response = client.post("/analyze-url", json={"url": "   "})
    assert response.status_code == 400
    data = response.json()
    assert "URL field cannot be empty" in data["detail"]


def test_domain_intelligence_endpoint():
    payload = {"url": "https://example.com"}
    response = client.post("/api/v1/domain-intelligence", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "registration" in data
    assert "dns" in data
    assert "reputation" in data
    assert "domain_risk_score" in data
