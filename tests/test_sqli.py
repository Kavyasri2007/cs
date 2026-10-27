"""
Automated Tests for Module 1: SQL Injection (SQLi) — Authentication Bypass
CampusConnect — Student Portal
"""
import pytest
from app import create_app
from database import init_db

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    init_db(force_reset=True)
    with app.test_client() as client:
        yield client

def test_vulnerable_sqli_authentication_bypass(client):
    """
    Verifies that unsafe string concatenation allows an attacker to bypass authentication
    using the harmless payload `admin' --` or `' OR '1'='1' --`.
    """
    payload = "admin' --"
    response = client.post(
        "/sqli/vulnerable/login",
        data={"username": payload, "password": "anypassword"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["auth_success"] is True
    assert data["user_info"]["username"] == "admin"
    assert "admin' --" in data["executed_query"]

def test_secure_sqli_injection_attempt_rejected(client):
    """
    Verifies that parameterized queries treat `admin' --` strictly as literal string data,
    rejecting the injection attempt.
    """
    payload = "admin' --"
    response = client.post(
        "/sqli/secure/login",
        data={"username": payload, "password": "anypassword"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["auth_success"] is False
    assert "Invalid username or password" in data["error_message"]

def test_secure_sqli_legitimate_login_success(client):
    """
    Verifies that legitimate credentials authenticate successfully against the secure handler
    using PBKDF2/SHA-256 hash verification.
    """
    response = client.post(
        "/sqli/secure/login",
        data={"username": "alice", "password": "Alice#Pass2026"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["auth_success"] is True
    assert data["user_info"]["username"] == "alice"
    assert data["user_info"]["student_id"] == "S2023-042"

def test_secure_sqli_invalid_password_rejected(client):
    """
    Verifies that incorrect credentials fail against the secure handler.
    """
    response = client.post(
        "/sqli/secure/login",
        data={"username": "alice", "password": "WrongPassword123"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["auth_success"] is False
