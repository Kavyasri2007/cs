"""
Automated Tests for Module 2: OS Command Injection — In-band
"""
import pytest
import platform
from app import create_app

IS_WINDOWS = platform.system().lower() == "windows"

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_vulnerable_cmd_injection_exploit(client):
    """
    Verifies that the vulnerable diagnostic endpoint executes chained shell commands in-band.
    """
    if IS_WINDOWS:
        payload = "127.0.0.1 & echo [LAB-PROOF: In-Band Command Executed]"
    else:
        payload = "127.0.0.1 ; echo [LAB-PROOF: In-Band Command Executed]"

    response = client.post(
        "/cmd/vulnerable/diagnose",
        data={"target": payload},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "[LAB-PROOF: In-Band Command Executed]" in data["output"]
    assert data["injected_detected"] is True

def test_secure_cmd_injection_blocked_by_allowlist(client):
    """
    Verifies that the secure diagnostic endpoint rejects shell metacharacters (&, ;, |)
    and aborts execution before calling any binary.
    """
    if IS_WINDOWS:
        payload = "127.0.0.1 & echo [LAB-PROOF]"
    else:
        payload = "127.0.0.1 ; echo [LAB-PROOF]"

    response = client.post(
        "/cmd/secure/diagnose",
        data={"target": payload},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["validation_rejected"] is True
    assert data["injected_detected"] is False
    assert "Security Validation Filter Blocked Input" in data["output"]

def test_secure_cmd_clean_host_allowed(client):
    """
    Verifies that clean alphanumeric inputs matching the allow-list are executed safely.
    """
    response = client.post(
        "/cmd/secure/diagnose",
        data={"target": "127.0.0.1"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["validation_rejected"] is False
    assert "ping" in data["executed_command"].lower()
