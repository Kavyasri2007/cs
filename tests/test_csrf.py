"""
Automated Tests for Module 4: Cross-Site Request Forgery (CSRF) — GET-based Forged Action
CampusConnect — Student Portal
"""
import pytest
from app import create_app
from database import init_db, get_db_connection

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    init_db(force_reset=True)
    with app.test_client() as client:
        # Pre-authenticate as Alice (id=1)
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "alice"
            sess["student_id"] = "S2023-042"
            sess["full_name"] = "Alice Sharma"
            sess["role"] = "Student"
            sess["csrf_token"] = "valid_test_csrf_token_12345"
            sess["demo_mode"] = "vulnerable"
        yield client

def test_vulnerable_csrf_get_updates_state(client):
    """
    Verifies that the vulnerable route permits state change via a GET request
    using ambient session credentials without any CSRF token.
    """
    new_status = "SMS Alerts Only"
    response = client.get(
        f"/profile/update-preference?preference={new_status}",
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["forged_request_successful"] is True
    assert data["new_status"] == new_status

    # Verify directly in SQLite database
    conn = get_db_connection()
    row = conn.execute("SELECT notification_pref FROM users WHERE id = 1").fetchone()
    conn.close()
    assert row["notification_pref"] == new_status

def test_secure_csrf_rejects_get_with_405(client):
    """
    Verifies that the secure route rejects state-changing GET requests with HTTP 405 Method Not Allowed.
    """
    # Switch to secure mode
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"

    response = client.get(
        "/profile/update-preference?preference=Malicious+Attempt",
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 405
    data = response.get_json()
    assert data["status_code"] == 405

def test_secure_csrf_rejects_post_without_token(client):
    """
    Verifies that the secure route rejects cross-site POST requests lacking a valid CSRF token with HTTP 403.
    """
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"

    response = client.post(
        "/profile/update-preference",
        data={"preference": "Attacker POST without token"},
        headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert response.status_code == 403
    data = response.get_json()
    assert data["status_code"] == 403
    assert "Invalid or missing CSRF synchronizer token" in data["error"]

def test_secure_csrf_accepts_post_with_valid_token(client):
    """
    Verifies that legitimate POST requests containing the correct session synchronizer token succeed.
    """
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"

    legit_status = "Emergency Broadcasts Only"
    response = client.post(
        "/profile/update-preference",
        data={
            "preference": legit_status,
            "csrf_token": "valid_test_csrf_token_12345"
        }
    )
    # Successful post redirects to profile
    assert response.status_code == 302

    # Verify database update
    conn = get_db_connection()
    row = conn.execute("SELECT notification_pref FROM users WHERE id = 1").fetchone()
    conn.close()
    assert row["notification_pref"] == legit_status
