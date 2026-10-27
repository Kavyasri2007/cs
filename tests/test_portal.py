"""
Automated Tests for CampusConnect Student Portal User Flows & Demo Mode Switching
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
        yield client

def test_portal_login_page_renders_cleanly(client):
    """Verifies that the login page renders a clean student portal form."""
    res = client.get("/login")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Student Portal Login" in html
    assert "CampusConnect" in html
    assert "institutional credentials" in html.lower()

def test_portal_legitimate_student_login(client):
    """Verifies that a valid student (Alice) logs in and is redirected to dashboard."""
    res = client.post("/login", data={"username": "alice", "password": "Alice#Pass2026"}, follow_redirects=True)
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Alice Sharma" in html
    assert "S2023-042" in html
    assert "Cumulative GPA" in html

def test_portal_sqli_bypass_in_vulnerable_mode(client):
    """Verifies that SQLi authentication bypass works in portal login when demo mode is vulnerable."""
    with client.session_transaction() as sess:
        sess["demo_mode"] = "vulnerable"

    res = client.post("/login", data={"username": "admin' --", "password": "anypassword"}, follow_redirects=True)
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    # Logged in as Dr. Admin Prasad
    assert "Dr. Admin Prasad" in html

def test_portal_sqli_bypass_fails_in_secure_mode(client):
    """Verifies that SQLi bypass fails in portal login when demo mode is secure."""
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"

    res = client.post("/login", data={"username": "admin' --", "password": "anypassword"})
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Invalid Student ID / Username or Password" in html

def test_portal_notices_xss_vulnerable_vs_secure(client):
    """Verifies that Notices search exhibits Reflected XSS in vulnerable mode and escaping in secure mode."""
    xss_payload = "<script>alert('XSS_PORTAL_PROOF');</script>"

    # 1. Vulnerable mode: raw unescaped script tag
    with client.session_transaction() as sess:
        sess["demo_mode"] = "vulnerable"
    res_vuln = client.get(f"/notices?q={xss_payload}")
    assert res_vuln.status_code == 200
    assert xss_payload in res_vuln.get_data(as_text=True)

    # 2. Secure mode: escaped HTML entities
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"
    res_sec = client.get(f"/notices?q={xss_payload}")
    assert res_sec.status_code == 200
    html_sec = res_sec.get_data(as_text=True)
    assert xss_payload not in html_sec
    assert "&lt;script&gt;" in html_sec

def test_portal_network_diagnostic_cmd_injection(client):
    """Verifies Command Injection in Help & Support diagnostic tool."""
    cmd_payload = "127.0.0.1 & echo [CAMPUS-IT-PROOF]"

    # Vulnerable mode
    with client.session_transaction() as sess:
        sess["demo_mode"] = "vulnerable"
    res_vuln = client.post("/support", data={"target": cmd_payload})
    assert res_vuln.status_code == 200
    assert "[CAMPUS-IT-PROOF]" in res_vuln.get_data(as_text=True)

    # Secure mode
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"
    res_sec = client.post("/support", data={"target": cmd_payload})
    assert res_sec.status_code == 200
    assert "Security Filter Blocked Input" in res_sec.get_data(as_text=True)

def test_portal_csrf_preference_update(client):
    """Verifies CSRF vulnerability and mitigation on student profile preference update."""
    # Authenticate as Alice
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "alice"
        sess["csrf_token"] = "valid_portal_token_999"

    # Vulnerable mode: GET updates preference
    with client.session_transaction() as sess:
        sess["demo_mode"] = "vulnerable"
    res_vuln = client.get("/profile/update-preference?preference=Forged+via+GET", follow_redirects=True)
    assert res_vuln.status_code == 200
    conn = get_db_connection()
    user = conn.execute("SELECT notification_pref FROM users WHERE id = 1").fetchone()
    conn.close()
    assert user["notification_pref"] == "Forged via GET"

    # Secure mode: GET rejected with 405
    with client.session_transaction() as sess:
        sess["demo_mode"] = "secure"
    res_sec_get = client.get("/profile/update-preference?preference=Attempt")
    assert res_sec_get.status_code == 405

    # Secure mode: POST with valid token succeeds
    res_sec_post = client.post("/profile/update-preference", data={
        "preference": "Email & Portal Alerts",
        "csrf_token": "valid_portal_token_999"
    }, follow_redirects=True)
    assert res_sec_post.status_code == 200
    conn = get_db_connection()
    user = conn.execute("SELECT notification_pref FROM users WHERE id = 1").fetchone()
    conn.close()
    assert user["notification_pref"] == "Email & Portal Alerts"

def test_demo_mode_switching_endpoint(client):
    """Verifies that /demo/set-mode dynamically updates session mode."""
    res = client.post("/demo/set-mode", json={"mode": "secure"})
    assert res.status_code == 200
    assert res.get_json()["mode"] == "secure"
