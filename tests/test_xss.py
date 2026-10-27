"""
Automated Tests for Module 3: Reflected Cross-Site Scripting (XSS)
"""
import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_vulnerable_reflected_xss_returns_raw_markup(client):
    """
    Verifies that the vulnerable search endpoint reflects raw, unescaped HTML/JavaScript tags
    in the HTTP response.
    """
    payload = "<script>alert('XSS_TEST_HARMFREE');</script>"
    response = client.get(f"/xss/vulnerable/search?q={payload}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    # The raw script tag must be present directly in the HTML without escaping
    assert "<script>alert('XSS_TEST_HARMFREE');</script>" in html

def test_secure_xss_escapes_html_entities(client):
    """
    Verifies that the secure search endpoint safely encodes HTML entities,
    rendering < as &lt; and > as &gt;.
    """
    payload = "<script>alert('XSS_TEST_HARMFREE');</script>"
    response = client.get(f"/xss/secure/search?q={payload}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    # Raw script tag must NOT be present
    assert "<script>alert('XSS_TEST_HARMFREE');</script>" not in html
    # Escaped entities must be present
    assert "&lt;script&gt;alert(&#39;XSS_TEST_HARMFREE&#39;);&lt;/script&gt;" in html or \
           "&lt;script&gt;alert('XSS_TEST_HARMFREE');&lt;/script&gt;" in html or \
           "&lt;script&gt;" in html
