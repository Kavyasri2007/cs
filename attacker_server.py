"""
Attacker Server for CSRF Demonstration
Simulates a separate, untrusted external web origin (http://localhost:5001)
targeting the vulnerable Web Server Security Lab at http://127.0.0.1:5000.

Binds strictly to loopback (127.0.0.1:5001) for local educational safety.
"""

from flask import Flask, render_template, request, jsonify
from config import Config

attacker_app = Flask(__name__, template_folder="templates")
attacker_app.secret_key = "attacker-server-secret-key"

@attacker_app.before_request
def check_loopback():
    """Ensure attacker server is only accessible via local loopback."""
    if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
        return jsonify({"error": "Access denied: Attacker server restricted to local loopback."}), 403

@attacker_app.route("/")
def attack_dashboard():
    """
    Renders the simulated attacker page.
    Demonstrates:
    1. Cross-site Top-Level Navigation GET exploit (succeeds against vulnerable endpoint under SameSite=Lax).
    2. Subresource cross-site GET attempt (illustrates why SameSite=Lax blocks subresource cookies).
    3. Mitigated endpoint test (demonstrates HTTP 405 rejection of GET and HTTP 403 rejection of forged POST).
    """
    target_origin = f"http://{Config.TARGET_HOST}:{Config.TARGET_PORT}"
    return render_template(
        "attacker/csrf_attack.html",
        target_origin=target_origin,
        target_host=Config.TARGET_HOST,
        target_port=Config.TARGET_PORT
    )

if __name__ == "__main__":
    print("=" * 70)
    print("  SIMULATED ATTACKER SERVER (PORT 5001)")
    print("  Origin: http://localhost:5001 (or http://127.0.0.1:5001)")
    print(f"  Target: http://{Config.TARGET_HOST}:{Config.TARGET_PORT}")
    print("=" * 70)
    attacker_app.run(host="127.0.0.1", port=Config.ATTACKER_PORT, debug=True)
