"""
Module 4: Cross-Site Request Forgery (CSRF) — GET-based Forged Action
CampusConnect — Student Portal (IIIT Allahabad)

Demonstrates:
- Reconciled CSRF routes across student profile update, attacker server, and tests.
- Vulnerable state-changing GET endpoint abused via cross-origin request.
- Why SameSite=Lax permits cookies on top-level GET navigations.
- Secure mitigation via:
  1. Rejection of state-changing GET requests (HTTP 405 Method Not Allowed).
  2. Enforcing HTTP POST with server-side Synchronizer CSRF Token validation (hmac.compare_digest).
  3. Defense-in-depth cookie attributes.
"""

import secrets
import hmac
from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify, abort
from database import get_db_connection
from config import is_local_dev

csrf_bp = Blueprint("csrf", __name__, url_prefix="/csrf")

# ============================================================================
# EXPLANATION & ROOT CAUSE SNIPPETS (For Demo Mode drawer & Viva)
# ============================================================================
VULNERABLE_CODE_SNIPPET = '''# INTENTIONALLY VULNERABLE — LOCAL LAB ONLY
# Root Cause: State-changing action executed over HTTP GET without intent verification.
# An external website (http://localhost:5001) tricks the browser into a top-level GET navigation.
# Under SameSite=Lax, the browser sends ambient session cookies, altering user data without consent!
@csrf_bp.route("/profile/update-preference", methods=["GET"])
def vulnerable_update_preference():
    new_pref = request.args.get("preference")
    update_user_preference(session["user_id"], new_pref)'''

SECURE_CODE_SNIPPET = '''# SECURE FIX — REJECT GET & ENFORCE SYNCHRONIZER CSRF TOKEN OVER POST
@csrf_bp.route("/profile/update-preference", methods=["GET", "POST"])
def secure_update_preference():
    # 1. State changes MUST NOT allow HTTP GET
    if request.method == "GET":
        return "Method Not Allowed: State changes must use POST with CSRF token.", 405

    # 2. Cryptographic Synchronizer Token Validation (Constant-time comparison)
    client_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not hmac.compare_digest(client_token, session_token):
        return "Forbidden: Invalid or missing CSRF token.", 403

    update_user_preference(session["user_id"], request.form.get("preference"))'''


def get_user_by_id(user_id):
    """Retrieves user row from database by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, student_id, username, full_name, email, role,
               department, semester, cgpa, attendance, notification_pref
        FROM users WHERE id = ?
    """, (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def update_user_preference(user_id, new_pref):
    """Updates user's campus notification preference in SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET notification_pref = ? WHERE id = ?", (new_pref, user_id))
    conn.commit()
    conn.close()


def ensure_csrf_token():
    """Generates a cryptographically strong synchronizer token in the session if not present."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


# ============================================================================
# RECONCILED VULNERABLE CSRF ENDPOINTS (GET-BASED STATE CHANGE)
# ============================================================================
@csrf_bp.route("/vulnerable/update-status", methods=["GET"])
def vulnerable_update_status():
    """
    INTENTIONALLY VULNERABLE — LOCAL LAB ONLY:
    Permits state change via HTTP GET using ambient session cookies.
    """
    if not is_local_dev(request):
        abort(403, description="Access Denied: Vulnerable endpoints restricted to local development.")

    if "user_id" not in session:
        return jsonify({
            "success": False,
            "error": "Unauthorized: Victim is not logged in. Please log in on http://127.0.0.1:5000/login first."
        }), 401

    new_pref = request.args.get("preference") or request.args.get("status") or "Notification Setting Updated via Unsafe GET"
    user_before = get_user_by_id(session["user_id"])
    prev_pref = user_before["notification_pref"] if user_before else "Unknown"

    update_user_preference(session["user_id"], new_pref)
    user_after = get_user_by_id(session["user_id"])

    response_data = {
        "variant": "vulnerable",
        "action": "Notification Preference Updated via GET (CSRF Vulnerable)",
        "victim_username": session.get("username"),
        "victim_name": user_after["full_name"] if user_after else session.get("username"),
        "previous_status": prev_pref,
        "new_status": user_after["notification_pref"] if user_after else new_pref,
        "forged_request_successful": True,
        "message": f"CRITICAL: Preference changed to '{new_pref}' without CSRF token validation!"
    }

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(response_data)

    return render_template(
        "portal/csrf_result.html",
        result=response_data,
        variant="vulnerable",
        user=user_after
    )


# ============================================================================
# RECONCILED SECURE CSRF ENDPOINTS (POST-BASED + SYNCHRONIZER TOKEN)
# ============================================================================
@csrf_bp.route("/secure/update-status", methods=["GET", "POST"])
def secure_update_status():
    """
    SECURE FIX — REJECT GET & ENFORCE SYNCHRONIZER CSRF TOKEN:
    1. HTTP GET requests rejected immediately with 405 Method Not Allowed.
    2. HTTP POST requests require cryptographically verified csrf_token.
    """
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized: Session expired."}), 401

    # DEFENSE 1: Disallow state-changing GET requests
    if request.method == "GET":
        response_data = {
            "variant": "secure",
            "action": "Blocked State-Changing GET Request",
            "status_code": 405,
            "error": "HTTP 405 Method Not Allowed: State-changing operations are strictly forbidden on HTTP GET. Use POST with a valid CSRF token."
        }
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(response_data), 405
        return render_template(
            "portal/csrf_result.html",
            result=response_data,
            variant="secure_blocked",
            user=get_user_by_id(session["user_id"])
        ), 405

    # DEFENSE 2: Verify Synchronizer CSRF Token
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")

    if not expected_token or not submitted_token or not hmac.compare_digest(submitted_token, expected_token):
        response_data = {
            "variant": "secure",
            "action": "CSRF Attack Blocked",
            "status_code": 403,
            "error": "HTTP 403 Forbidden: Invalid or missing CSRF synchronizer token. Cross-origin forged request successfully thwarted!"
        }
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(response_data), 403
        return render_template(
            "portal/csrf_result.html",
            result=response_data,
            variant="secure_blocked",
            user=get_user_by_id(session["user_id"])
        ), 403

    # Authorized state change
    new_pref = request.form.get("preference") or request.form.get("status") or ""
    if new_pref:
        update_user_preference(session["user_id"], new_pref)

    user_after = get_user_by_id(session["user_id"])

    response_data = {
        "variant": "secure",
        "action": "Authorized Notification Preference Update",
        "status_code": 200,
        "new_status": user_after["notification_pref"] if user_after else new_pref,
        "message": "Success: Notification preference updated securely via POST with valid CSRF synchronizer token."
    }

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(response_data)

    return redirect(url_for("profile_view"))
