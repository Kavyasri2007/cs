"""
Module 1: SQL Injection (SQLi) — Authentication Bypass
CampusConnect — Student Portal (IIIT Allahabad)

Demonstrates:
- Vulnerable authentication via unsafe SQL query string concatenation.
- Harmless exploit payload bypassing credentials: ' OR '1'='1' -- (or admin' --).
- Database stores password hashes only (zero password_plain column).
- Secure authentication via parameterised queries and Werkzeug password hash verification.
"""

import hashlib
import hmac
from flask import Blueprint, render_template, request, jsonify, session, abort
from werkzeug.security import check_password_hash
from database import get_db_connection
from config import is_local_dev

sqli_bp = Blueprint("sqli", __name__, url_prefix="/sqli")

# ============================================================================
# EXPLANATION & ROOT CAUSE SNIPPETS (For Demo Mode drawer & Viva)
# ============================================================================
VULNERABLE_CODE_SNIPPET = '''# INTENTIONALLY VULNERABLE — LOCAL LAB ONLY (Password Hashes Only in DB)
# Root Cause: Direct string concatenation allows comment tokens (--) or tautologies (OR 1=1)
# to alter the query logic and bypass the password hash constraint entirely.
hashed_pw_attempt = hashlib.sha256(password.encode()).hexdigest()
query = f"SELECT * FROM users WHERE (username = '{username}' OR student_id = '{username}') AND password_hash = '{hashed_pw_attempt}'"
cursor.execute(query)
row = cursor.fetchone()  # Bypassed! Row returned without valid password'''

SECURE_CODE_SNIPPET = '''# SECURE FIX — PARAMETERISED PREPARED STATEMENT & HASH VERIFICATION
# Fix: Query structure is pre-compiled with place holders (?). Input is treated strictly as data.
cursor.execute("SELECT * FROM users WHERE username = ? OR student_id = ?", (username, username))
user = cursor.fetchone()
if user and check_password_hash(user["password_hash"], password):
    # Legitimate login verified via cryptographic hash
    pass'''


# ============================================================================
# 1. INTENTIONALLY VULNERABLE AUTHENTICATION HANDLER
# ============================================================================
@sqli_bp.route("/vulnerable/login", methods=["POST"])
def vulnerable_login():
    """
    INTENTIONALLY VULNERABLE — LOCAL LAB ONLY:
    Demonstrates SQL injection authentication bypass on a modern database schema
    storing password hashes only.
    
    The developer attempted to authenticate directly inside SQL using string concatenation:
    `WHERE (username = '{username}' ...) AND password_hash = '...'`
    When an attacker supplies `' OR '1'='1' --` or `admin' --`, the comment operator (`--`)
    truncates the query, instructing SQLite to ignore the password condition completely.
    """
    if not is_local_dev(request):
        abort(403, description="Access Denied: Vulnerable endpoints restricted to local development.")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    # INTENTIONALLY VULNERABLE STRING CONCATENATION:
    hashed_pw_attempt = hashlib.sha256(password.encode("utf-8")).hexdigest()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{hashed_pw_attempt}'"

    executed_query = query
    conn = get_db_connection()
    cursor = conn.cursor()
    
    auth_success = False
    user_info = None
    error_message = None

    try:
        cursor.execute(query)
        row = cursor.fetchone()
        if row:
            auth_success = True
            user_info = {
                "id": row["id"],
                "student_id": row["student_id"],
                "username": row["username"],
                "full_name": row["full_name"],
                "email": row["email"],
                "role": row["role"],
                "department": row["department"],
                "semester": row["semester"],
                "notification_pref": row["notification_pref"],
                "profile_status": row["notification_pref"]  # Alias for backward compatibility
            }
            # Populate session for portal navigation
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["student_id"] = row["student_id"]
            session["full_name"] = row["full_name"]
            session["role"] = row["role"]
        else:
            error_message = "Authentication Failed: Invalid student ID or password."
    except Exception as e:
        error_message = f"Database Error: {str(e)}"
    finally:
        conn.close()

    result = {
        "variant": "vulnerable",
        "auth_success": auth_success,
        "username_input": username,
        "password_input": password,
        "executed_query": executed_query,
        "user_info": user_info,
        "error_message": error_message
    }

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result)

    return jsonify(result)


# ============================================================================
# 2. SECURE MITIGATED AUTHENTICATION HANDLER
# ============================================================================
@sqli_bp.route("/secure/login", methods=["POST"])
def secure_login():
    """
    SECURE FIX — PARAMETERISED QUERY & HASH VERIFICATION:
    1. Uses parameterized query with (?) placeholders. User input is treated strictly as a data literal.
    2. Verifies password hash using PBKDF2/SHA-256 via Werkzeug check_password_hash.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    parameterized_query = """
        SELECT id, student_id, username, password_hash, full_name, email,
               role, department, semester, cgpa, attendance, notification_pref
        FROM users WHERE username = ? OR student_id = ?
    """
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    auth_success = False
    user_info = None
    error_message = None

    try:
        cursor.execute(parameterized_query, (username, username))
        row = cursor.fetchone()
        
        # Verify user exists and check cryptographic password hash
        if row and (hmac.compare_digest(row["password_hash"], hashlib.sha256(password.encode("utf-8")).hexdigest()) or check_password_hash(row["password_hash"], password)):
            auth_success = True
            user_info = {
                "id": row["id"],
                "student_id": row["student_id"],
                "username": row["username"],
                "full_name": row["full_name"],
                "email": row["email"],
                "role": row["role"],
                "department": row["department"],
                "semester": row["semester"],
                "notification_pref": row["notification_pref"],
                "profile_status": row["notification_pref"]
            }
            # Populate session
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["student_id"] = row["student_id"]
            session["full_name"] = row["full_name"]
            session["role"] = row["role"]
        else:
            error_message = "Authentication Failed: Invalid username or password."
    except Exception as e:
        error_message = "An error occurred during authentication. Please check your credentials."
    finally:
        conn.close()

    result = {
        "variant": "secure",
        "auth_success": auth_success,
        "username_input": username,
        "password_input": password,
        "executed_query": parameterized_query + " (bound parameter: " + repr(username) + ")",
        "user_info": user_info,
        "error_message": error_message
    }

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result)

    return jsonify(result)
