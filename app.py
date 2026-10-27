"""
CampusConnect — Student Portal
Indian Institute of Information Technology, Allahabad (IIIT Allahabad)

Main Application Entry Point:
- Educational Cyber Security demonstration integrated seamlessly into an authentic college student portal.
- Integrates 4 vulnerabilities: SQLi (Login), Command Injection (Network Diagnostic), Reflected XSS (Notices Search), CSRF (Profile Update).
- Provides a discreet Demo Mode drawer for local presentation and viva defense.
"""

import os
import secrets
import hmac
import hashlib
import platform
import subprocess
import re
from markupsafe import Markup
from flask import (
    Flask, render_template, request, session, redirect,
    url_for, jsonify, abort, flash
)
from werkzeug.security import check_password_hash

from config import Config, is_local_dev
from database import init_db, get_db_connection
from modules.sqli import sqli_bp, VULNERABLE_CODE_SNIPPET as SQLI_VULN_SNIPPET, SECURE_CODE_SNIPPET as SQLI_SEC_SNIPPET
from modules.cmd_injection import cmd_bp, VULNERABLE_CODE_SNIPPET as CMD_VULN_SNIPPET, SECURE_CODE_SNIPPET as CMD_SEC_SNIPPET
from modules.xss import xss_bp, VULNERABLE_CODE_SNIPPET as XSS_VULN_SNIPPET, SECURE_CODE_SNIPPET as XSS_SEC_SNIPPET
from modules.csrf import csrf_bp, VULNERABLE_CODE_SNIPPET as CSRF_VULN_SNIPPET, SECURE_CODE_SNIPPET as CSRF_SEC_SNIPPET

IS_WINDOWS = platform.system().lower() == "windows"

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database if needed
    if not os.path.exists(app.config["DATABASE_PATH"]):
        with app.app_context():
            init_db()

    # Register blueprints for direct API/test compatibility
    app.register_blueprint(sqli_bp)
    app.register_blueprint(cmd_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(csrf_bp)

    @app.before_request
    def enforce_security_boundary():
        """Ensure loopback access only."""
        if not is_local_dev(request):
            return jsonify({
                "error": "Access Denied: CampusConnect lab endpoints are strictly restricted to local loopback."
            }), 403

    @app.context_processor
    def inject_portal_context():
        """Injects portal user details, CSRF token, and Demo Mode status into all templates."""
        user = None
        if "user_id" in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
            user = cursor.fetchone()
            conn.close()

        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)

        # Default Demo Mode is 'vulnerable' for controlled testing
        demo_mode = session.get("demo_mode", "vulnerable")

        return {
            "current_user": user,
            "csrf_token": session.get("csrf_token"),
            "demo_mode": demo_mode,
            "is_local": is_local_dev(request),
            "is_windows": IS_WINDOWS,
            "snippets": {
                "sqli_vuln": SQLI_VULN_SNIPPET,
                "sqli_sec": SQLI_SEC_SNIPPET,
                "cmd_vuln": CMD_VULN_SNIPPET,
                "cmd_sec": CMD_SEC_SNIPPET,
                "xss_vuln": XSS_VULN_SNIPPET,
                "xss_sec": XSS_SEC_SNIPPET,
                "csrf_vuln": CSRF_VULN_SNIPPET,
                "csrf_sec": CSRF_SEC_SNIPPET
            }
        }

    # =========================================================================
    # CORE STUDENT PORTAL ROUTES
    # =========================================================================

    @app.route("/")
    def index():
        """Root route: Redirects to dashboard if logged in, else to login page."""
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        Student Login Page.
        Integrates Module 1 (SQL Injection Authentication Bypass):
        - In 'vulnerable' mode: executes unsafe string concatenation query.
        - In 'secure' mode: executes parameterized prepared statement + PBKDF2 verification.
        """
        error = None
        demo_mode = session.get("demo_mode", "vulnerable")

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            conn = get_db_connection()
            cursor = conn.cursor()

            if demo_mode == "vulnerable":
                # INTENTIONALLY VULNERABLE STRING CONCATENATION (Password Hashes in DB):
                hashed_pw_attempt = hashlib.sha256(password.encode("utf-8")).hexdigest()
                query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{hashed_pw_attempt}'"
                try:
                    cursor.execute(query)
                    row = cursor.fetchone()
                    if row:
                        session["user_id"] = row["id"]
                        session["username"] = row["username"]
                        session["student_id"] = row["student_id"]
                        session["full_name"] = row["full_name"]
                        conn.close()
                        return redirect(url_for("dashboard"))
                    else:
                        error = "Invalid Student ID / Username or Password."
                except Exception as e:
                    error = f"Database Error: {str(e)}"
                conn.close()
            else:
                # SECURE FIX — PARAMETERIZED QUERY & CRYPTOGRAPHIC HASH:
                parameterized_query = "SELECT * FROM users WHERE username = ? OR student_id = ?"
                cursor.execute(parameterized_query, (username, username))
                row = cursor.fetchone()
                if row and (hmac.compare_digest(row["password_hash"], hashlib.sha256(password.encode("utf-8")).hexdigest()) or check_password_hash(row["password_hash"], password)):
                    session["user_id"] = row["id"]
                    session["username"] = row["username"]
                    session["student_id"] = row["student_id"]
                    session["full_name"] = row["full_name"]
                    conn.close()
                    return redirect(url_for("dashboard"))
                else:
                    error = "Invalid Student ID / Username or Password."
                conn.close()

        return render_template("portal/login.html", error=error)

    @app.route("/dashboard")
    def dashboard():
        """
        Student Dashboard:
        Displays student profile, academic metrics (CGPA, attendance), and recent notices.
        """
        # Auto-authenticate as Alice for quick demonstration if not logged in
        if "user_id" not in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'alice'")
            alice = cursor.fetchone()
            conn.close()
            if alice:
                session["user_id"] = alice["id"]
                session["username"] = alice["username"]
                session["student_id"] = alice["student_id"]
                session["full_name"] = alice["full_name"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notices ORDER BY id DESC LIMIT 3")
        recent_notices = cursor.fetchall()
        conn.close()

        return render_template("portal/dashboard.html", recent_notices=recent_notices)

    @app.route("/notices")
    def notices():
        """
        Campus Notices Bulletin Board.
        Integrates Module 3 (Reflected Cross-Site Scripting):
        - In 'vulnerable' mode: reflects search term using Markup() unescaped.
        - In 'secure' mode: reflects search term via Jinja2 auto-escaping (&lt;script&gt;).
        """
        query = request.args.get("q", "")
        demo_mode = session.get("demo_mode", "vulnerable")

        conn = get_db_connection()
        cursor = conn.cursor()
        if query:
            cursor.execute("""
                SELECT * FROM notices 
                WHERE title LIKE ? OR category LIKE ? OR content LIKE ?
                ORDER BY id DESC
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
        else:
            cursor.execute("SELECT * FROM notices ORDER BY id DESC")
        notices_list = cursor.fetchall()
        conn.close()

        rendered_query = Markup(query) if demo_mode == "vulnerable" else query

        return render_template(
            "portal/notices.html",
            notices=notices_list,
            raw_query=query,
            rendered_query=rendered_query,
            mode=demo_mode
        )

    @app.route("/support", methods=["GET", "POST"])
    def support():
        """
        Help & Support / IT Helpdesk.
        Integrates Module 2 (OS Command Injection):
        - Network connectivity ping diagnostic tool.
        - In 'vulnerable' mode: shell=True evaluates chained metacharacters (&, ;).
        - In 'secure' mode: regex allow-list ^[a-zA-Z0-9.-]+$ and shell=False.
        """
        diagnostic_result = None
        demo_mode = session.get("demo_mode", "vulnerable")

        if request.method == "POST":
            target = request.form.get("target", "").strip()

            if demo_mode == "vulnerable":
                # INTENTIONALLY VULNERABLE: shell=True
                raw_cmd = f"ping -n 1 {target}" if IS_WINDOWS else f"ping -c 1 {target}"
                output = ""
                injected = False
                try:
                    proc = subprocess.run(raw_cmd, shell=True, capture_output=True, text=True, timeout=5)
                    output = proc.stdout + (("\nSTDERR:\n" + proc.stderr) if proc.stderr else "")
                    if any(marker in output for marker in ["[LAB-PROOF", "whoami", "Windows IP Configuration", "Directory of"]):
                        injected = True
                    elif IS_WINDOWS and ("\\" in output or "nt authority" in output.lower()):
                        injected = True
                except subprocess.TimeoutExpired:
                    output = "Diagnostic timed out after 5 seconds."
                except Exception as e:
                    output = f"Execution error: {str(e)}"

                diagnostic_result = {
                    "variant": "vulnerable",
                    "target": target,
                    "command": raw_cmd,
                    "output": output,
                    "injected": injected,
                    "success": True
                }
            else:
                # SECURE FIX: Allow-list + shell=False
                HOSTNAME_REGEX = r"^[a-zA-Z0-9.-]+$"
                if not re.match(HOSTNAME_REGEX, target):
                    diagnostic_result = {
                        "variant": "secure",
                        "target": target,
                        "validation_rejected": True,
                        "output": "Security Filter Blocked Input: Target contains illegal characters. Only clean hostnames and IP addresses are permitted.",
                        "command": "Execution aborted by security filter",
                        "injected": False,
                        "success": False
                    }
                else:
                    cmd_args = ["ping", "-n", "1", target] if IS_WINDOWS else ["ping", "-c", "1", target]
                    try:
                        proc = subprocess.run(cmd_args, shell=False, capture_output=True, text=True, timeout=3)
                        output = proc.stdout + (("\nSTDERR:\n" + proc.stderr) if proc.stderr else "")
                    except subprocess.TimeoutExpired:
                        output = "Diagnostic timed out after 3 seconds."
                    except Exception as e:
                        output = f"Execution error: {str(e)}"

                    diagnostic_result = {
                        "variant": "secure",
                        "target": target,
                        "command": " ".join(cmd_args) + " [Invoked directly without shell]",
                        "output": output,
                        "injected": False,
                        "validation_rejected": False,
                        "success": True
                    }

        return render_template(
            "portal/support.html",
            diagnostic_result=diagnostic_result,
            mode=demo_mode
        )

    @app.route("/profile")
    def profile_view():
        """
        My Profile Page.
        Displays student details and editable notification preference.
        """
        if "user_id" not in session:
            return redirect(url_for("login"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        user = cursor.fetchone()
        conn.close()

        return render_template("portal/profile.html", user=user)

    @app.route("/profile/update-preference", methods=["GET", "POST"])
    def update_preference():
        """
        Reconciled CSRF Demonstration Endpoint.
        - In 'vulnerable' mode: updates preference on HTTP GET with ambient session cookies.
        - In 'secure' mode: rejects GET with 405 Method Not Allowed; enforces POST with valid CSRF token.
        """
        demo_mode = session.get("demo_mode", "vulnerable")

        if "user_id" not in session:
            return jsonify({"error": "Unauthorized: Student is not logged in."}), 401

        # SECURE MODE ENFORCEMENT
        if demo_mode == "secure":
            if request.method == "GET":
                response_data = {
                    "variant": "secure",
                    "status_code": 405,
                    "action": "Blocked State-Changing GET Request",
                    "error": "HTTP 405 Method Not Allowed: State-changing operations are strictly forbidden on HTTP GET. Use POST with a valid CSRF token."
                }
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify(response_data), 405
                return render_template("portal/csrf_result.html", result=response_data, variant="secure_blocked"), 405

            # Validate CSRF Token on POST
            submitted_token = request.form.get("csrf_token", "")
            expected_token = session.get("csrf_token", "")
            if not expected_token or not submitted_token or not hmac.compare_digest(submitted_token, expected_token):
                response_data = {
                    "variant": "secure",
                    "status_code": 403,
                    "action": "CSRF Attack Blocked",
                    "error": "HTTP 403 Forbidden: Invalid or missing CSRF synchronizer token. Forged cross-site request intercepted!"
                }
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify(response_data), 403
                return render_template("portal/csrf_result.html", result=response_data, variant="secure_blocked"), 403

            # Authorized POST update
            new_pref = request.form.get("preference", "").strip()
            if new_pref:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET notification_pref = ? WHERE id = ?", (new_pref, session["user_id"]))
                conn.commit()
                conn.close()

            return redirect(url_for("profile_view"))

        else:
            # VULNERABLE MODE: Permits state change via HTTP GET without CSRF token!
            new_pref = request.args.get("preference") or request.form.get("preference") or "Updated via Unsafe GET"
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT notification_pref, full_name, username FROM users WHERE id = ?", (session["user_id"],))
            user_before = cursor.fetchone()
            prev_pref = user_before["notification_pref"] if user_before else "Unknown"

            cursor.execute("UPDATE users SET notification_pref = ? WHERE id = ?", (new_pref, session["user_id"]))
            conn.commit()
            conn.close()

            response_data = {
                "variant": "vulnerable",
                "action": "Notification Preference Updated via GET (CSRF Vulnerable)",
                "victim_username": user_before["username"] if user_before else session.get("username"),
                "victim_name": user_before["full_name"] if user_before else "Student",
                "previous_status": prev_pref,
                "new_status": new_pref,
                "forged_request_successful": True,
                "message": f"CRITICAL: Student preference changed to '{new_pref}' without CSRF token validation!"
            }

            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(response_data)

            return render_template("portal/csrf_result.html", result=response_data, variant="vulnerable")

    @app.route("/demo/set-mode", methods=["POST"])
    def set_demo_mode():
        """AJAX endpoint to switch Demo Mode between 'vulnerable' and 'secure'."""
        if not is_local_dev(request):
            abort(403)
        data = request.get_json() or {}
        mode = data.get("mode", "vulnerable")
        if mode in ("vulnerable", "secure"):
            session["demo_mode"] = mode
            return jsonify({"success": True, "mode": mode})
        return jsonify({"success": False, "error": "Invalid mode"}), 400

    @app.route("/logout")
    def logout():
        """Clears session and redirects to login."""
        session.clear()
        return redirect(url_for("login"))

    @app.route("/api/reset-lab", methods=["POST"])
    def reset_lab():
        """Resets the SQLite database to seeded baseline state."""
        if not is_local_dev(request):
            abort(403)
        init_db(force_reset=True)
        return jsonify({"success": True, "message": "Database successfully reset to initial seeded records."})

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("portal/error.html", code=404, message="The requested portal page was not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("portal/error.html", code=500, message="An internal server error occurred."), 500

    return app

if __name__ == "__main__":
    app = create_app()
    print("=" * 70)
    print("  CAMPUSCONNECT — STUDENT PORTAL (IIIT ALLAHABAD)")
    print("  Cyber Security Assignment Redesign")
    print(f"  Target Server: http://{Config.TARGET_HOST}:{Config.TARGET_PORT}")
    print("=" * 70)
    app.run(host=Config.TARGET_HOST, port=Config.TARGET_PORT, debug=True)
