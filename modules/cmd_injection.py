"""
Module 2: OS Command Injection — In-band Command Injection
CampusConnect — Student Portal (IIIT Allahabad)

Demonstrates:
- Campus IT Helpdesk network connectivity diagnostic tool (ping utility).
- Vulnerable diagnostic tool executing shell commands with unsanitized user input (shell=True).
- Platform-appropriate harmless test payloads (Windows & Linux).
- Secure mitigation via strict allow-list input validation, argument vector execution (shell=False), and timeouts.
"""

import os
import platform
import subprocess
import re
from flask import Blueprint, render_template, request, jsonify, abort
from config import is_local_dev

cmd_bp = Blueprint("cmd", __name__, url_prefix="/cmd")

IS_WINDOWS = platform.system().lower() == "windows"

# ============================================================================
# EXPLANATION & ROOT CAUSE SNIPPETS (For Demo Mode drawer & Viva)
# ============================================================================
VULNERABLE_CODE_SNIPPET = '''# INTENTIONALLY VULNERABLE — LOCAL LAB ONLY
# Root Cause: shell=True invokes cmd.exe / /bin/sh which evaluates metacharacters (&, ;, |)
command = f"ping -n 1 {target}" if is_windows else f"ping -c 1 {target}"
output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)'''

SECURE_CODE_SNIPPET = '''# SECURE FIX — STRICT ALLOW-LIST & ARGUMENT VECTOR (shell=False)
# 1. Strict allow-list regex restricts input to valid IPv4 / hostnames
if not re.match(r"^[a-zA-Z0-9.-]+$", target):
    raise ValueError("Invalid target format. Shell metacharacters are strictly forbidden.")

# 2. Argument vector execution directly invokes the binary without any shell
ping_args = ["ping", "-n", "1", target] if is_windows else ["ping", "-c", "1", target]
output = subprocess.run(ping_args, shell=False, capture_output=True, text=True, timeout=3)'''


# ============================================================================
# 1. INTENTIONALLY VULNERABLE DIAGNOSTIC HANDLER
# ============================================================================
@cmd_bp.route("/vulnerable/diagnose", methods=["POST"])
def vulnerable_diagnose():
    """
    INTENTIONALLY VULNERABLE — LOCAL LAB ONLY:
    Campus network diagnostic utility executing ping with shell=True.
    Metacharacters like `&` or `;` execute chained commands in-band.
    """
    if not is_local_dev(request):
        abort(403, description="Access Denied: Vulnerable endpoints restricted to local development.")

    target = request.form.get("target", "").strip()
    
    if not target:
        result = {"success": False, "output": "Please enter a target host or IP.", "injected": False}
        return jsonify(result)

    if IS_WINDOWS:
        raw_cmd = f"ping -n 1 {target}"
    else:
        raw_cmd = f"ping -c 1 {target}"

    executed_command = raw_cmd
    output = ""
    injected_detected = False

    try:
        proc = subprocess.run(
            raw_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = proc.stdout + (("\nSTDERR:\n" + proc.stderr) if proc.stderr else "")
        
        # Check if proof or chained command executed
        if any(marker in output for marker in ["[LAB-PROOF", "whoami", "Windows IP Configuration", "Directory of"]):
            injected_detected = True
        elif IS_WINDOWS and ("\\" in output or "nt authority" in output.lower()):
            injected_detected = True

    except subprocess.TimeoutExpired:
        output = "Diagnostic ping timed out after 5 seconds."
    except Exception as e:
        output = f"Execution error: {str(e)}"

    result = {
        "variant": "vulnerable",
        "target_input": target,
        "executed_command": executed_command,
        "output": output,
        "injected_detected": injected_detected,
        "success": True
    }

    return jsonify(result)


# ============================================================================
# 2. SECURE MITIGATED DIAGNOSTIC HANDLER
# ============================================================================
@cmd_bp.route("/secure/diagnose", methods=["POST"])
def secure_diagnose():
    """
    SECURE FIX — AVOIDING SHELL & STRICT ALLOW-LIST VALIDATION:
    1. Input Validation: Enforces strict allow-list regex matching standard IPv4 or hostnames.
    2. Argument Vector Execution: subprocess.run(..., shell=False).
    3. Safe Timeout: 3-second hard timeout.
    """
    target = request.form.get("target", "").strip()
    
    HOSTNAME_REGEX = r"^[a-zA-Z0-9.-]+$"
    is_valid = bool(re.match(HOSTNAME_REGEX, target))
    output = ""

    if not is_valid:
        rejection_reason = (
            "Security Validation Filter Blocked Input: "
            "Input contains illegal characters or shell metacharacters. "
            "Only clean hostnames and IP addresses matching ^[a-zA-Z0-9.-]+$ are permitted."
        )
        result = {
            "variant": "secure",
            "target_input": target,
            "validation_rejected": True,
            "rejection_reason": rejection_reason,
            "executed_command": "None (Execution aborted by defense filter)",
            "output": rejection_reason,
            "injected_detected": False,
            "success": False
        }
    else:
        if IS_WINDOWS:
            cmd_args = ["ping", "-n", "1", target]
        else:
            cmd_args = ["ping", "-c", "1", target]

        try:
            proc = subprocess.run(
                cmd_args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=3
            )
            output = proc.stdout + (("\nSTDERR:\n" + proc.stderr) if proc.stderr else "")
        except subprocess.TimeoutExpired:
            output = "Ping request timed out after 3 seconds."
        except Exception as e:
            output = f"Execution error: {str(e)}"

        result = {
            "variant": "secure",
            "target_input": target,
            "validation_rejected": False,
            "executed_command": " ".join(cmd_args) + " [Invoked directly via execve/CreateProcess without shell]",
            "output": output,
            "injected_detected": False,
            "success": True
        }

    return jsonify(result)
