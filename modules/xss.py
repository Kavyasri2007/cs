"""
Module 3: Reflected Cross-Site Scripting (XSS)
CampusConnect — Student Portal (IIIT Allahabad)

Demonstrates:
- Campus Notices search board reflecting untrusted search queries.
- Vulnerable mode: Reflects unescaped input using Markup(), executing benign JavaScript.
- Strict requirement: ZERO cookie extraction or session hijacking payloads.
- Secure mode: Jinja2 automatic context-aware HTML entity escaping (&lt;script&gt;).
"""

from flask import Blueprint, render_template, request, jsonify, abort
from markupsafe import Markup
from database import get_db_connection
from config import is_local_dev

xss_bp = Blueprint("xss", __name__, url_prefix="/xss")

# ============================================================================
# EXPLANATION & ROOT CAUSE SNIPPETS (For Demo Mode drawer & Viva)
# ============================================================================
VULNERABLE_CODE_SNIPPET = '''# INTENTIONALLY VULNERABLE — LOCAL LAB ONLY
# Root Cause: Disabling framework escaping using Markup() reflects raw HTML/JS into the response
raw_query = request.args.get("q", "")
return render_template("portal/notices.html", query=Markup(raw_query), mode="vulnerable")'''

SECURE_CODE_SNIPPET = '''# SECURE FIX — CONTEXT-AWARE AUTO-ESCAPING
# Fix: Native Jinja2 auto-escaping converts characters (< -> &lt;, > -> &gt;)
safe_query = request.args.get("q", "")
return render_template("portal/notices.html", query=safe_query, mode="secure")'''


def search_notices(query_str):
    """Searches notices table in SQLite by title, category, or content."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if query_str:
        cursor.execute("""
            SELECT * FROM notices 
            WHERE title LIKE ? OR category LIKE ? OR content LIKE ?
            ORDER BY id DESC
        """, (f"%{query_str}%", f"%{query_str}%", f"%{query_str}%"))
    else:
        cursor.execute("SELECT * FROM notices ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ============================================================================
# 1. INTENTIONALLY VULNERABLE SEARCH HANDLER
# ============================================================================
@xss_bp.route("/vulnerable/search", methods=["GET"])
def vulnerable_search():
    """
    INTENTIONALLY VULNERABLE — LOCAL LAB ONLY:
    Renders untrusted search input directly into the HTML response using Markup().
    """
    if not is_local_dev(request):
        abort(403, description="Access Denied: Vulnerable endpoints restricted to local development.")

    query = request.args.get("q", "")
    notices = search_notices(query)

    # Render through portal notices template
    return render_template(
        "portal/notices.html",
        rendered_query=Markup(query),
        raw_query=query,
        notices=notices,
        mode="vulnerable",
        vulnerable_code=VULNERABLE_CODE_SNIPPET,
        secure_code=SECURE_CODE_SNIPPET
    )


# ============================================================================
# 2. SECURE MITIGATED SEARCH HANDLER
# ============================================================================
@xss_bp.route("/secure/search", methods=["GET"])
def secure_search():
    """
    SECURE FIX — CONTEXT-AWARE AUTO-ESCAPING:
    Preserves default Jinja2 auto-escaping. Special characters are converted to entities.
    """
    query = request.args.get("q", "")
    notices = search_notices(query)

    return render_template(
        "portal/notices.html",
        rendered_query=query,  # Auto-escaped by Jinja2
        raw_query=query,
        notices=notices,
        mode="secure",
        vulnerable_code=VULNERABLE_CODE_SNIPPET,
        secure_code=SECURE_CODE_SNIPPET
    )
