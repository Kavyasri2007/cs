"""
Configuration for CampusConnect — Student Portal
IIIT Allahabad — Cyber Security Assignment

Enforces strict local-only loopback binding and production safeguards.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("PORTAL_SECRET_KEY", "campusconnect-iiita-student-portal-2026-secret")
    DATABASE_PATH = os.path.join(BASE_DIR, "lab_database.db")
    
    # Server binding (strictly loopback)
    TARGET_HOST = "127.0.0.1"
    TARGET_PORT = 5000
    
    ATTACKER_HOST = "127.0.0.1"
    ATTACKER_PORT = 5001
    
    # Session Cookie Configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Local HTTP development
    SESSION_COOKIE_NAME = "campusconnect_session"

def is_local_dev(req):
    """
    SAFETY GUARD:
    Verifies that the request originates from a local loopback interface
    and that production environment flags are NOT set.
    Vulnerable endpoints and Demo Mode controls are strictly forbidden if this returns False.
    """
    if os.environ.get("FLASK_ENV") == "production" or os.environ.get("PRODUCTION") is not None:
        return False
    remote = req.remote_addr
    return remote in ("127.0.0.1", "::1", "localhost")
