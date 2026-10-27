"""
Database initialization and seeding module for CampusConnect — Student Portal.
IIIT Allahabad — Cyber Security Assignment

Note on Security Architecture:
- Schema stores ONLY cryptographic password hashes (PBKDF2/SHA-256 via Werkzeug).
- NO password_plain column exists in the database.
- Fictional student records only.
"""
import sqlite3
import os
import hashlib
from config import Config

def hash_pw(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def get_db_connection():
    """Returns a connection to the SQLite database with row access by column name."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(force_reset=False):
    """
    Initializes the database schema and seeds realistic dummy student accounts and notices.
    If force_reset is True, existing tables are dropped and reseeded.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if force_reset:
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS notices")

    # Users Table — Stores password hashes only (zero plaintext passwords)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            semester TEXT NOT NULL,
            cgpa TEXT NOT NULL DEFAULT '8.75',
            attendance TEXT NOT NULL DEFAULT '88%',
            notification_pref TEXT NOT NULL DEFAULT 'Email & Portal Alerts'
        )
    """)

    # Notices Table — College Announcements for the Notices board
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            date_posted TEXT NOT NULL,
            author TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)

    # Check if user data exists
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] == 0:
        # Seed realistic dummy accounts
        dummy_users = [
            (
                "S2023-042",
                "alice",
                hash_pw("Alice#Pass2026"),
                "Alice Sharma",
                "alice.sharma@iiita.ac.in",
                "Student",
                "Computer Science & Engineering",
                "VI Semester",
                "8.92",
                "91%",
                "Email & Portal Alerts"
            ),
            (
                "S2023-118",
                "bob",
                hash_pw("Bob$Project99"),
                "Bob Verma",
                "bob.verma@iiita.ac.in",
                "Student",
                "Information Technology",
                "IV Semester",
                "8.45",
                "85%",
                "SMS Alerts Only"
            ),
            (
                "FAC-001",
                "admin",
                hash_pw("Admin@123_Secure!"),
                "Dr. Admin Prasad",
                "admin.prasad@iiita.ac.in",
                "Faculty Administrator",
                "Department of Cyber Security & Computing",
                "Faculty Staff",
                "N/A",
                "100%",
                "Immediate Email Notifications"
            )
        ]
        
        cursor.executemany("""
            INSERT INTO users (
                student_id, username, password_hash, full_name, email,
                role, department, semester, cgpa, attendance, notification_pref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, dummy_users)

    # Check if notice data exists
    cursor.execute("SELECT COUNT(*) as count FROM notices")
    if cursor.fetchone()["count"] == 0:
        dummy_notices = [
            (
                "End-Semester Examination Schedule Announced (May 2026)",
                "Academics",
                "2026-05-02",
                "Office of the Dean (Academic Affairs)",
                "The finalized timetable for the Spring Semester End-Term Examinations has been published. Theory exams will commence from May 18, 2026. Hall tickets will be available for download from the portal starting May 10."
            ),
            (
                "Smart India Hackathon (SIH 2026) — Campus Internal Hackathon",
                "Events",
                "2026-04-28",
                "Tech Club & Student Innovation Cell",
                "Registrations are now open for teams of 6 students to participate in the Internal Hackathon for SIH 2026 nominations. Domains include Smart Automation, Cybersecurity, and Healthcare Informatics. Register by May 8."
            ),
            (
                "Central Library Extended 24x7 Reading Room Hours",
                "Campus Services",
                "2026-04-25",
                "Chief Librarian",
                "In view of upcoming practical assessments and end-semester evaluations, the Central Library reading halls on the 1st and 2nd floors will remain open 24 hours a day until June 5, 2026."
            ),
            (
                "Hostel High-Speed Wi-Fi & Gateway Maintenance Downtime",
                "IT Infrastructure",
                "2026-04-20",
                "Computer Center (CC-3)",
                "Scheduled maintenance of core network distribution switches and intranet firewall nodes will take place on Saturday from 02:00 AM to 05:00 AM. Intermittent connectivity to the 10.0.0.0/8 intranet is expected."
            ),
            (
                "Annual Technical Symposium 'Aparoksha 2026' Results Declared",
                "Cultural & Technical",
                "2026-04-15",
                "Student Gymkhana Council",
                "Congratulations to all prize winners across algorithmic competitive programming, web development, capture-the-flag (CTF), and robotic competitions. Certificates can be collected from SAC office."
            )
        ]
        cursor.executemany("""
            INSERT INTO notices (title, category, date_posted, author, content)
            VALUES (?, ?, ?, ?, ?)
        """, dummy_notices)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    print("[*] Initializing SQLite database with password-hash-only schema...")
    init_db(force_reset=True)
    print(f"[+] Database successfully initialized at: {Config.DATABASE_PATH}")
