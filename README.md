# CampusConnect — Student Portal
**Indian Institute of Information Technology, Allahabad (IIIT Allahabad)**  
*Cyber Security Educational Lab & Student Portal Redesign*

> ⚠️ **ISOLATED EDUCATIONAL LAB WARNING:**  
> This project contains intentionally vulnerable implementations designed exclusively for controlled local academic evaluation, laboratory demonstration, and viva examinations at IIIT Allahabad. All demonstration endpoints are strictly guarded and bound to the loopback interface (`127.0.0.1`). These vulnerable handlers must **never** be enabled in production environments or exposed to public networks.

---

## 1. Project Overview & Architecture

**CampusConnect** is designed to look, feel, and behave like an ordinary, authentic college student portal (styled in institutional navy blue `#1e3a8a`, crisp white, and light slate `#f8fafc`). Beneath its realistic academic workflows, it incorporates controlled demonstrations of four critical web security vulnerabilities and their corresponding defenses:

1. **SQL Injection (SQLi) — Authentication Bypass** on the Student Login Page
2. **OS Command Injection (In-band)** in the Campus Network Diagnostic Utility
3. **Reflected Cross-Site Scripting (XSS)** on the Campus Notices Bulletin Board
4. **Cross-Site Request Forgery (CSRF) — GET-based Forged Action** on Student Notification Preferences

### System Architecture
The application runs as a lightweight Python Flask service backed by SQLite, featuring two local server origins for realistic cross-site testing:
- **CampusConnect Student Portal (`http://127.0.0.1:5000`)**: The primary institutional website hosting the student dashboard, notices, IT helpdesk, profile management, and side-by-side vulnerable/secure handlers.
- **External Phishing / Attacker Site (`http://localhost:5001`)**: A simulated untrusted external website (*"Campus Cafeteria 50% Off Voucher"*) designed to demonstrate cross-origin CSRF attacks against authenticated students.

---

## 2. Student Ownership Declaration Table

| Member Name | Roll Number | Vulnerability Category | Integrated Feature | Demonstration Focus |
|---|---|---|---|---|
| **Student 1 (Lead)** | `LIT2023xxx` | SQL Injection (SQLi) | Student Portal Login (`/login`) | Unsafe string concatenation vs Parameterised Prepared Statements |
| **Student 2** | `LIT2023xxx` | OS Command Injection | Helpdesk Network Diagnostic (`/support`) | Shell metacharacter chaining (`&`, `;`) vs Regex Allow-List & `shell=False` |
| **Student 3** | `LIT2023xxx` | Cross-Site Scripting (XSS) | Campus Notices Search (`/notices`) | Parser context breakout vs Context-Aware Jinja2 HTML Entity Escaping |
| **Student 4** | `LIT2023xxx` | Cross-Site Request Forgery | Profile Preferences (`/profile`) | Ambient credentials, `SameSite=Lax` top-level GET vs Synchronizer CSRF Token |

---

## 3. Student Portal Pages & User Flows

### A. Student Login (`/login`)
- **Appearance:** A clean institutional sign-in card with CampusConnect branding, Student ID or Username, Password, and a "Sign In" button.
- **Normal Flow:** Valid students (e.g. `alice` / `Alice#Pass2026`) log in and are routed to their personalized dashboard.
- **Security Integration (SQLi):**
  - *Vulnerable Mode:* An attacker inputs `admin' --` or `' OR '1'='1' --`. The comment token `--` comments out the password constraint in the query, authenticating the user as `admin` (`Dr. Admin Prasad`).
  - *Secure Mode:* Parameterized prepared statements treat the payload strictly as a literal text string. Authentication fails.
  - *Hash-Only Security:* The database stores **only password hashes** (zero plaintext passwords).

### B. Student Dashboard (`/dashboard`)
- **Appearance:** Displays a personalized student greeting (*"Welcome back, Alice Sharma!"*), enrollment details (`S2023-042`, B.Tech CSE, Semester VI), and academic KPI cards (CGPA: `8.92`, Biometric Attendance: `91%`, Registered Credits: `21`).
- **Functionality:** Features a recent notices preview widget and quick navigation links to Notices, Help & Support, and My Profile.

### C. Campus Notices Bulletin Board (`/notices`)
- **Appearance:** Displays official campus announcements (exam timetables, Smart India Hackathon, library hours, hostel maintenance) with a search filter.
- **Normal Flow:** Entering keywords filters circulars by title, category, and text content.
- **Security Integration (Reflected XSS):**
  - *Vulnerable Mode:* Search terms are reflected directly into the response using `Markup()`, executing script payloads (e.g., `<script>alert(...)` or visible DOM proof).
  - *Secure Mode:* Native Jinja2 auto-escaping encodes `<` to `&lt;` and `>` to `&gt;`, displaying input inertly as plain text glyphs.
  - *Ethical Safety:* Strictly zero cookie access or credential theft payloads.

### D. Help & Support / IT Helpdesk (`/support`)
- **Appearance:** Contains an IT Helpdesk support ticket submission form alongside a **Campus Network Connectivity Diagnostic Tool**.
- **Normal Flow:** Students enter a host or IP address (e.g. `127.0.0.1` or `gateway.iiita.ac.in`) to check ICMP connectivity and ping latency to the campus intranet.
- **Security Integration (OS Command Injection):**
  - *Vulnerable Mode:* Invokes the shell (`shell=True`). Supplying `127.0.0.1 & echo [CAMPUS-IT-PROOF] & whoami` executes the chained commands and returns the output in-band inside the terminal window.
  - *Secure Mode:* Enforces an allow-list regex (`^[a-zA-Z0-9.-]+$`) and runs directly via `subprocess.run(shell=False)` with argument vectors.

### E. My Profile (`/profile`)
- **Appearance:** Displays academic registration information, institutional advisor details, and editable **Campus Notification & Alert Preferences** (*Email & Portal Alerts*, *SMS Alerts Only*, *Emergency Broadcasts Only*).
- **Security Integration (CSRF):**
  - *Vulnerable Mode:* Uses state-changing HTTP `GET /profile/update-preference?preference=...`. An external attacker page on `http://localhost:5001` triggers a top-level GET navigation that carries the student's `SameSite=Lax` cookies and forges their preference without consent.
  - *Secure Mode:* Rejects GET with `HTTP 405 Method Not Allowed`. Requires HTTP `POST` with a cryptographically verified synchronizer `csrf_token`.

---

## 4. Discreet "Demo Mode" Presentation Drawer

To keep the student portal authentic while providing full control during your viva presentation:
- A small floating button in the bottom-right corner: **`🛠️ Demo Mode`** (only active on local development / loopback).
- Clicking it opens a slide-over control drawer:
  1. **Security Mode Toggle:** Instantly switch between `🔴 Intentionally Vulnerable` and `🟢 Secure Mitigated`.
  2. **1-Click Test Payloads:** Pre-fills input fields on the current page with documented harmless exploit inputs.
  3. **Vulnerability Mechanics & Mitigations:** Displays root causes, code excerpts, and before-and-after expected results.
  4. **Attacker Server Shortcut:** Direct link to launch the cross-origin attack from `http://localhost:5001`.
  5. **Database Reset Button:** 1-click restore of the SQLite database to its seeded state.

---

## 5. Installation & Execution Guide (Windows PowerShell)

### Step 1: Open PowerShell in Project Directory
```powershell
cd c:\Users\kavya\Desktop\cs_last_assignment
```

### Step 2: Set Up Virtual Environment & Dependencies
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 3: Initialize Database (Password Hashes Only)
```powershell
python database.py
```
*Seeds dummy accounts: `alice` (`Alice#Pass2026`), `bob` (`Bob$Project99`), and `admin` (`Admin@123_Secure!`).*

### Step 4: Start the Servers
Open two separate PowerShell terminal tabs:

**Terminal 1 (CampusConnect Student Portal):**
```powershell
python app.py
```
*Access in browser at **`http://127.0.0.1:5000`**.*

**Terminal 2 (Simulated Attacker Phishing Page):**
```powershell
python attacker_server.py
```
*Access in browser at **`http://localhost:5001`**.*

---

## 6. Demonstration Checklist for Viva

### 1. SQL Injection Authentication Bypass (Login Page)
1. Navigate to `http://127.0.0.1:5000/login`.
2. Open **Demo Mode** drawer (bottom-right) and ensure mode is set to **🔴 Intentionally Vulnerable**.
3. Click **Payload: `admin' --`** (or `' OR '1'='1' --`) and click **Sign In**.
4. **Observed Result:** Successfully bypasses authentication and logs into the portal as `Dr. Admin Prasad` without a valid password!
5. In Demo Mode, toggle to **🟢 Secure Mitigated**. Submit the same payload again.
6. **Observed Result:** Rejected with `Invalid Student ID / Username or Password`.
7. Sign in with legitimate credentials (`alice` / `Alice#Pass2026`) to show normal logins work.

### 2. In-band OS Command Injection (Help & Support Page)
1. In the portal header, click **Help & Support** (`http://127.0.0.1:5000/support`).
2. Set Demo Mode to **🔴 Intentionally Vulnerable**.
3. Under Network Diagnostic, click the 1-click payload:  
   `127.0.0.1 & echo [CAMPUS-IT-PROOF: Command Executed] & whoami`
4. Click **Run Network Ping Diagnostic**.
5. **Observed Result:** Terminal displays the ping response **plus** `[CAMPUS-IT-PROOF]` and the current logged-in user name (`whoami`).
6. Set Demo Mode to **🟢 Secure Mitigated** and run the identical payload.
7. **Observed Result:** Intercepted by the allow-list regex. Displays `Security Filter Blocked Input`. Command is not passed to the shell.

### 3. Reflected Cross-Site Scripting (Notices Page)
1. Click **Notices** (`http://127.0.0.1:5000/notices`).
2. Set Demo Mode to **🔴 Intentionally Vulnerable**.
3. Click the 1-click payload: `<script>alert('Reflected XSS Demonstrated - Insecure Page Executed Script!');</script>`
4. Click **Search Notices**.
5. **Observed Result:** Browser pops an alert dialog.
6. Set Demo Mode to **🟢 Secure Mitigated** and submit the same payload.
7. **Observed Result:** Rendered harmlessly as literal text on screen. Inspecting HTML source confirms `<` was escaped to `&lt;`.

### 4. GET-based CSRF (My Profile Page)
1. Click **My Profile** (`http://127.0.0.1:5000/profile`). Verify Alice's current setting is `"Email & Portal Alerts"`.
2. Ensure Demo Mode is set to **🔴 Intentionally Vulnerable**.
3. Open a second tab and navigate to `http://localhost:5001`.
4. Click **🚀 Launch Top-Level GET Attack**.
5. **Observed Result:** The attacker page navigates to `http://127.0.0.1:5000/profile/update-preference?preference=Compromised+by+Phishing+Attack`. Under `SameSite=Lax`, top-level GET navigations send Alice's ambient session cookie, altering her preference to `"Compromised by Phishing Attack"`!
6. In CampusConnect, switch Demo Mode to **🟢 Secure Mitigated**.
7. Return to `http://localhost:5001` and click **Test GET on Secure Endpoint** (returns `405 Method Not Allowed`) and **Submit Forged POST without Token** (returns `403 Forbidden`). Alice's setting remains protected.

---

## 7. Automated Test Suite

Run all automated pytest suites:
```powershell
python -m pytest tests/ -v
```

### Test Results (21/21 Passed, 100% Success)
```
tests/test_cmd_injection.py::test_vulnerable_cmd_injection_exploit PASSED [  4%]
tests/test_cmd_injection.py::test_secure_cmd_injection_blocked_by_allowlist PASSED [  9%]
tests/test_cmd_injection.py::test_secure_cmd_clean_host_allowed PASSED   [ 14%]
tests/test_csrf.py::test_vulnerable_csrf_get_updates_state PASSED        [ 19%]
tests/test_csrf.py::test_secure_csrf_rejects_get_with_405 PASSED         [ 23%]
tests/test_csrf.py::test_secure_csrf_rejects_post_without_token PASSED   [ 28%]
tests/test_csrf.py::test_secure_csrf_accepts_post_with_valid_token PASSED [ 33%]
tests/test_portal.py::test_portal_login_page_renders_cleanly PASSED      [ 38%]
tests/test_portal.py::test_portal_legitimate_student_login PASSED        [ 42%]
tests/test_portal.py::test_portal_sqli_bypass_in_vulnerable_mode PASSED  [ 47%]
tests/test_portal.py::test_portal_sqli_bypass_fails_in_secure_mode PASSED [ 52%]
tests/test_portal.py::test_portal_notices_xss_vulnerable_vs_secure PASSED [ 57%]
tests/test_portal.py::test_portal_network_diagnostic_cmd_injection PASSED [ 61%]
tests/test_portal.py::test_portal_csrf_preference_update PASSED          [ 66%]
tests/test_demo_mode_switching_endpoint PASSED                           [ 71%]
tests/test_sqli.py::test_vulnerable_sqli_authentication_bypass PASSED    [ 76%]
tests/test_sqli.py::test_secure_sqli_injection_attempt_rejected PASSED   [ 80%]
tests/test_sqli.py::test_secure_sqli_legitimate_login_success PASSED     [ 85%]
tests/test_sqli.py::test_secure_sqli_invalid_password_rejected PASSED    [ 90%]
tests/test_xss.py::test_vulnerable_reflected_xss_returns_raw_markup PASSED [ 95%]
tests/test_xss.py::test_secure_xss_escapes_html_entities PASSED          [100%]

============================= 21 passed in 4.93s ==============================
```

---

## 8. Viva Questions & Model Answers

### Q1: How does SQL Injection bypass authentication when only password hashes are stored in the database?
> **Answer:** In vulnerable implementations, the application attempts to perform credential matching directly inside the SQL query using string formatting (e.g. `WHERE username = '{user}' AND password_hash = '{hash}'`). When an attacker provides `admin' --`, the comment token (`--`) truncates the SQL statement, causing the database to execute `WHERE username = 'admin'`. Because the developer relied on the query returning a matching row to confirm authentication, the password constraint is completely ignored without needing a plaintext password column.

### Q2: Why does argument-vector execution (`shell=False`) prevent command injection?
> **Answer:** When `shell=False` is used (e.g. `subprocess.run(["ping", target], shell=False)`), Python invokes the operating system's process creation API directly (`CreateProcess` on Windows, `execve` on Linux). No shell interpreter (`cmd.exe` or `/bin/sh`) is launched. As a result, shell metacharacters such as `&`, `|`, and `;` lose their special grammatical meaning and are passed strictly as literal argument strings to the target binary.

### Q3: Why does `HttpOnly` not prevent Cross-Site Scripting (XSS)?
> **Answer:** Setting `HttpOnly` on session cookies only prevents client-side scripts from reading `document.cookie`. However, an injected script still executes within the full security context of the user's origin. The attacker can deface the webpage, capture keystrokes, extract sensitive form data, or make authenticated `fetch()` requests on behalf of the victim using the browser's ambient credentials.

### Q4: Why are state-changing GET endpoints vulnerable to CSRF even under `SameSite=Lax`?
> **Answer:** While the browser default `SameSite=Lax` blocks cookies on cross-origin *subresources* (such as `<img>` or background `fetch()` calls), it **explicitly permits cookies on top-level cross-site GET navigations** (such as clicking a hyperlink). Therefore, an external malicious site can trick the victim into following a link to a state-changing GET endpoint, and the browser will attach the victim's session cookie.
