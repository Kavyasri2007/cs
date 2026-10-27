# CampusConnect: Web Server Security Lab                    

> **Security notice:** This project intentionally contains vulnerable code paths for a controlled academic demonstration. Run it locally only. Do not expose the application to public networks or test systems without explicit authorisation.

## Overview

CampusConnect is a Flask-based student portal backed by SQLite. It demonstrates four web vulnerability categories, shows how each can be exploited in the local lab, and compares the vulnerable implementation with a mitigated implementation.

| Vulnerability | Variant | Implemented mitigation |
|---|---|---|
| SQL Injection (SQLi) | Authentication bypass | Parameterised SQL queries |
| OS Command Injection | In-band command injection | Input allow-list validation and shell-free execution |
| Cross-Site Scripting (XSS) | Reflected XSS | Jinja2 auto-escaping |
| Cross-Site Request Forgery (CSRF) | GET-based forged action | Reject state-changing GET requests and require a CSRF token for POST |

## Team and Ownership

| Member | Roll number | Vulnerability | Variant |
|---|---|---|---|
| Kavya Sri Badimala | IIB2024007 | SQL Injection | Authentication bypass |
| Bandla Bhargavi | IIB2024011 | OS Command Injection | In-band command injection |
| Rithwika Naidu Mode | IIB2024021 | Cross-Site Scripting (XSS) | Reflected XSS |
| Banavathu Sravanthi | IIT2024254 | Cross-Site Request Forgery (CSRF) | GET-based forged action |

*The ownership mapping should reflect each member's actual individual contribution.*

## Technology Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript, Jinja2 templates
- **Tests:** pytest

## Application Architecture

The project runs two local services:

| Component | Address | Purpose |
|---|---|---|
| CampusConnect student portal | `http://127.0.0.1:5000` | Main application and vulnerability demonstrations |
| Simulated attacker website | `http://127.0.0.1:5001` | Cross-origin CSRF demonstration |

Key application routes:

| Route | Purpose |
|---|---|
| `/login` | Student login and SQL injection demonstration |
| `/dashboard` | Student dashboard |
| `/notices` | Reflected XSS demonstration |
| `/support` | Network diagnostic utility and command injection demonstration |
| `/profile` | Profile and notification preferences |
| `/profile/update-preference` | State-changing preference endpoint used for the CSRF demonstration |

A **Demo Mode** drawer lets the presenter switch between vulnerable and secured implementations and use the application's demonstration inputs.

## Vulnerability Details

### 1. SQL Injection: Authentication Bypass

**Vulnerable behaviour:** The vulnerable login handler constructs an SQL query using untrusted input. Crafted input can alter the query's logic and bypass the intended password check.

**Local demonstration input:**

```text
admin' --
```

In vulnerable mode, the input can cause the password condition to be commented out. In secured mode, the same input is treated as a literal value and authentication should fail.

**Root cause:** Untrusted input is combined with SQL syntax instead of being treated strictly as data.

**Implemented mitigation:** Parameterised SQL queries separate query structure from user-supplied values.

**Other mitigation options:**

- **Allow-list validation:** Restrict fields to the expected format and reject invalid values. Validation is an additional layer, not a replacement for parameterised queries.
- **Least-privilege database account:** Give the application only the database permissions it needs to reduce the impact of a successful attack.
- **Safe error handling:** Return generic errors to users and keep sensitive database details out of responses.

### 2. OS Command Injection: In-Band

**Vulnerable behaviour:** The network diagnostic utility passes user-controlled input to a system command through a shell. Crafted input can run additional commands, with their output returned in the response.

**Local demonstration input:** Use the application's documented Demo Mode payload, which uses a harmless marker and displays the command output.

**Root cause:** Shell metacharacters in untrusted input can be interpreted as command syntax when input is incorporated into a shell command.

**Implemented mitigation:** Validate the host using an allow-list and invoke the command with an argument vector and `shell=False`.

**Other mitigation options:**

- **Avoid the shell:** Prefer a dedicated library or API where possible.
- **Argument-vector execution:** Pass the executable and arguments separately rather than concatenating a shell command string.
- **Allow-list validation:** Accept only values matching the expected hostname or IP-address format.
- **Least privilege:** Run the application with only the operating-system permissions it requires.

### 3. Cross-Site Scripting: Reflected XSS

**Vulnerable behaviour:** The notices search handler reflects user input into the HTML response without normal output escaping. In the vulnerable path, `Markup()` marks the supplied content as safe HTML.

**Local demonstration:** Use the harmless JavaScript alert payload provided in Demo Mode. The vulnerable response allows the browser to execute the script; the secured response displays the input as text.

**Root cause:** Untrusted input is inserted into an HTML response without appropriate context-aware output encoding.

**Implemented mitigation:** Jinja2 auto-escaping encodes HTML-sensitive characters in reflected input.

**Other mitigation options:**

- **Context-aware output encoding:** Encode data appropriately for the HTML, attribute, URL, or JavaScript context where it is used.
- **Framework auto-escaping:** Preserve secure framework defaults and do not mark untrusted input as safe.
- **HTML sanitisation:** If user-authored rich HTML is required, use a maintained sanitiser configured to permit only safe elements and attributes.
- **Content Security Policy (CSP):** Restrict permitted script execution as an additional defensive layer; CSP does not replace output encoding.
- **HttpOnly cookies:** Prevent JavaScript from directly reading cookies marked `HttpOnly`; this does not prevent XSS itself.
- **Safe DOM sinks:** Prefer APIs such as `textContent` when inserting untrusted text into the DOM.

### 4. Cross-Site Request Forgery: GET-Based Forged Action

**Vulnerable behaviour:** The vulnerable profile-preference endpoint changes a notification setting through an HTTP GET request. The simulated attacker page can trigger a top-level navigation to this endpoint while the victim is signed in.

**Root cause:** A state-changing request is accepted without adequately verifying that the action was intentionally initiated through the application. Browsers may attach session cookies to top-level cross-site GET navigations, depending on cookie policy.

**Implemented mitigation:** The secured endpoint rejects GET requests for the state-changing operation and requires a POST request with a valid synchronizer CSRF token.

**Other mitigation options:**

- **Synchronizer CSRF tokens:** Generate an unpredictable token associated with the session and validate it before processing state-changing requests.
- **SameSite cookies:** Restrict when browsers send cookies with cross-site requests. `SameSite=Lax` still permits cookies on many top-level cross-site GET navigations.
- **Re-authentication:** Require the user to re-authenticate before particularly sensitive actions.
- **Avoid state-changing GET requests:** Use GET for retrieving information rather than changing state. This is an important design rule, but it does not replace CSRF protection for state-changing requests.

## Installation and Execution

### Prerequisites

- Python 3
- `pip`
- A modern web browser

### 1. Clone the repository

```bash
git clone https://github.com/Kavyasri2007/cs.git
cd cs
```

### 2. Create a virtual environment and install dependencies

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Initialise the database

```powershell
python database.py
```

The database initialisation script creates the lab's sample data. Use only the dummy accounts intended for this local demonstration.

### 4. Start CampusConnect

In the first terminal:

```powershell
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

### 5. Start the simulated attacker website

In a second terminal, activate the same virtual environment and run:

```powershell
python attacker_server.py
```

Open <http://127.0.0.1:5001> to access the simulated attacker page used for the CSRF demonstration.

## Testing

Automated tests are included for the vulnerable handlers, the mitigations, and normal application flows. Run them from the project root:

```powershell
python -m pytest tests/ -v
```

## Scope and Safety

This project is for authorised, local academic testing only.

- Keep the vulnerable application and attacker page on the loopback interface.
- Use only the lab's dummy accounts and test data.
- Do not expose vulnerable endpoints to public networks.
- Do not test third-party or university systems without explicit authorisation.
- Do not use the intentionally vulnerable implementations in production.
