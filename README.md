1. Project Overview

CampusConnect is a Flask-based student portal developed to demonstrate four categories of web application vulnerabilities and their corresponding mitigations in a controlled local environment.

The application provides vulnerable and secured implementations of SQL injection, OS command injection, reflected cross-site scripting (XSS), and cross-site request forgery (CSRF). Each vulnerability demonstrates how the flaw occurs, how it can be exploited, and how an appropriate mitigation prevents the attack.

Vulnerabilities and mitigations

Vulnerability

Variant

Implemented mitigation

SQL Injection (SQLi)

Authentication bypass

Parameterised SQL queries

OS Command Injection

In-band command injection

Allow-list validation and shell-free command execution

Cross-Site Scripting (XSS)

Reflected XSS

Jinja2 auto-escaping

Cross-Site Request Forgery (CSRF)

GET-based forged action

Reject state-changing GET requests and require a CSRF token for POST

2. Team and Ownership Declaration

Member

Roll number

Vulnerability category

Variant

Kavya Sri Badimala

IIB2024007

SQL Injection

Authentication bypass

Bandla Bhargavi

IIB2024011

OS Command Injection

In-band command injection

Rithwika Naidu Mode

IIB2024021

Cross-Site Scripting (XSS)

Reflected XSS

Banavathu Sravanthi

IIT2024254

Cross-Site Request Forgery (CSRF)

GET-based forged action

Each member is responsible for their assigned implementation and should be able to explain its vulnerable code path, exploit, root cause, and mitigation.

3. Technology Stack

Backend: Python, Flask

Database: SQLite

Frontend: HTML, CSS, JavaScript, Jinja2

Testing: pytest

4. Application Architecture

The application consists of two local services:

Component

Local address

Purpose

CampusConnect student portal

http://127.0.0.1:5000

Student portal and vulnerability demonstrations

Simulated attacker website

http://localhost:5001

Cross-origin CSRF demonstration

Main application pages

Page

Route

Functionality

Student Login

/login

SQL injection authentication bypass

Dashboard

/dashboard

Student dashboard

Campus Notices

/notices

Reflected XSS

Help & Support

/support

In-band OS command injection

My Profile

/profile

CSRF against notification preferences

The application includes a local Demo Mode control for switching between vulnerable and secured implementations.

5. Vulnerability Implementations and Mitigations

5.1 SQL Injection: Authentication Bypass

Vulnerable implementation: The login handler constructs an SQL query using untrusted input. An attacker can alter the query's logic to bypass authentication.

Demonstration input: admin' --

In vulnerable mode, the input can cause the password condition to be ignored. In secured mode, the same input is treated as a literal value and authentication fails.

Root cause: Untrusted input is concatenated into SQL syntax instead of being treated strictly as data.

Implemented mitigation: Parameterised SQL queries separate query structure from user-supplied values.

Other mitigation alternatives:

Allow-list input validation: Restrict input to the expected format and reject invalid values.

Least-privilege database accounts: Limit database permissions to reduce the potential impact of a successful attack.

Safe error handling: Avoid revealing SQL statements, database details, or stack traces to users.

5.2 OS Command Injection: In-Band

Vulnerable implementation: The network diagnostic utility passes user-controlled input to a system command through a shell.

Demonstration input: Use the documented command-injection payload provided by Demo Mode, which demonstrates additional command execution and returns its output.

In vulnerable mode, injected command output is displayed in the application. In secured mode, the same input is rejected by the input validation mechanism.

Root cause: Shell interpretation allows specially crafted input to introduce additional command syntax.

Implemented mitigation: Allow-list validation of the host input combined with argument-vector execution using shell=False.

Other mitigation alternatives:

Avoid invoking a shell: Prefer a dedicated library or API when system command execution is unnecessary.

Argument-vector execution: Pass the executable and arguments separately rather than constructing a shell command string.

Allow-list validation: Accept only inputs matching the expected host or IP-address format.

Least privilege: Run the application with only the operating-system permissions it needs.

5.3 Cross-Site Scripting: Reflected XSS

Vulnerable implementation: The notices search handler reflects untrusted input into an HTML response using Markup(), bypassing normal output escaping.

Demonstration: Use the harmless JavaScript alert payload provided by Demo Mode.

In vulnerable mode, the browser executes the injected script. In secured mode, the same input is rendered as text rather than executable HTML.

Root cause: Untrusted input is inserted into an HTML response without appropriate output encoding.

Implemented mitigation: Jinja2 auto-escaping encodes HTML-sensitive characters in the reflected input.

Other mitigation alternatives:

Context-aware output encoding: Encode data appropriately for the HTML, attribute, URL, or JavaScript context in which it appears.

Framework auto-escaping: Preserve framework defaults and avoid marking untrusted content as safe.

HTML sanitisation: Use a maintained sanitiser when users genuinely need to submit permitted rich HTML.

Content Security Policy (CSP): Restrict permitted script execution as an additional layer of protection.

HttpOnly cookies: Prevent JavaScript from reading cookies marked HttpOnly; this does not prevent XSS itself.

Safe DOM sinks: Use APIs such as textContent for untrusted text rather than unsafe HTML insertion methods.

5.4 Cross-Site Request Forgery: GET-Based Forged Action

Vulnerable implementation: The profile-preference endpoint changes a user's notification preference through an HTTP GET request without sufficient verification of the intended action.

The simulated attacker website triggers a cross-origin navigation to the vulnerable endpoint. If the browser sends the authenticated session cookie, the preference can be changed without an intentional submission through the portal.

Root cause: The application accepts a state-changing GET request without verifying that the action was intentionally initiated by the authenticated user.

Implemented mitigation: The secured endpoint rejects state-changing GET requests and requires a POST request with a valid synchronizer CSRF token.

Other mitigation alternatives:

Synchronizer CSRF tokens: Generate an unpredictable token associated with the user's session and validate it before processing state-changing requests.

SameSite cookies: Restrict the contexts in which session cookies accompany cross-site requests. SameSite=Lax still permits cookies on many top-level cross-site GET navigations.

Re-authentication: Require the user to re-authenticate for particularly sensitive operations.

Avoid state-changing GET requests: Use GET for retrieving information, not for modifying application state. Appropriate CSRF protection is still necessary for state-changing requests.

6. Installation and Execution

Prerequisites

Python 3

pip

A modern web browser

Clone the repository

git clone https://github.com/Kavyasri2007/cs.git
cd cs

Create a virtual environment and install dependencies

Windows PowerShell:

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

Initialise the database

python database.py

Use only the dummy accounts and data provided for the local demonstration.

Start the student portal

In the first terminal:

python app.py

Open http://127.0.0.1:5000 in the browser.

Start the simulated attacker website

In a second terminal, activate the same virtual environment and run:

python attacker_server.py

Open http://localhost:5001 to access the simulated attacker website used in the CSRF demonstration.

7. Testing

Automated tests are provided for the vulnerable implementations, their mitigations, and the normal application flows.

Run the test suite with:

python -m pytest tests/ -v

8. Security Scope

This project intentionally includes vulnerable implementations for academic demonstration only.

Run the application and attacker website locally.

Keep vulnerable endpoints isolated from public networks.

Use only the application's dummy accounts and test data.

Test only systems for which explicit authorisation has been granted.

Do not deploy the vulnerable implementations in production.

The project demonstrates common web security weaknesses and defensive techniques in a controlled environment.
