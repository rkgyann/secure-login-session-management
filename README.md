# Project 7: Secure Login and Session Management

A local student portal for the Essentials of Cyber Security assignment. Built with Flask, SQLite, Argon2id, encrypted TOTP secrets, and server-side sessions.

Start with **[the complete step-by-step guide](docs/STEP_BY_STEP.md)**. It explains where to work, what each file does, how the controls work, and how to collect demo evidence.

## Run on your Mac

Open Terminal (or VS Code → Terminal → New Terminal), then run each line:

```bash
cd "/Users/rkgyani/Library/CloudStorage/OneDrive-DITUniversity/secure-login-session-management"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python scripts/setup_local.py
python run.py
```

The environment and local keys have already been prepared on this computer. For later sessions, only `cd`, `source .venv/bin/activate`, and `python run.py` are needed.

Open **https://localhost:5443**, using HTTPS. The certificate is generated locally and self-signed: a browser may show a certificate warning. Check the address is your local portal before accepting the local certificate exception. Do not weaken certificate verification for unrelated sites. HSTS is emitted over HTTPS; browsers enforce it only with an acceptable certificate/trust configuration.

Register a new test account, scan the setup QR code with an authenticator app, and enter its code. No email is sent. Use fictional student details. Stop the server with Control+C.

The Flask development server binds only to this computer. This project is a classroom demonstration, not a deployment configuration for a public service.

## Run tests

```bash
python -m pytest -q
```

Tests use a temporary database and disposable keys; they do not alter student accounts. Test cases cover hashing, encrypted secrets, CSRF, both login factors, code replay, login and TOTP throttling, session rotation, revocation and expiry, cookie flags, headers, SQL input, HTML escaping, password changes, oversized requests, and host restrictions.

## File map

| File | Responsibility |
| --- | --- |
| `run.py` | Starts the local HTTPS server |
| `app/__init__.py` | Configures Flask and registers security hooks |
| `app/schema.sql` | Defines users, sessions, rate limits, security events |
| `app/database.py` | Opens/closes SQLite connections and initializes schema |
| `app/security.py` | Sessions, CSRF, headers, throttling, TOTP replay protection |
| `app/password_reset.py` | Single-use reset links, expiry, session revocation, private local message delivery |
| `scripts/show_reset_link.py` | Reads a local reset message for the lab operator |
| `app/routes.py` | Registration, password login, enrollment, OTP verification, dashboard, password change, logout |
| `app/templates/` | HTML pages with escaped output and CSRF fields |
| `app/static/style.css` | Responsive page design |
| `scripts/setup_local.py` | Generates a private encryption key and localhost certificate |
| `tests/test_security.py` | Automated security checks |
| `docs/STEP_BY_STEP.md` | Setup, implementation, testing, and submission walkthrough |
| `docs/SECURITY_CHECKLIST.md` | Required control → code → test → screenshot mapping |
| `docs/REPORT_AND_DEMO.md` | Report outline, demo sequence, viva preparation |

## Configuration

`scripts/setup_local.py` creates `.env` with `TOTP_ENCRYPTION_KEY`. The actual key is never included in documentation. Existing secrets and certificate pairs are preserved. Do not regenerate the encryption key while keeping the existing database: its encrypted TOTP seeds would become unreadable. `.env`, `certs/`, `instance/`, and `.venv/` are excluded from Git.

Defaults in `app/__init__.py`: authenticated inactivity timeout 600 seconds; absolute lifetime 3600 seconds; enrollment/verification lifetime 300 seconds. OTPs use 30-second steps with one adjacent step of clock tolerance. The server remembers the last accepted step to reject replay.

Login allows five submissions per normalized account identifier and thirty per IP in a five-minute fixed window. TOTP has a separate five-per-user/thirty-per-IP limit. Limits count all submissions, including successful ones. The sixth applicable submission is blocked until the fixed window expires. Registration allows ten submissions per IP; password changes allow five per user. Limits persist in SQLite across restarts. The app deliberately does not trust a user-supplied `X-Forwarded-For` header.

## Scope and limitations

- Required assignment features are implemented. Local self-signed HTTPS is included. Single-use, 15-minute password-reset links are implemented using a private local delivery outbox.
- No email ownership verification, authenticator recovery, administrator portal, or real student records. An unfinished enrollment can be resumed by logging in with the account password.
- Account creation necessarily has a different flow for a duplicate address; generic login errors reduce login enumeration but do not promise total account anonymity.
- SQLite plus serialized security writes suits a small local demo. Shared-NAT users can share IP limits; account throttling can temporarily inconvenience a legitimate user. These tradeoffs belong in the report.
- TOTP can still be phished. It is not a phishing-resistant authentication method.
- Application keys live separately from the database. Encryption alone does not protect against a compromised running server.
- Security events are ordinary local records, not tamper-evident audit logs. No public deployment, real email delivery, or production hardening claim is made.

## Assignment submission

Submit code, setup instructions, a completed security checklist, screenshots of blocked attempts, a 10–15 page report, and a working demo. Work in a shared repository with meaningful commits from every member. Use only your own or explicitly authorized lab systems for testing. Record source references and assistance; every member should understand the implementation.

## References

- Assignment: supplied `Cyber_Security_Project_List.pdf`, Project 7 on page 9; general rules on page 2.
- Flask security: https://flask.palletsprojects.com/en/stable/web-security/
- OWASP session management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- PyOTP: https://pyauth.github.io/pyotp/
- Argon2-cffi: https://argon2-cffi.readthedocs.io/en/stable/api.html

## Bonus feature: password-reset links

Both PDF bonus features are implemented: local self-signed HTTPS and a single-use, expiring password-reset link.

1. Start the server and choose **Forgot your password?** on the login page.
2. Submit the email of a registered test account. All addresses receive the same on-screen message.
3. In a separate activated project Terminal, run:

```bash
python scripts/show_reset_link.py student@example.test
```

Replace the example with the account you registered. The operator command reads the private local message; no email is actually sent. Open its HTTPS link in your browser, set a new password, and sign in again with your authenticator. The link expires after 15 minutes and is invalid after a successful reset. Requesting another link replaces the previous one. A normal authenticated password change also invalidates pending reset links.

Reset tokens are generated with 32 random bytes, stored only as SHA-256 hashes in the `password_resets` table, and consumed atomically with the password update. Successful resets revoke all existing user sessions and preserve TOTP. Rate limits cover requests and token guessing; forms retain CSRF protection. Link construction uses a configured HTTPS origin, not the request Host header. Access-log query tokens are redacted.

Messages are stored with owner-only permissions under `instance/reset-outbox/`, which is excluded from Git and has no HTTP endpoint. This simulates private email delivery for the local lab; it is not a public self-service email system. Anyone with access to the operating-system account can read these messages. Do not publish their contents. Expired/used message files may remain, but their links no longer work.

The new database table is created automatically on startup; existing accounts and keys are preserved. If you change the HTTPS port, update `RESET_BASE_URL` in `app/__init__.py` as well as `run.py`.

Reference: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
