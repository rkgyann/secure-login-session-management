# Step-by-step implementation guide

This guide assumes you are using the Mac and project folder from this chat. The source files are already written in that folder. Open them in the order below to understand and explain the implementation. Commands go in Terminal, not into Python files or the browser address bar.

## Step 1 — Open the project

1. Open VS Code if installed, or use another code editor.
2. Choose File → Open Folder.
3. Select `/Users/rkgyani/Library/CloudStorage/OneDrive-DITUniversity/secure-login-session-management`.
4. Open Terminal → New Terminal in the editor, or open the macOS Terminal app.
5. Enter:

```bash
cd "/Users/rkgyani/Library/CloudStorage/OneDrive-DITUniversity/secure-login-session-management"
pwd
```

Expected: the printed location ends in `secure-login-session-management`. You should see `run.py`, `requirements.txt`, `app`, `tests`, and `docs` in the editor. You do not need to copy the code out of the chat.

## Step 2 — Prepare Python

Check Python:

```bash
python3 --version
```

Use Python 3.11 or newer. This computer was tested with Python 3.14. A virtual environment keeps this project's packages separate from other projects.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
```

The packages have already been installed in this workspace. These commands are also the reproducible setup instructions for another group member on a compatible computer. `requirements.txt` declares the direct dependencies; `requirements-lock.txt` records the exact installed package versions tested here.

What each package does:

| Package | Purpose |
| --- | --- |
| Flask | Web routing, requests, responses, HTML templates |
| argon2-cffi | Salted Argon2id password hashes |
| pyotp | Authenticator enrollment URI and time-based codes |
| cryptography | Fernet encryption for TOTP seeds |
| qrcode and Pillow | Generates the local enrollment QR image |
| python-dotenv | Loads the local encryption key from `.env` |
| pytest | Runs security tests |

## Step 3 — Generate local secrets and HTTPS certificate

```bash
python scripts/setup_local.py
```

This creates:

- `.env`: random TOTP encryption key, readable only by your operating-system account.
- `certs/localhost.crt`: self-signed local certificate.
- `certs/localhost.key`: private certificate key.

Running the script again preserves existing files. You can inspect the script in `scripts/setup_local.py`. Do not copy the real encryption key or certificate private key into a report, screenshot, repository, or chat. Losing the TOTP encryption key while keeping the database will prevent existing accounts from verifying codes.

## Step 4 — Start and open the app

```bash
python run.py
```

Keep this Terminal open. The server should show an HTTPS address and run on port 5443. Open **https://localhost:5443** in your browser. The certificate is self-signed, so your browser may ask you to accept a local certificate exception. Check the URL is the local project before continuing. Some browsers require trusting the local certificate instead; do not disable browser security globally. HSTS is returned over HTTPS, but browser HSTS enforcement requires acceptable certificate trust.

Use exactly the same hostname throughout: `localhost`. Switching to `127.0.0.1` creates a separate browser cookie context. The server is restricted to your own computer; you do not need to expose it to the network or visit the portal on your phone. Your phone only scans the screen's QR code.

To stop: click Terminal and press Control+C. To start on a later day:

```bash
cd "/Users/rkgyani/Library/CloudStorage/OneDrive-DITUniversity/secure-login-session-management"
source .venv/bin/activate
python run.py
```

## Step 5 — Implement and understand the database

Open **`app/schema.sql`**, then **`app/database.py`**.

| Table | Stored data | Reason |
| --- | --- | --- |
| `users` | Name, normalized email, password hash, encrypted TOTP seed, TOTP activation, last accepted code step | Account and authenticator verification |
| `sessions` | Hash of random cookie token, user ID, authentication stage, CSRF token, creation/activity/expiry times | Server-side access, revocation, timeout |
| `rate_limits` | Hashed scope/identifier, attempt count, window expiry | Persistent brute-force limits |
| `password_resets` | Hashed reset token, user ID, expiration | Single-use, expiring password-reset links |
| `security_events` | User ID where known, event name, IP, time | Local demonstration record |

The database is created automatically at `instance/portal.sqlite` when the app starts. Do not make a database manually. Database queries use placeholders such as `WHERE email = ?`, with values passed separately, to avoid treating input as SQL.

## Step 6 — Implement registration and password storage

Open **`app/routes.py`**, function **`register`**, and **`app/templates/register.html`**.

The form collects name, email, password, and password confirmation. The server checks name length, email shape, password length (12–128 characters), and matching confirmation. Browser checks improve usability; the server repeats checks because browser checks can be bypassed.

The key password line is:

```python
password_hash = current_app.extensions['password_hasher'].hash(password)
```

`PasswordHasher` uses Argon2id and generates its salt internally. Store the encoded hash, never the original password. At login, `verify(stored_hash, supplied_password)` checks it. Successful logins can upgrade old hashing parameters using `check_needs_rehash`.

Try registering with fictional details such as `student@example.test`. Use your own unique test passphrase of at least 12 characters. No email is sent and mailbox ownership is not verified in this classroom project.

Expected: registration takes you to authenticator setup, not directly to the dashboard.

## Step 7 — Implement authenticator setup and login verification

Open **`app/routes.py`**, functions **`totp_page`** and **`totp_qr`**; then **`app/security.py`**, function **`consume_totp`**.

1. Registration generates a random TOTP seed.
2. The seed is encrypted using the key in `.env` and saved in the database.
3. A restricted enrollment session allows the QR/setup page.
4. The QR code is generated locally; no third-party QR service receives the seed.
5. In an authenticator app on your phone, add an account by scanning the QR.
6. Enter its six-digit code on the portal.
7. A correct code enables TOTP and creates a fully authenticated session.

The next login requires password verification followed by the authenticator code. A password-only session cannot open `/dashboard`.

TOTP normally changes every 30 seconds. The server accepts the current or one adjacent time step for modest clock drift. It saves the last accepted step, so a code used for enrollment/login/password change cannot be used again. If you sign out and back in immediately, wait for the next fresh code. Set your phone's time to automatic.

Enrollment and password-verified sessions expire after five minutes. If setup expires, sign in with your password to resume setup. Once TOTP is enabled, the setup seed/QR is no longer accessible. There is no lost-authenticator recovery flow in this version.

Do not include the enrollment QR, setup key, or a current code in screenshots that you share.

## Step 8 — Implement brute-force defence

Open **`app/security.py`**, function **`allowed`**, then **`app/routes.py`**, function **`login`**.

The app keeps fixed five-minute counters in SQLite. Login permits five submissions per account identifier and thirty per IP; the next is blocked with HTTP 429. Unknown account identifiers use the same rate-limit structure and a dummy Argon2 check to reduce timing differences. Login failures use one generic message.

TOTP has its own per-user and per-IP counters, so restarting a login does not reset code guessing. Registration and password changes also have limits. Counters count all submissions, including successes. A blocked request does not continually extend the window.

`BEGIN IMMEDIATE` serializes security updates in SQLite so concurrent requests cannot both consume the same accepted code step or lose counter increments.

Manual test: on the login form, submit the same fictional email with a wrong password six times within five minutes. The sixth submission should show HTTP 429 in the browser Network panel. Wait five minutes before repeating other tests with that identifier. Use a separate test account if needed.

## Step 9 — Implement secure sessions and logout

Open **`app/security.py`**, functions **`new_session`**, **`load_session`**, **`require_stage`**, and **`finish_response`**.

The session design is:

```text
Browser: random opaque __Host-portal cookie
Server: SHA-256 hash of that token → session record
Record: user, stage, CSRF token, timestamps
```

Tokens are generated using `secrets.token_urlsafe(32)`. A fresh token replaces the previous token at password verification and full authentication. This prevents carrying a pre-login identifier into the authenticated session.

Cookie flags:

- `Secure`: cookie sent over HTTPS.
- `HttpOnly`: page JavaScript cannot read it.
- `SameSite=Lax`: reduces cross-site cookie sending; CSRF tokens provide explicit form protection.
- `__Host-` prefix, `Path=/`, no Domain attribute: host-scoped cookie restrictions.

Authenticated sessions expire after ten minutes without a request or after one hour total, whichever occurs first. Every protected request checks the server record. Logout is POST with CSRF protection and deletes the old session record, then creates a fresh anonymous session. Deleting only the browser cookie would not be sufficient.

Manual test: sign out and enter `https://localhost:5443/dashboard` directly. You should be redirected to login. For a quick inactivity demo, temporarily change `IDLE_SECONDS=600` to `IDLE_SECONDS=20` in `app/__init__.py`, restart the server, sign in, wait without making requests, then refresh. Restore 600 after testing. Expiry is enforced on the next request; there is no live countdown or automatic page redirect.

## Step 10 — Implement CSRF, headers, and escaped output

Open **`app/security.py`**, function **`load_session`**, and any template form.

Each session has a random CSRF token. Every form has:

```html
<input type="hidden" name="csrf_token" value="{{ g.session.csrf_token }}">
```

For every state-changing request, the server compares this form field with the stored session token using a constant-time comparison. A missing or changed token returns HTTP 400 before the route can change state. Reload stale forms after login/logout, because token rotation is intentional.

`finish_response` sets HSTS over HTTPS, CSP, X-Content-Type-Options, and X-Frame-Options, plus no-store cache and referrer restrictions. CSP allows local CSS/images, denies scripts, disallows framing, and restricts form destinations. The templates use Jinja's default HTML escaping and never mark student input as safe HTML.

Manual header check, in a second Terminal while the server runs:

```bash
curl --insecure --head https://localhost:5443/login
```

`--insecure` is only for inspecting this project's self-signed local certificate. Look for the required headers. To inspect cookie flags, open browser Developer Tools → Application/Storage → Cookies → `https://localhost:5443`. Do not include cookie values in shared screenshots.

Manual CSRF test: open the login page, then Developer Tools → Elements. Find the hidden `csrf_token` input and change its `value` to `invalid`. Submit the form. Expect the CSRF error page and HTTP 400. Reload before continuing.

## Step 11 — Understand password changes

Open **`app/routes.py`**, function **`account_security`**. From an authenticated dashboard, open Account security.

Changing a password requires the current password, matching new passwords, and a fresh authenticator code. On success, all server sessions for that user are deleted and the browser returns to login. The old password no longer works. This is an extra feature supporting the session design; the optional password-reset link is implemented separately below.

## Step 11A — Demonstrate the bonus password-reset link

Local HTTPS already implements the first bonus. For the second, open `app/password_reset.py` and the three reset templates. The flow is request → private local message → expiring token → new password → normal password plus authenticator login.

1. On the login page, click **Forgot your password?**.
2. Enter the email of an existing fictional test account.
3. Open a second Terminal in this project folder and activate `.venv`.
4. Run this, replacing the address with your registered test account:

```bash
python scripts/show_reset_link.py student@example.test
```

5. Copy the HTTPS link printed by this local operator tool and open it in the browser. The application does not send a real email; the private outbox simulates the message channel for the lab. It is not accessible through the website.
6. Enter matching new passwords of 12–128 characters and submit.
7. Sign in with the new password and a fresh authenticator code. A reset does not disable TOTP or log you in automatically.
8. Reopen the same reset link. Expect an invalid/expired/used message and HTTP 400.
9. Request a new link; wait 15 minutes and open it. Expect rejection. For a quick live expiry demo, temporarily set `RESET_SECONDS=20` in `app/__init__.py`, restart the app, request a new link, wait 21 seconds, then open it. The standard page/message still describes the default 15-minute policy, so record the temporary test setting and restore 900 afterwards.
10. Check that prior logged-in sessions no longer access the dashboard. The automated test also checks this with a copied old session cookie.

Opening a valid link does not consume it; submitting a valid new password does. Reset consumption and password/session updates happen in one database transaction. Invalid form input leaves the link available until expiry. Requesting a new link invalidates earlier links. Reset requests allow three per address and fifteen per IP per 15-minute fixed window; guessing/reset-page requests allow sixty per IP per five minutes. Existing and unknown addresses show the same request message. No password reset is needed merely because someone requests a link, and login sessions remain valid until a reset succeeds.

Do not screenshot token values, local message contents, or a complete reset URL. `RESET_BASE_URL` fixes the trusted HTTPS origin; update it if you change the server port. The new `password_resets` table is created on restart without deleting your existing accounts. Forgotten-password recovery does not recover a lost authenticator.

## Step 12 — Run tests and collect evidence

Open a second Terminal so you can keep the app running:

```bash
cd "/Users/rkgyani/Library/CloudStorage/OneDrive-DITUniversity/secure-login-session-management"
source .venv/bin/activate
python -m pytest -q
```

Tests use temporary databases and keys and do not require the server to be running. Read **`tests/test_security.py`** to see actual requests and assertions. The test client sends HTTPS-labelled requests to exercise cookie/header behavior; it does not test browser trust or perform a TLS network handshake. Test the real certificate/server separately using the browser or local curl command above.

Use **`docs/SECURITY_CHECKLIST.md`** to collect your own screenshots. Create a local `docs/test-evidence/` folder for sanitized screenshots. Record the date, steps, expected result, actual result, and image name. Do not label screenshots as complete until you have captured them.

## Step 13 — Work as a group and prepare submission

Create a shared Git repository and have each member make meaningful contributions. Before adding files, confirm `.gitignore` excludes `.env`, certificates/private keys, `instance`, and `.venv`.

If this folder has no repository yet, run:

```bash
git init
git status
git add .
git diff --cached --stat
git commit -m "Add secure authentication portal and security tests"
```

Connect that repository to your group's chosen remote using its real URL. Do not invent a remote URL. Each member should clone it, create their own local environment/keys, and contribute tests, UI improvements, documentation, or other understood work. Do not share the running database and private key through Git.

Follow **`docs/REPORT_AND_DEMO.md`** for the 10–15 page report, evidence, demo, and viva. A working app alone does not complete the assignment.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| `ModuleNotFoundError` | Activate `.venv`, then install `requirements-lock.txt` with that environment's Python |
| `python: command not found` | Use `python3` to create the environment, then activate it |
| Certificate files missing | Run `python scripts/setup_local.py` from the project folder |
| `openssl` not found or `-addext` unsupported | Use a current OpenSSL installation; do not remove certificate checks or cookie flags to work around it |
| Port 5443 already in use | Stop your old project server. Alternatively change port in `run.py` to 5444 and use the matching HTTPS URL |
| Login keeps returning to login | Use HTTPS and one consistent hostname; check cookies are allowed |
| CSRF error after going Back | Reload the form; login/logout rotates sessions and tokens |
| Correct code rejected | Wait for the next code; check automatic phone time; a used code is deliberately rejected |
| HTTP 429 | Wait for the five-minute window; repeated successful submissions also count |
| Invalid token/encryption error after changing `.env` | Restore the original key matching the database; do not overwrite a working key |
| App fails after editing Python | Read the Terminal error, fix the file, stop and restart the server; debug mode is disabled |
