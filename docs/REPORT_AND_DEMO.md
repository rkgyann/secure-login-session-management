# Report, demo, and viva plan

## 10–15 page report outline

Use this as an outline, not a completed report. Add actual screenshots, results, group names, and references.

1. Title page: Project 7 title, course, group members and IDs, institution, date.
2. Problem statement and objectives: account takeover risks; scope of the student portal.
3. Concepts and related work: hashing vs encryption, authentication vs sessions, TOTP, HTTPS, CSRF.
4. Requirements: map every Project 7 must-have to code and test evidence. Include both bonus features: local HTTPS and single-use, expiring password-reset links with local outbox delivery.
5. Architecture and user flow: browser, HTTPS, Flask, SQLite; anonymous → enrollment/verification → authenticated.
6. Database design: five tables, relationships, token hashes, encryption-key separation.
7. Registration and authentication: validation, Argon2id, generic errors, persistent throttling.
8. TOTP design: protected enrollment, secret encryption, 30-second steps, drift, replay protection, rate limiting.
9. Session design: rotation, cookie flags, idle/absolute expiry, logout, password-change revocation.
10. Request/browser controls: CSRF, SQL parameters, escaped templates, CSP, HSTS and certificate trust.
11–12. Testing: security checklist, automated test results, blocked attempts and sanitized screenshots.
13. Limitations: no authenticator recovery or real email delivery/verification, TOTP phishing risk, local server/self-signed cert, SQLite and throttling tradeoffs.
14. Conclusion and future work: improvements supported by actual observations, not claims of perfect security.
15. References: assignment PDF, official library/OWASP references, borrowed material and assistance.

Combine sections to meet the instructor's page-count convention. The general assignment says 10–15 pages. Do not substitute another project's shorter page requirement.

## Suggested live demo sequence

1. Start `python run.py`; open the local HTTPS portal.
2. Briefly explain registration, salted hashing, and TOTP. Use a prepared test account; avoid displaying live enrollment secrets to an audience.
3. Attempt a wrong password and point out the generic error.
4. Sign in with the correct password; try visiting `/dashboard` before OTP to show denied access.
5. Enter a fresh authenticator code and show the dashboard.
6. Inspect required response headers and cookie flags, hiding values.
7. Demonstrate a missing/altered CSRF token rejection on a form.
8. Demonstrate login throttling with a separate disposable identifier so the main account remains usable.
9. Sign out and show protected dashboard access is denied.
10. Show automated tests and the completed checklist; explain timeout/replay tests and limitations.

If time is short, prioritize the controls your instructor requests and keep other screenshots ready. Project 7 does not specify a demo duration.

## Group contribution plan

For a group of 3–4, divide ownership among registration/database, TOTP/sessions, UI/headers/CSRF, and tests/report/demo. Combine the last two for three members. Each person should review another person's code, contribute meaningful commits, and understand the complete authentication flow.

## Viva preparation

- Why hash passwords but encrypt TOTP seeds? Passwords need verification only; TOTP seeds must be recovered to recompute codes.
- What is a salt? Random per-password input encoded in the Argon2 hash; it prevents identical passwords producing identical stored hashes.
- What is the difference between hashing and encryption? Hashes are one-way verification values; encryption is reversible with a key.
- Why are password and OTP stages separate? A valid password alone must not create access to protected pages.
- Why generate a new session ID after authentication? To avoid keeping a potentially known pre-login ID.
- Why store a session-token hash? A database-only leak should not immediately yield usable browser tokens.
- Why is logout server-side? A copied cookie must stop working after the old session is revoked.
- What do Secure, HttpOnly, and SameSite do? Explain each flag and its limits; flags do not replace HTTPS, CSRF tokens, or authorization checks.
- How is a reused OTP rejected? The consumed time step is persisted atomically and subsequent checks require a newer step.
- Why must rate limits survive restarting login? Otherwise an attacker could start new verification flows to guess more codes.
- What prevents CSRF? A random session-bound form token checked before state changes.
- How does SQL injection prevention work? SQL structure and supplied values are passed separately.
- Why not rely on browser validation? Attackers can send their own HTTP requests.
- What does the self-signed certificate demonstrate? Encrypted local transport; browser trust is a separate concern.
- What remains unfinished for a production system? Deployment, certificate management, verified contact/recovery flows, stronger availability controls, monitoring, operational key management, and broader review.

## Submission checklist

- Working local app and source code.
- README with reproducible setup and pinned tested dependencies.
- Shared repository and meaningful commits from every member.
- Completed control/implementation/test checklist.
- Actual sanitized screenshots of blocked attempts and other controls.
- 10–15 page report with limitations, conclusion, and references.
- Demo and individual viva preparation.
- Testing only on owned or explicitly authorized systems.

## Bonus demo addition

Request a reset for a test account, read the local message with `python scripts/show_reset_link.py EMAIL`, reset the password, show that the old link is rejected, and sign in with the new password plus authenticator. Show token expiry through tests or a documented short-timeout demonstration. Hide full token URLs and message contents in shared screenshots. Explain that private local outbox delivery simulates an email channel.
