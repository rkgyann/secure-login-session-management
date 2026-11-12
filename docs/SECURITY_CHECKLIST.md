# Security checklist and evidence record

Fill the Actual result / screenshot column after your own manual demonstration. Automated tests are separate from real browser screenshots. Screenshot names below are proposed filenames, not evidence already captured.

| Control | Implementation | Automated verification | Manual evidence to capture |
| --- | --- | --- | --- |
| Salted password hash | Argon2id `PasswordHasher`; hash only in users table | `test_registration_hash_encrypted_secret_and_validation` | Show only the password_hash field, not TOTP seed/ciphertext or keys: `01-password-hash.png` |
| Input validation | Server length/shape checks; request body limit | Registration validation; `test_wrong_host_and_large_request` | Rejected invalid input: `02-validation.png` |
| Brute-force defence | Persistent fixed-window account and IP counters | `test_login_rate_limit_and_expiry` | Login sixth request, status 429: `03-login-blocked.png` |
| Generic login errors | Same text for unknown account/wrong password | `test_sql_injection_and_generic_errors` | Compare sanitized error messages: `04-generic-error.png` |
| TOTP second factor | Enrollment confirmation and restricted pre-auth stages | `test_no_dashboard_before_both_factors`; `test_otp_replay_and_successful_new_step` | Dashboard blocked before OTP, then authenticated dashboard: `05-second-factor.png` |
| OTP guessing and replay | Per-user/IP rate limits; atomic last-step update | OTP replay and TOTP throttling tests | Invalid/reused-code error with code field blank: `06-otp-rejected.png` |
| Random session IDs and rotation | 32-byte random tokens; only hashes in DB; rotation on authentication | `test_successful_enrollment_rotation_and_logout_revocation` | Explain rotation with test output; never publish token values |
| Cookie flags | Secure, HttpOnly, SameSite=Lax, host-only | `test_cookie_and_headers` | Browser cookie attributes with value hidden: `07-cookie-flags.png` |
| Session timeout | 10-minute idle and 1-hour absolute server-side expiry | `test_idle_and_absolute_expiry` | Redirect after inactivity; record temporary test timeout if used: `08-timeout.png` |
| Logout | CSRF-protected POST; server token deletion | Rotation/logout test | Dashboard denied after logout: `09-logout.png` |
| Security headers | HSTS on HTTPS; CSP; nosniff; DENY | `test_cookie_and_headers` | Network response headers or curl: `10-headers.png` |
| CSRF protection | Session synchronizer token checked before mutations | `test_csrf_cannot_be_bypassed` | Altered form token returns 400: `11-csrf-blocked.png` |
| SQL and output safety | Parameterized queries; Jinja autoescape; restrictive CSP | SQL input and template escaping tests | Literal escaped test name or denied injection attempt: `12-input-safety.png` |
| TOTP seed protection | Fernet encryption; setup QR restricted to enrollment | Hash/encryption and secret-access tests | Describe design; do not screenshot QR/seed |
| Password change | Current password + fresh code; revoke all sessions | Password-change test | Return to login and old password rejection: `13-password-change.png` |
| Local HTTPS | Self-signed localhost certificate, TLS server | Real local HTTPS smoke check separately from test client | Address/certificate details without private keys: `14-local-https.png` |
| Bonus: single-use reset link | Hashed random token, atomic consumption, latest-link replacement, session revocation | Reset single-use, supersession, concurrency, and session-revocation tests | Sanitized successful-reset page and used-link rejection: `15-reset-single-use.png` |
| Bonus: reset expiry | Server-side 15-minute token expiry | Reset expiry test | Expired-link rejection with token hidden: `16-reset-expired.png` |
| Reset safeguards | Generic request reply, request/guessing limits, CSRF, private local outbox, log redaction, retained TOTP | Reset generic/rate-limit, CSRF, permissions, log-redaction, and TOTP-preservation tests | Generic request reply and fresh authenticator prompt; no outbox contents |

For each captured test, record: date, test account alias, steps, expected result, actual result, and sanitized screenshot filename. Report failed or incomplete tests honestly.
