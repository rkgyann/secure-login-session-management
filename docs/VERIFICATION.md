# Verification record

Verified on 27 October 2026 in the project workspace using Python 3.14.0.

## Automated tests

Command: `.venv/bin/python -m pytest -q`

Original baseline: **15 passed in 2.51s**.

Bonus-feature verification in a staging copy: **24 passed in 3.87s**. Added checks cover private hashed reset tokens, generic messages, request/guessing rate limits, single use, expiry, forged links, session revocation, retained TOTP, CSRF, invalid input, latest-link replacement, password-change invalidation, access-log redaction, and two concurrent reset submissions.

Tests cover validation, Argon2id password storage, encrypted TOTP secrets, CSRF rejection, restricted pre-authentication access, enrollment and session rotation, logout revocation, OTP replay, login/OTP rate limits, fixed-window expiry, idle/absolute expiry, cookie flags and headers, SQL input, escaped HTML, seed access restrictions, password-change revocation, host checks, and request size limits.

## Local HTTPS smoke check

Started the real server using `python run.py` with its generated localhost certificate on port 5443. Port 5000 was occupied by the Mac's Control Center/AirPlay service, so this project uses 5443.

Requested `https://localhost:5443/login` using a HEAD request with local self-signed certificate verification bypassed for this check only.

Observed:

- HTTP 200 OK.
- HSTS: `max-age=31536000`.
- CSP with local resources and `script-src 'none'`.
- `X-Content-Type-Options: nosniff`.
- `X-Frame-Options: DENY`.
- `Cache-Control: no-store`.
- Session cookie marked Secure, HttpOnly, Path=/, SameSite=Lax, without a Domain attribute.

This check confirms an HTTPS connection and the server's headers. It does not demonstrate browser certificate trust or HSTS enforcement by a browser.

## Submission evidence still to collect

Actual browser screenshots, the group contribution history, the completed report, and the presentation/demo remain student submission tasks. No screenshots or manual browser results are claimed here. Follow `SECURITY_CHECKLIST.md` for the evidence plan.
