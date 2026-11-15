# Cloud deployment

This branch runs the original Flask application with PostgreSQL. Render supplies `RENDER_EXTERNAL_HOSTNAME` and `PORTAL_MASTER_SECRET`; configure `DATABASE_PASSWORD` as a secret. Never change the master secret while retaining the database: existing authenticator secrets would become unreadable. The cloud branch connects to the configured Supabase session pooler with TLS. Do not commit passwords or keys.

Hosted registration, Argon2id, TOTP, CSRF, session expiry and rate limits use PostgreSQL. Email addresses are usernames and are not verified. Password reset and email delivery are disabled on Render because the original local outbox cannot deliver email. Visitors are informed of both limitations. Free hosting may sleep; free Supabase projects may pause. This is an educational project, not a claim of production hardening.

Local tests: `python -m pytest -q`. The original SQLite mode remains available for local development.
