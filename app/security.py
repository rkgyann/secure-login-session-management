"""Server-side sessions, synchronizer CSRF tokens, rate limits, and TOTP replay protection."""
import hashlib
import secrets
import time
from functools import wraps

import pyotp
from flask import abort, current_app, g, redirect, request, url_for
from .database import get_db

COOKIE = '__Host-portal'


def now():
    return int(time.time())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def new_session(stage='anonymous', user_id=None):
    db = get_db()
    if getattr(g, 'session', None):
        db.execute('DELETE FROM sessions WHERE token_hash = ?', (g.session['token_hash'],))
    token = secrets.token_urlsafe(32)
    timestamp = now()
    ttl = current_app.config['ABSOLUTE_SECONDS'] if stage == 'authenticated' else 300 if stage in ('enroll', 'verify') else 900
    db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)',
               (digest(token), user_id, stage, secrets.token_urlsafe(32), timestamp, timestamp, timestamp + ttl))
    g.session = db.execute('SELECT * FROM sessions WHERE token_hash = ?', (digest(token),)).fetchone()
    g.new_token = token


def load_session():
    if request.endpoint == 'static':
        return
    db = get_db()
    token = request.cookies.get(COOKIE, '')
    g.session = db.execute('SELECT * FROM sessions WHERE token_hash = ?', (digest(token),)).fetchone() if token else None
    if g.session:
        idle = current_app.config['IDLE_SECONDS'] if g.session['stage'] == 'authenticated' else 900
        if now() >= g.session['expires_at'] or now() - g.session['last_seen'] >= idle:
            db.execute('DELETE FROM sessions WHERE token_hash = ?', (g.session['token_hash'],))
            g.session = None
    if g.session is None:
        new_session()
    else:
        db.execute('UPDATE sessions SET last_seen = ? WHERE token_hash = ?', (now(), g.session['token_hash']))
    # Bounded cleanup of expired transient state on requests.
    db.execute('DELETE FROM rate_limits WHERE expires_at <= ?', (now(),))
    db.execute('DELETE FROM sessions WHERE expires_at <= ?', (now(),))
    db.commit()
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        supplied = request.form.get('csrf_token', '')
        if not secrets.compare_digest(supplied, g.session['csrf_token']):
            abort(400, description='Form expired or CSRF token invalid. Reload the page and try again.')


def finish_response(response):
    response.headers.update({
        'Content-Security-Policy': "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    })
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    if getattr(g, 'new_token', None):
        response.set_cookie(COOKIE, g.new_token, secure=True, httponly=True, samesite='Lax', path='/')
    return response


def require_stage(*stages):
    def decorator(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if g.session['stage'] not in stages:
                return redirect(url_for('portal.login'))
            return function(*args, **kwargs)
        return wrapped
    return decorator


def allowed(buckets):
    """Call inside BEGIN IMMEDIATE, to serialize updates across workers.

    Each tuple is (scope, identifier, max requests, fixed window seconds).
    Count all submissions, including successful ones. Blocked requests do not
    extend the window. Persist in SQLite rather than process memory.
    """
    db = get_db()
    keys = [(digest(scope + ':' + str(identifier)), maximum, window) for scope, identifier, maximum, window in buckets]
    for key, maximum, _ in keys:
        row = db.execute('SELECT * FROM rate_limits WHERE bucket = ?', (key,)).fetchone()
        if row and row['expires_at'] > now() and row['attempts'] >= maximum:
            return False
    for key, _, window in keys:
        db.execute('''INSERT INTO rate_limits VALUES (?, 1, ?)
            ON CONFLICT(bucket) DO UPDATE SET
            attempts = CASE WHEN rate_limits.expires_at <= ? THEN 1 ELSE rate_limits.attempts + 1 END,
            expires_at = CASE WHEN rate_limits.expires_at <= ? THEN excluded.expires_at ELSE rate_limits.expires_at END''',
                   (key, now() + window, now(), now()))
    return True


def audit(event, user_id=None):
    get_db().execute('INSERT INTO security_events(user_id, event, ip, created_at) VALUES (?, ?, ?, ?)',
                     (user_id, event, request.remote_addr or 'unknown', now()))


def consume_totp(user, code):
    """Atomically consume a step; a code cannot authenticate twice.

    Stored secrets need reversible encryption because TOTP must recompute codes.
    Password hashes, by contrast, are never decrypted.
    """
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    secret = current_app.extensions['fernet'].decrypt(user['totp_secret'].encode()).decode()
    totp = pyotp.TOTP(secret)
    step = now() // 30
    for candidate in (step, step - 1, step + 1):
        if candidate > user['last_totp_step'] and secrets.compare_digest(totp.at(candidate * 30), code):
            result = get_db().execute('UPDATE users SET last_totp_step = ? WHERE id = ? AND last_totp_step < ?',
                                      (candidate, user['id'], candidate))
            return result.rowcount == 1
    return False
