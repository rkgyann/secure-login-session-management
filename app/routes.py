import io
import re
import sqlite3

import pyotp
import qrcode
from argon2.exceptions import VerificationError, InvalidHashError
from flask import Blueprint, current_app, g, redirect, render_template, request, send_file, url_for

from .database import get_db
from .security import allowed, audit, consume_totp, new_session, now, require_stage

bp = Blueprint('portal', __name__)
GENERIC = 'Unable to sign in. Check your details or try again later.'


def user_record():
    return get_db().execute('SELECT * FROM users WHERE id = ?', (g.session['user_id'],)).fetchone()


def password_valid(stored, password):
    try:
        return current_app.extensions['password_hasher'].verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False


def normalize_email(value):
    return value.strip().casefold()


@bp.route('/')
def home():
    return render_template('home.html')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        db = get_db()
        db.execute('BEGIN IMMEDIATE')
        if not allowed([('register-ip', request.remote_addr, 10, 300)]):
            db.commit()
            return render_template('register.html', error='Too many submissions. Try again in five minutes.'), 429
        name = request.form.get('name', '').strip()
        email = normalize_email(request.form.get('email', ''))
        password = request.form.get('password', '')
        if not (2 <= len(name) <= 80 and 3 <= len(email) <= 254 and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email)
                and 12 <= len(password) <= 128 and password == request.form.get('confirm_password')):
            error = 'Use a name of 2–80 characters, a valid email, and matching passwords of 12–128 characters.'
        else:
            encrypted = current_app.extensions['fernet'].encrypt(pyotp.random_base32().encode()).decode()
            password_hash = current_app.extensions['password_hasher'].hash(password)
            result = db.execute('INSERT INTO users(name, email, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO NOTHING RETURNING id',
                                (name, email, password_hash, encrypted, now())).fetchone()
            if not result:
                error = 'Unable to register with these details. Try signing in or use different details.'
            else:
                user_id = result['id']
                audit('registered', user_id)
                new_session('enroll', user_id)
                db.commit()
                return redirect(url_for('portal.setup_totp'))
        db.commit()
    return render_template('register.html', error=error), 400 if error else 200


@bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = normalize_email(request.form.get('email', ''))[:254]
        password = request.form.get('password', '')
        db = get_db()
        db.execute('BEGIN IMMEDIATE')
        if not allowed([('login-account', email, 5, 300), ('login-ip', request.remote_addr, 30, 300)]):
            audit('login_throttled')
            db.commit()
            return render_template('login.html', error=GENERIC), 429
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        stored = user['password_hash'] if user else current_app.extensions['dummy_hash']
        valid = password_valid(stored, password) if len(password) <= 128 else False
        if user and valid:
            hasher = current_app.extensions['password_hasher']
            if hasher.check_needs_rehash(stored):
                db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hasher.hash(password), user['id']))
            stage = 'verify' if user['totp_enabled'] else 'enroll'
            new_session(stage, user['id'])
            audit('password_verified', user['id'])
            db.commit()
            return redirect(url_for('portal.verify_totp' if user['totp_enabled'] else 'portal.setup_totp'))
        audit('login_failed', user['id'] if user else None)
        db.commit()
        error = GENERIC
    return render_template('login.html', error=error), 401 if error else 200


@bp.route('/setup-2fa', methods=['GET', 'POST'])
@require_stage('enroll')
def setup_totp():
    return totp_page(enrolling=True)


@bp.route('/verify-2fa', methods=['GET', 'POST'])
@require_stage('verify')
def verify_totp():
    return totp_page(enrolling=False)


def totp_page(enrolling):
    db = get_db()
    error = None
    if request.method == 'POST':
        db.execute('BEGIN IMMEDIATE')
    user = user_record()
    # A second pending enrollment session must never reveal an already-enabled secret.
    if enrolling and user['totp_enabled']:
        new_session('verify', user['id'])
        db.commit()
        return redirect(url_for('portal.verify_totp'))
    if request.method == 'POST':
        if not allowed([('totp-user', user['id'], 5, 300), ('totp-ip', request.remote_addr, 30, 300)]):
            audit('totp_throttled', user['id'])
            db.commit()
            return render_template('totp.html', enrolling=False, error=GENERIC), 429
        if consume_totp(user, request.form.get('code', '')):
            db.execute('UPDATE users SET totp_enabled = 1 WHERE id = ?', (user['id'],))
            new_session('authenticated', user['id'])
            audit('login_success', user['id'])
            db.commit()
            return redirect(url_for('portal.dashboard'))
        audit('totp_failed', user['id'])
        db.commit()
        error = 'Invalid or already-used code. Wait for a fresh code, or try again later.'
    secret = current_app.extensions['fernet'].decrypt(user['totp_secret'].encode()).decode() if enrolling else None
    return render_template('totp.html', enrolling=enrolling, secret=secret, error=error), 401 if error else 200


@bp.route('/setup-2fa/qr.png')
@require_stage('enroll')
def totp_qr():
    user = user_record()
    if user['totp_enabled']:
        return '', 403
    secret = current_app.extensions['fernet'].decrypt(user['totp_secret'].encode()).decode()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user['email'], issuer_name='Secure Student Portal')
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')


@bp.route('/dashboard')
@require_stage('authenticated')
def dashboard():
    return render_template('dashboard.html', user=user_record(), remaining=max(0, g.session['expires_at'] - now()))


@bp.route('/security', methods=['GET', 'POST'])
@require_stage('authenticated')
def account_security():
    error = None
    if request.method == 'POST':
        db = get_db()
        db.execute('BEGIN IMMEDIATE')
        user = user_record()
        if not allowed([('password-change', user['id'], 5, 300)]):
            db.commit()
            return render_template('security.html', error=GENERIC), 429
        new_password = request.form.get('new_password', '')
        old_password = request.form.get('current_password', '')
        if not (12 <= len(new_password) <= 128 and new_password == request.form.get('confirm_password')):
            error = 'New passwords must match and contain 12–128 characters.'
        elif len(old_password) > 128 or not password_valid(user['password_hash'], old_password):
            error = GENERIC
        elif not consume_totp(user, request.form.get('code', '')):
            error = 'Invalid or already-used authenticator code.'
        else:
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                       (current_app.extensions['password_hasher'].hash(new_password), user['id']))
            db.execute('DELETE FROM sessions WHERE user_id = ?', (user['id'],))
            db.execute('DELETE FROM password_resets WHERE user_id = ?', (user['id'],))
            audit('password_changed_sessions_revoked', user['id'])
            new_session()
            db.commit()
            return redirect(url_for('portal.login'))
        db.commit()
    return render_template('security.html', error=error), 400 if error else 200


@bp.route('/logout', methods=['POST'])
def logout():
    db = get_db()
    audit('logout', g.session['user_id'])
    new_session()
    db.commit()
    return redirect(url_for('portal.login'))
