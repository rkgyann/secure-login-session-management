"""Single-use reset links with a private, local delivery outbox for the lab."""
import logging
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlencode

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from .database import get_db
from . import security as sec

bp = Blueprint('reset', __name__)
MESSAGE = 'If the account exists, a password-reset message has been queued. Follow its link within 15 minutes.'
INVALID = 'This reset link is invalid, expired, or already used. Request a new link.'


class RedactResetToken(logging.Filter):
    def filter(self, record):
        # Werkzeug's development access log otherwise includes query tokens.
        record.msg = re.sub(r'([?&]token=)[^\s"&]+', r'\1[redacted]', record.getMessage())
        record.args = ()
        return True


def write_reset_message(email, link):
    """Local mail simulation; never expose the outbox through an HTTP route."""
    outbox = Path(current_app.config['RESET_OUTBOX'])
    outbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    outbox.chmod(0o700)
    path = outbox / (sec.digest(email) + '.txt')
    # Atomic replacement: readers cannot see a partially written message.
    temporary = outbox / (secrets.token_hex(16) + '.tmp')
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
            file.write('LOCAL DEMO MESSAGE — no email was sent\n'
                       + 'To: ' + email + '\n\n'
                       + 'Reset your Secure Student Portal password:\n' + link + '\n\n'
                       + 'This link expires in 15 minutes and works once.\n'
                       + 'Ignore this message if you did not request it.\n')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')
    email = request.form.get('email', '').strip().casefold()[:254]
    db = get_db()
    db.execute('BEGIN IMMEDIATE')
    if not sec.allowed([('reset-request-account', email, 3, 900),
                        ('reset-request-ip', request.remote_addr, 15, 900)]):
        db.commit()
        return render_template('forgot_password.html', message=MESSAGE), 429
    user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    # Generate a token even for an unknown address; never return it in the response.
    token = secrets.token_urlsafe(32)
    db.execute('DELETE FROM password_resets WHERE expires_at <= ?', (sec.now(),))
    if user:
        db.execute('DELETE FROM password_resets WHERE user_id = ?', (user['id'],))
        db.execute('INSERT INTO password_resets VALUES (?, ?, ?)',
                   (sec.digest(token), user['id'], sec.now() + current_app.config['RESET_SECONDS']))
        # A configured origin avoids trusting request Host headers for reset URLs.
        link = current_app.config['RESET_BASE_URL'] + url_for('reset.reset_password') + '?' + urlencode({'token': token})
        try:
            write_reset_message(email, link)
        except OSError:
            db.execute('DELETE FROM password_resets WHERE token_hash = ?', (sec.digest(token),))
            sec.audit('password_reset_delivery_failed', user['id'])
            current_app.logger.warning('Local reset delivery failed; no usable reset token retained.')
        else:
            sec.audit('password_reset_requested', user['id'])
    db.commit()
    return render_template('forgot_password.html', message=MESSAGE)


@bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.form.get('token', '') if request.method == 'POST' else request.args.get('token', '')
    db = get_db()
    db.execute('BEGIN IMMEDIATE')
    if not sec.allowed([('reset-consume-ip', request.remote_addr, 60, 300)]):
        db.commit()
        return render_template('reset_password.html', error=INVALID, valid=False), 429
    token_hash = sec.digest(token) if 40 <= len(token) <= 128 else ''
    row = db.execute('SELECT * FROM password_resets WHERE token_hash = ? AND expires_at > ?',
                     (token_hash, sec.now())).fetchone()
    if row is None:
        db.commit()
        return render_template('reset_password.html', error=INVALID, valid=False), 400
    if request.method == 'GET':
        db.commit()
        return render_template('reset_password.html', token=token, valid=True)
    password = request.form.get('password', '')
    if not (12 <= len(password) <= 128 and password == request.form.get('confirm_password')):
        db.commit()
        return render_template('reset_password.html', token=token, valid=True,
                               error='Passwords must match and contain 12–128 characters.'), 400
    hashed = current_app.extensions['password_hasher'].hash(password)
    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed, row['user_id']))
    # All changes commit together: concurrent reuse cannot change the password twice.
    db.execute('DELETE FROM password_resets WHERE user_id = ?', (row['user_id'],))
    db.execute('DELETE FROM sessions WHERE user_id = ?', (row['user_id'],))
    sec.audit('password_reset_completed_sessions_revoked', row['user_id'])
    sec.new_session()
    db.commit()
    return redirect(url_for('reset.reset_complete'))


@bp.route('/reset-complete')
def reset_complete():
    return render_template('reset_complete.html')
