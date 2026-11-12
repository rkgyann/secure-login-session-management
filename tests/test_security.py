import re
import sqlite3
import time

from cryptography.fernet import Fernet
import pyotp
import pytest

from app import create_app
from app.security import COOKIE, digest

BASE = 'https://localhost'
PASSWORD = 'a long unique student passphrase'


@pytest.fixture
def app(tmp_path):
    return create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'test.sqlite'),
                       'RESET_OUTBOX': str(tmp_path / 'outbox'),
                       'TOTP_ENCRYPTION_KEY': Fernet.generate_key().decode()})


@pytest.fixture
def client(app):
    return app.test_client()


def db(app):
    connection = sqlite3.connect(app.config['DATABASE'])
    connection.row_factory = sqlite3.Row
    return connection


def csrf(client, path):
    if path == '/logout':
        path = '/dashboard'
    response = client.get(path, base_url=BASE, follow_redirects=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


def post(client, path, data=None):
    return client.post(path, data={'csrf_token': csrf(client, path), **(data or {})}, base_url=BASE)


def register(client, name='Test Student', email='student@example.test'):
    return post(client, '/register', {'name': name, 'email': email,
                                     'password': PASSWORD, 'confirm_password': PASSWORD})


def secret(app):
    with db(app) as connection:
        encrypted = connection.execute('SELECT totp_secret FROM users ORDER BY id LIMIT 1').fetchone()[0]
    return app.extensions['fernet'].decrypt(encrypted.encode()).decode()


def enroll(app, client):
    register(client)
    result = post(client, '/setup-2fa', {'code': pyotp.TOTP(secret(app)).now()})
    assert result.status_code == 302
    assert result.location.endswith('/dashboard')


def login(client, email='student@example.test', password=PASSWORD):
    return post(client, '/login', {'email': email, 'password': password})


def test_registration_hash_encrypted_secret_and_validation(app, client):
    assert post(client, '/register', {'name': 'x', 'email': 'bad', 'password': 'short'}).status_code == 400
    assert register(client).status_code == 302
    with db(app) as connection:
        user = connection.execute('SELECT * FROM users').fetchone()
    assert user['password_hash'].startswith('$argon2id$')
    assert PASSWORD not in user['password_hash']
    assert app.extensions['password_hasher'].verify(user['password_hash'], PASSWORD)
    assert user['totp_secret'] != secret(app)


def test_csrf_cannot_be_bypassed(app, client):
    client.get('/register', base_url=BASE)
    assert client.post('/register', base_url=BASE, data={'name': 'Attacker'}).status_code == 400
    assert client.post('/logout', base_url=BASE, data={'csrf_token': 'forged'}).status_code == 400
    with db(app) as connection:
        assert connection.execute('SELECT count(*) FROM users').fetchone()[0] == 0


def test_no_dashboard_before_both_factors(app, client):
    assert client.get('/dashboard', base_url=BASE).status_code == 302
    register(client)
    assert client.get('/dashboard', base_url=BASE).location.endswith('/login')
    assert client.get('/setup-2fa/qr.png', base_url=BASE).mimetype == 'image/png'
    assert post(client, '/setup-2fa', {'code': 'notnum'}).status_code == 401
    assert client.get('/dashboard', base_url=BASE).status_code == 302


def test_successful_enrollment_rotation_and_logout_revocation(app, client):
    register(client)
    old = client.get_cookie(COOKIE).value
    assert post(client, '/setup-2fa', {'code': pyotp.TOTP(secret(app)).now()}).status_code == 302
    authenticated = client.get_cookie(COOKIE).value
    assert old != authenticated
    assert client.get('/dashboard', base_url=BASE).status_code == 200
    assert post(client, '/logout').status_code == 302
    client.set_cookie(COOKIE, authenticated)
    assert client.get('/dashboard', base_url=BASE).status_code == 302
    with db(app) as connection:
        assert connection.execute('SELECT 1 FROM sessions WHERE token_hash = ?', (digest(authenticated),)).fetchone() is None


def test_otp_replay_and_successful_new_step(app, client, monkeypatch):
    enroll(app, client)
    used = pyotp.TOTP(secret(app)).now()
    post(client, '/logout')
    assert login(client).location.endswith('/verify-2fa')
    assert client.get('/dashboard', base_url=BASE).status_code == 302
    assert post(client, '/verify-2fa', {'code': used}).status_code == 401
    # Move test clock only; never change the computer clock.
    future = int(time.time()) + 30
    monkeypatch.setattr('app.security.now', lambda: future)
    assert post(client, '/verify-2fa', {'code': pyotp.TOTP(secret(app)).at(future)}).location.endswith('/dashboard')


def test_login_rate_limit_and_expiry(app, client, monkeypatch):
    for _ in range(5):
        assert login(client, password='wrong').status_code == 401
    assert login(client, password='wrong').status_code == 429
    future = int(time.time()) + 301
    monkeypatch.setattr('app.security.now', lambda: future)
    assert login(client, password='wrong').status_code == 401


def test_totp_rate_limit_survives_new_login(app, client):
    enroll(app, client)
    post(client, '/logout')
    login(client)
    for _ in range(4):  # Enrollment used the first of five permitted submissions.
        assert post(client, '/verify-2fa', {'code': 'abcdef'}).status_code == 401
    assert post(client, '/verify-2fa', {'code': 'abcdef'}).status_code == 429
    login(client)
    assert post(client, '/verify-2fa', {'code': 'abcdef'}).status_code == 429


@pytest.mark.parametrize('field,age', [('last_seen', 601), ('created_at', 3601)])
def test_idle_and_absolute_expiry(app, client, field, age):
    enroll(app, client)
    with db(app) as connection:
        if field == 'last_seen':
            connection.execute('UPDATE sessions SET last_seen = ?', (int(time.time()) - age,))
        else:
            connection.execute('UPDATE sessions SET expires_at = ?', (int(time.time()) - 1,))
    assert client.get('/dashboard', base_url=BASE).status_code == 302


def test_cookie_and_headers(client):
    response = client.get('/login', base_url=BASE)
    cookie = response.headers['Set-Cookie']
    for flag in ('Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'):
        assert flag in cookie
    assert 'Domain=' not in cookie
    assert response.headers['Strict-Transport-Security'] == 'max-age=31536000'
    assert "script-src 'none'" in response.headers['Content-Security-Policy']
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['Cache-Control'] == 'no-store'


def test_sql_injection_and_generic_errors(app, client):
    register(client)
    post(client, '/logout')
    wrong = login(client, password='wrong')
    unknown = login(client, email="' OR 1=1 --", password='wrong')
    assert wrong.status_code == unknown.status_code == 401
    assert 'Unable to sign in. Check your details or try again later.' in unknown.text
    with db(app) as connection:
        assert connection.execute('SELECT count(*) FROM users').fetchone()[0] == 1


def test_template_escaping(app, client):
    register(client, name='<script>alert(1)</script>')
    post(client, '/setup-2fa', {'code': pyotp.TOTP(secret(app)).now()})
    text = client.get('/dashboard', base_url=BASE).text
    assert '<script>alert(1)</script>' not in text
    assert '&lt;script&gt;' in text


def test_secret_unavailable_after_enrollment(app, client):
    enroll(app, client)
    assert client.get('/setup-2fa/qr.png', base_url=BASE).status_code == 302
    post(client, '/logout')
    login(client)
    assert client.get('/setup-2fa/qr.png', base_url=BASE).status_code == 302


def test_password_change_requires_both_factors_and_revokes_sessions(app, client, monkeypatch):
    enroll(app, client)
    old_cookie = client.get_cookie(COOKIE).value
    other = app.test_client()
    other.set_cookie(COOKIE, old_cookie)
    future = int(time.time()) + 30
    monkeypatch.setattr('app.security.now', lambda: future)
    data = {'current_password': PASSWORD, 'new_password': 'replacement long passphrase',
            'confirm_password': 'replacement long passphrase', 'code': 'bad'}
    assert post(client, '/security', data).status_code == 400
    data['code'] = pyotp.TOTP(secret(app)).at(future)
    assert post(client, '/security', data).location.endswith('/login')
    assert other.get('/dashboard', base_url=BASE).status_code == 302
    assert login(client, password=PASSWORD).status_code == 401
    assert login(client, password=data['new_password']).location.endswith('/verify-2fa')


def test_wrong_host_and_large_request(client):
    assert client.get('/', base_url='https://untrusted.example').status_code == 400
    assert client.post('/login', base_url=BASE, data={'email': 'x' * 20000}).status_code == 413


def reset_link(app, client):
    from pathlib import Path
    response = post(client, '/forgot-password', {'email': 'student@example.test'})
    assert response.status_code == 200
    text = next(Path(app.config['RESET_OUTBOX']).glob('*.txt')).read_text()
    return re.search(r'https://\S+', text).group()


def submit_reset(client, token, password='a completely new passphrase'):
    return client.post('/reset-password', base_url=BASE,
                       data={'csrf_token': csrf(client, '/forgot-password'), 'token': token,
                             'password': password, 'confirm_password': password})


def token_from(link):
    from urllib.parse import parse_qs, urlsplit
    return parse_qs(urlsplit(link).query)['token'][0]


def test_reset_request_generic_private_hashed_and_rate_limited(app, client):
    from pathlib import Path
    register(client)
    exists = post(client, '/forgot-password', {'email': 'student@example.test'})
    unknown = post(client, '/forgot-password', {'email': 'unknown@example.test'})
    assert exists.status_code == unknown.status_code == 200
    assert exists.text == unknown.text
    assert '?token=' not in exists.text
    outbox = Path(app.config['RESET_OUTBOX'])
    message = next(outbox.glob('*.txt'))
    assert message.stat().st_mode & 0o777 == 0o600
    assert outbox.stat().st_mode & 0o777 == 0o700
    token = token_from(re.search(r'https://\S+', message.read_text()).group())
    with db(app) as connection:
        row = connection.execute('SELECT * FROM password_resets').fetchone()
    assert row['token_hash'] == digest(token)
    assert token not in row['token_hash']
    assert row['expires_at'] - int(time.time()) <= 900
    for _ in range(2):
        post(client, '/forgot-password', {'email': 'student@example.test'})
    assert post(client, '/forgot-password', {'email': 'student@example.test'}).status_code == 429


def test_reset_single_use_revokes_sessions_and_preserves_totp(app, client):
    enroll(app, client)
    old_cookie = client.get_cookie(COOKIE).value
    token = token_from(reset_link(app, client))
    assert submit_reset(client, token).location.endswith('/reset-complete')
    assert submit_reset(client, token).status_code == 400
    stolen = app.test_client()
    stolen.set_cookie(COOKIE, old_cookie)
    assert stolen.get('/dashboard', base_url=BASE).status_code == 302
    assert login(client, password=PASSWORD).status_code == 401
    assert login(client, password='a completely new passphrase').location.endswith('/verify-2fa')
    assert client.get('/dashboard', base_url=BASE).status_code == 302
    with db(app) as connection:
        assert connection.execute('SELECT totp_enabled FROM users').fetchone()[0] == 1
        assert connection.execute('SELECT count(*) FROM password_resets').fetchone()[0] == 0


def test_reset_expiry_and_forged_token(app, client, monkeypatch):
    register(client)
    token = token_from(reset_link(app, client))
    future = int(time.time()) + 901
    monkeypatch.setattr('app.security.now', lambda: future)
    assert client.get('/reset-password', query_string={'token': token}, base_url=BASE).status_code == 400
    assert submit_reset(client, token).status_code == 400
    assert submit_reset(client, 'forged-token').status_code == 400
    assert submit_reset(client, 'x' * 43).status_code == 400


def test_reset_get_and_invalid_password_do_not_consume(app, client):
    register(client)
    token = token_from(reset_link(app, client))
    for _ in range(2):
        page = client.get('/reset-password', query_string={'token': token}, base_url=BASE)
        assert page.status_code == 200
        assert page.headers['Referrer-Policy'] == 'no-referrer'
        assert page.headers['Cache-Control'] == 'no-store'
    assert submit_reset(client, token, password='short').status_code == 400
    assert submit_reset(client, token).status_code == 302


def test_reset_new_link_supersedes_old_and_csrf_is_required(app, client):
    register(client)
    old = token_from(reset_link(app, client))
    new = token_from(reset_link(app, client))
    assert old != new
    assert submit_reset(client, old).status_code == 400
    assert client.post('/reset-password', base_url=BASE,
                       data={'token': new, 'password': 'a completely new passphrase',
                             'confirm_password': 'a completely new passphrase'}).status_code == 400
    assert submit_reset(client, new).status_code == 302


def test_reset_guessing_throttled_and_get_does_not_leak_to_host(app, client):
    register(client)
    link = reset_link(app, client)
    assert link.startswith('https://localhost:5443/reset-password?token=')
    for _ in range(60):
        assert client.get('/reset-password?token=invalid', base_url=BASE).status_code == 400
    assert client.get('/reset-password?token=invalid', base_url=BASE).status_code == 429


def test_password_change_invalidates_pending_reset_link(app, client, monkeypatch):
    enroll(app, client)
    token = token_from(reset_link(app, client))
    future = int(time.time()) + 30
    monkeypatch.setattr('app.security.now', lambda: future)
    assert post(client, '/security', {'current_password': PASSWORD, 'new_password': 'another secure passphrase',
                'confirm_password': 'another secure passphrase',
                'code': pyotp.TOTP(secret(app)).at(future)}).status_code == 302
    assert submit_reset(client, token).status_code == 400


def test_reset_token_redacted_from_access_logs():
    import logging
    from app.password_reset import RedactResetToken
    record = logging.LogRecord('werkzeug', logging.INFO, '', 1,
                               'GET /reset-password?token=%s HTTP/1.1', ('very-secret-value',), None)
    assert RedactResetToken().filter(record)
    assert 'very-secret-value' not in record.getMessage()
    assert '[redacted]' in record.getMessage()


def test_concurrent_reset_only_one_request_succeeds(app, client):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    register(client)
    token = token_from(reset_link(app, client))
    clients = [app.test_client(), app.test_client()]
    csrf_tokens = [csrf(item, '/forgot-password') for item in clients]
    barrier = Barrier(2)

    def consume(index):
        barrier.wait(timeout=5)
        return clients[index].post('/reset-password', base_url=BASE,
                data={'csrf_token': csrf_tokens[index], 'token': token,
                      'password': 'concurrent secure passphrase',
                      'confirm_password': 'concurrent secure passphrase'}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, range(2)))
    assert sorted(results) == [302, 400]
