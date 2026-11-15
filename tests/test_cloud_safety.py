from cryptography.fernet import Fernet
from app import create_app

def test_hosted_reset_is_not_exposed_when_disabled(tmp_path):
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'hosted.sqlite'), 'TOTP_ENCRYPTION_KEY': Fernet.generate_key().decode(), 'RESET_ENABLED': False})
    client = app.test_client()
    page = client.get('/login', base_url='https://localhost')
    assert 'Password reset is not available' in page.text
    assert client.get('/forgot-password', base_url='https://localhost').status_code == 404
    assert 'not verified' in client.get('/register', base_url='https://localhost').text
