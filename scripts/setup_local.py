"""Generate local secrets/certificate once, without overwriting existing keys."""
import os
from pathlib import Path
import subprocess

from cryptography.fernet import Fernet

root = Path(__file__).resolve().parent.parent
env_file = root / '.env'
if not env_file.exists():
    # Restrict permissions at creation, before writing the encryption key.
    with os.fdopen(os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
        file.write('TOTP_ENCRYPTION_KEY=' + Fernet.generate_key().decode() + '\n')
    print('Created .env. Keep it private; losing this key prevents TOTP verification.')
else:
    print('Kept existing .env.')

certs = root / 'certs'
certs.mkdir(exist_ok=True, mode=0o700)
key, cert = certs / 'localhost.key', certs / 'localhost.crt'
if not key.exists() and not cert.exists():
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '365',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True)
    key.chmod(0o600)
    print('Created local self-signed HTTPS certificate.')
elif key.exists() and cert.exists():
    print('Kept existing certificate and private key.')
else:
    raise SystemExit('Certificate or key is missing. Restore the pair before continuing.')
print('Next: python run.py, then open https://localhost:5443')
