"""Local lab operator tool. Never publish its output or expose it as a route."""
import hashlib
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit('Usage: python scripts/show_reset_link.py student@example.test')
email = sys.argv[1].strip().casefold()
path = Path(__file__).resolve().parent.parent / 'instance' / 'reset-outbox' / (hashlib.sha256(email.encode()).hexdigest() + '.txt')
if not path.is_file():
    raise SystemExit('No local message found. Request a reset for an existing account first.')
print(path.read_text())
