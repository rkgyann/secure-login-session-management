import os
import logging
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, render_template
from werkzeug.exceptions import SecurityError

from .database import close_db, init_db
from .security import finish_response, load_session


def create_app(test_config=None):
    root = Path(__file__).resolve().parent.parent
    load_dotenv(root / '.env')
    app = Flask(__name__, instance_path=str(root / 'instance'))
    app.config.update(DATABASE=str(root / 'instance' / 'portal.sqlite'),
                      TOTP_ENCRYPTION_KEY=os.getenv('TOTP_ENCRYPTION_KEY'),
                      IDLE_SECONDS=600, ABSOLUTE_SECONDS=3600,
                      RESET_SECONDS=900,
                      RESET_BASE_URL='https://localhost:5443',
                      RESET_OUTBOX=str(root / 'instance' / 'reset-outbox'),
                      MAX_CONTENT_LENGTH=16 * 1024,
                      TRUSTED_HOSTS=['localhost', '127.0.0.1'])
    if test_config:
        app.config.update(test_config)
    if not app.config['TOTP_ENCRYPTION_KEY']:
        raise RuntimeError('Run python scripts/setup_local.py first to generate the local encryption key.')
    app.extensions['fernet'] = Fernet(app.config['TOTP_ENCRYPTION_KEY'])
    app.extensions['password_hasher'] = PasswordHasher()
    app.extensions['dummy_hash'] = app.extensions['password_hasher'].hash('dummy-' + os.urandom(32).hex())
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
    app.before_request(load_session)
    app.after_request(finish_response)
    from .routes import bp
    app.register_blueprint(bp)
    from .password_reset import bp as reset_bp, RedactResetToken
    app.register_blueprint(reset_bp)
    access_logger = logging.getLogger('werkzeug')
    if not any(isinstance(item, RedactResetToken) for item in access_logger.filters):
        access_logger.addFilter(RedactResetToken())

    @app.errorhandler(400)
    @app.errorhandler(413)
    def error_page(error):
        if isinstance(error, SecurityError):
            return 'Invalid host.', 400, {'Content-Type': 'text/plain; charset=utf-8'}
        return render_template('error.html', error=error), error.code

    return app
