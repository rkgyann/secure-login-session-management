import sqlite3
from pathlib import Path
from flask import current_app, g


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def init_db():
    db = get_db()
    db.executescript(Path(__file__).with_name('schema.sql').read_text())
    db.commit()


def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
