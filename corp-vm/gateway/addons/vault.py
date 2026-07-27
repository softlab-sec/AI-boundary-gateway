"""Deterministic pseudonymisation vault. HMAC tokens, reversible on our side only."""
from __future__ import annotations
import hmac, hashlib, os, sqlite3, threading, pathlib

DB_PATH = pathlib.Path(os.getenv("VAULT_DB", "/var/lib/boundary/vault.db"))
SECRET = os.getenv("VAULT_SECRET", "change-me-in-production").encode()
_lock = threading.Lock()


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS tokens(
        token TEXT PRIMARY KEY, value TEXT, label TEXT, first_seen REAL DEFAULT (strftime('%s','now')))""")
    return c


_db = _conn()


def tokenise(label: str, value: str) -> str:
    digest = hmac.new(SECRET, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()[:8]
    token = f"<<{label}_{digest}>>"
    with _lock:
        _db.execute("INSERT OR IGNORE INTO tokens(token,value,label) VALUES(?,?,?)",
                    (token, value, label))
        _db.commit()
    return token


def detokenise(text: str) -> str:
    if "<<" not in text:
        return text
    with _lock:
        rows = _db.execute("SELECT token,value FROM tokens").fetchall()
    for token, value in rows:
        if token in text:
            text = text.replace(token, value)
    return text


def stats() -> dict:
    with _lock:
        n = _db.execute("SELECT count(*) FROM tokens").fetchone()[0]
    return {"tokens_held": n, "db": str(DB_PATH)}
