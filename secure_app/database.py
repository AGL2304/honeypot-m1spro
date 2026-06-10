"""Accès base SQLite — connexion et schéma (J1 anti-injection SQL).

Toutes les requêtes de `repository.py` utilisent des **paramètres liés** (`?`),
jamais de f-string/concaténation. C'est la défense canonique contre l'injection
SQL (A03 OWASP, cf. Equifax 2017).

Anti-pattern interdit (vu en J1) :
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")  # ❌ SQLi
Pattern correct :
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # ✅
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,          -- UUID (anti-énumération, J4)
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,             -- Argon2id, jamais en clair
    mfa_secret    TEXT,                      -- NULL tant que MFA non activé
    mfa_enabled   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
    id         TEXT PRIMARY KEY,             -- UUID
    owner_id   TEXT NOT NULL,                -- FK users.id (contrôle d'ownership)
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id);

-- Coffre à secrets : valeur chiffrée au repos (AES-GCM via la clé applicative,
-- cf. crypto.py). Le clair ne touche jamais le disque. Ownership systématique
-- (anti-BOLA) et la liste ne renvoie qu'un APERÇU masqué, jamais le clair en
-- bloc -> contraste direct avec vuln_app (stockage en clair + dump SQLi).
CREATE TABLE IF NOT EXISTS secrets (
    id         TEXT PRIMARY KEY,             -- UUID
    owner_id   TEXT NOT NULL,                -- FK users.id (contrôle d'ownership)
    label      TEXT NOT NULL,
    value_enc  TEXT NOT NULL,                -- ciphertext (AES-256-GCM, base64)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secrets_owner ON secrets(owner_id);
"""


def connect(db_path: str | None = None) -> sqlite3.Connection:
    """Ouvre une connexion SQLite avec contraintes FK actives et row factory."""
    path = db_path or get_settings().db_path
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Crée les tables si absentes (idempotent)."""
    conn.executescript(_SCHEMA)
    conn.commit()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Contexte transactionnel : commit si OK, rollback si exception."""
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
