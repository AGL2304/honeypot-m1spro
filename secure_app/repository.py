"""Repository — accès données via requêtes paramétrées uniquement (J1).

Aucune chaîne SQL n'est construite par concaténation/f-string : tous les inputs
passent par des paramètres liés `?`. Les `notes` portent un `owner_id` consulté
systématiquement pour le contrôle d'ownership (anti-BOLA/IDOR, J4).
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


# --- Users ----------------------------------------------------------------
def create_user(
    conn: sqlite3.Connection, *, username: str, email: str, password_hash: str
) -> dict[str, Any]:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
        (user_id, username, email, password_hash),
    )
    conn.commit()
    return {"id": user_id, "username": username, "email": email}


def get_user_by_username(conn: sqlite3.Connection, username: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, username, email, password_hash, mfa_secret, mfa_enabled "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    return _row_to_dict(row)


def get_user_by_id(conn: sqlite3.Connection, user_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, username, email, mfa_enabled FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return _row_to_dict(row)


def username_or_email_exists(conn: sqlite3.Connection, username: str, email: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM users WHERE username = ? OR email = ? LIMIT 1",
        (username, email),
    ).fetchone()
    return row is not None


def set_mfa_secret(conn: sqlite3.Connection, user_id: str, secret: str) -> None:
    conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (secret, user_id))
    conn.commit()


def enable_mfa(conn: sqlite3.Connection, user_id: str) -> None:
    conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user_id,))
    conn.commit()


def update_password_hash(conn: sqlite3.Connection, user_id: str, password_hash: str) -> None:
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()


# --- Notes (ressource avec ownership) -------------------------------------
def create_note(
    conn: sqlite3.Connection, *, owner_id: str, title: str, body: str
) -> dict[str, Any]:
    note_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
        (note_id, owner_id, title, body),
    )
    conn.commit()
    return {"id": note_id, "owner_id": owner_id, "title": title, "body": body}


def get_note_for_owner(
    conn: sqlite3.Connection, note_id: str, owner_id: str
) -> dict[str, Any] | None:
    """Récupère une note SEULEMENT si elle appartient à `owner_id` (anti-BOLA).

    La clause `AND owner_id = ?` est la défense : un attaquant qui devine l'UUID
    d'autrui obtient None (-> 404), pas la ressource.
    """
    row = conn.execute(
        "SELECT id, owner_id, title, body, created_at FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, owner_id),
    ).fetchone()
    return _row_to_dict(row)


def list_notes_for_owner(conn: sqlite3.Connection, owner_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, owner_id, title, body, created_at FROM notes "
        "WHERE owner_id = ? ORDER BY created_at DESC",
        (owner_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_note_for_owner(conn: sqlite3.Connection, note_id: str, owner_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, owner_id),
    )
    conn.commit()
    return cur.rowcount > 0


# --- Secrets (ressource avec ownership + chiffrement au repos) -------------
# Le repository ne manipule QUE du ciphertext (`value_enc`) : le clair est
# chiffré/déchiffré dans le routeur via `crypto.py`. Toutes les requêtes filtrent
# par `owner_id` (anti-BOLA) et sont paramétrées (anti-SQLi).
def create_secret(
    conn: sqlite3.Connection, *, owner_id: str, label: str, value_enc: str
) -> dict[str, Any]:
    secret_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO secrets (id, owner_id, label, value_enc) VALUES (?, ?, ?, ?)",
        (secret_id, owner_id, label, value_enc),
    )
    conn.commit()
    return {"id": secret_id, "owner_id": owner_id, "label": label}


def list_secrets_for_owner(conn: sqlite3.Connection, owner_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, owner_id, label, value_enc, created_at FROM secrets "
        "WHERE owner_id = ? ORDER BY created_at DESC",
        (owner_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_secret_for_owner(
    conn: sqlite3.Connection, secret_id: str, owner_id: str
) -> dict[str, Any] | None:
    """Récupère un secret SEULEMENT s'il appartient à `owner_id` (anti-BOLA).

    Deviner l'UUID d'autrui renvoie None (-> 404), jamais le ciphertext d'autrui.
    """
    row = conn.execute(
        "SELECT id, owner_id, label, value_enc, created_at FROM secrets "
        "WHERE id = ? AND owner_id = ?",
        (secret_id, owner_id),
    ).fetchone()
    return _row_to_dict(row)


def delete_secret_for_owner(conn: sqlite3.Connection, secret_id: str, owner_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM secrets WHERE id = ? AND owner_id = ?",
        (secret_id, owner_id),
    )
    conn.commit()
    return cur.rowcount > 0


# --- Helpers de seed (démo) -----------------------------------------------
def count_users(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def create_user_with_id(
    conn: sqlite3.Connection, *, user_id: str, username: str, email: str, password_hash: str
) -> None:
    """Insertion idempotente d'un utilisateur à UUID fixe (seed démo)."""
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, email, password_hash) "
        "VALUES (?, ?, ?, ?)",
        (user_id, username, email, password_hash),
    )
    conn.commit()
