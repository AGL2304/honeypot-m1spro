"""Dépendances FastAPI — connexion DB et utilisateur courant (J3/J4).

`get_current_user` valide le Bearer JWT (whitelist d'algos, expiration, type,
révocation) et charge l'utilisateur. Toute route protégée en dépend ; les
contrôles d'ownership se font ensuite au niveau repository (anti-BOLA).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import repository
from .database import connect, init_db
from .security import decode_token

# auto_error=False : on renvoie nos propres 401 génériques (pas de détail).
_bearer = HTTPBearer(auto_error=False)


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    """Fournit une connexion SQLite par requête. Réutilise le chemin configuré.

    En test, `app.state.db_path` peut surcharger la base (fichier temporaire).
    """
    db_path = getattr(request.app.state, "db_path", None)
    conn = connect(db_path)
    try:
        init_db(conn)
        yield conn
    finally:
        conn.close()


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    conn: Annotated[sqlite3.Connection, Depends(get_db)],
) -> dict[str, Any]:
    """Authentifie via Bearer JWT. 401 générique si quoi que ce soit cloche."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentification requise ou invalide.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    payload = decode_token(credentials.credentials, expected_type="access")
    if payload is None:
        raise unauthorized

    user = repository.get_user_by_id(conn, payload["sub"])
    if user is None:
        raise unauthorized
    return user


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]
DbConn = Annotated[sqlite3.Connection, Depends(get_db)]
