"""Fixtures de test pour secure_app.

On force `SECURE_APP_ENV=dev` + un secret de test AVANT l'import de l'app, puis
on isole chaque test dans une base SQLite temporaire via `app.state.db_path`.
La blacklist de révocation JWT (en mémoire) est réinitialisée entre les tests.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

# Doit être défini avant tout import de secure_app (get_settings est lru_cached).
os.environ.setdefault("SECURE_APP_ENV", "dev")
os.environ.setdefault("SECURE_APP_SECRET_KEY", "test-secret-key-of-sufficient-length-123456")
# Paramètres Argon2 réduits : tests rapides (pas un usage prod).
os.environ.setdefault("SECURE_APP_ARGON2_TIME", "1")
os.environ.setdefault("SECURE_APP_ARGON2_MEMORY", "8192")
os.environ.setdefault("SECURE_APP_ARGON2_PAR", "1")
# Pas de seed démo en test : les tests créent eux-mêmes alice/bob (évite les 409).
os.environ.setdefault("SECURE_APP_SEED_DEMO", "0")

from fastapi.testclient import TestClient  # noqa: E402

from secure_app import security  # noqa: E402
from secure_app.main import create_app  # noqa: E402
from secure_app.routers import auth as auth_router  # noqa: E402


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:
    """TestClient isolé : base temporaire, révocations + rate limiter remis à zéro.

    Le limiteur de login est défini au niveau module (état partagé entre
    instances d'app) : on le réinitialise pour ne pas faire fuiter les
    compteurs d'un test à l'autre.
    """
    app = create_app()
    app.state.db_path = str(tmp_path / "test.db")
    security._reset_revocations_for_tests()
    auth_router._login_limiter.reset()
    with TestClient(app) as c:
        yield c
    security._reset_revocations_for_tests()
    auth_router._login_limiter.reset()


# --- Helpers --------------------------------------------------------------
STRONG_PASSWORD = "Sup3r-S3cret!Pass"


def register(client: TestClient, username: str = "alice", email: str | None = None) -> None:
    resp = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email or f"{username}@example.com",
            "password": STRONG_PASSWORD,
        },
    )
    assert resp.status_code == 201, resp.text


def login(client: TestClient, username: str = "alice") -> str:
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
