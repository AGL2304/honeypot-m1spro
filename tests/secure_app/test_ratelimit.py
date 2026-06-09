"""Test du rate limiting login (J4) : brute-force borné -> 429."""

from __future__ import annotations

from secure_app.config import get_settings

from .conftest import register


def test_login_rate_limited_after_max_attempts(client):
    register(client)
    settings = get_settings()

    # Les premières tentatives (mauvais mot de passe) renvoient 401.
    last_status = None
    for _ in range(settings.login_max_attempts + 3):
        resp = client.post(
            "/auth/login", json={"username": "alice", "password": "Wrong-Pass-123!"}
        )
        last_status = resp.status_code

    # Au-delà du quota dans la fenêtre, on bascule en 429 (Too Many Requests).
    assert last_status == 429


def test_rate_limit_sets_retry_after(client):
    register(client)
    settings = get_settings()
    resp = None
    for _ in range(settings.login_max_attempts + 3):
        resp = client.post(
            "/auth/login", json={"username": "alice", "password": "Wrong-Pass-123!"}
        )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
