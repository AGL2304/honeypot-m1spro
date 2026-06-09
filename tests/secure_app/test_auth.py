"""Tests du flux d'authentification (J3) : register/login/refresh/logout + /me."""

from __future__ import annotations

from .conftest import STRONG_PASSWORD, auth_header, login, register


def test_register_then_login_returns_tokens(client):
    register(client)
    resp = client.post("/auth/login", json={"username": "alice", "password": STRONG_PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]
    assert body["expires_in"] > 0


def test_me_returns_public_fields_only(client):
    register(client)
    token = login(client)
    resp = client.get("/users/me", headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "alice"
    # Aucune fuite de champ sensible (anti property-disclosure, API3).
    assert "password_hash" not in body
    assert "mfa_secret" not in body


def test_me_requires_auth(client):
    resp = client.get("/users/me")
    assert resp.status_code == 401


def test_register_duplicate_is_neutral_conflict(client):
    register(client)
    resp = client.post(
        "/auth/register",
        json={"username": "alice", "email": "alice@example.com", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 409
    # Message neutre : ne confirme pas l'existence (anti-énumération).
    assert "alice" not in resp.json()["detail"].lower()


def test_wrong_password_generic_401(client):
    register(client)
    resp = client.post("/auth/login", json={"username": "alice", "password": "Wrong-Pass-123!"})
    assert resp.status_code == 401
    detail = resp.json()["detail"].lower()
    # Pas d'oracle username vs password.
    assert "mot de passe" not in detail and "username" not in detail


def test_unknown_user_same_generic_401(client):
    resp = client.post("/auth/login", json={"username": "ghost", "password": STRONG_PASSWORD})
    assert resp.status_code == 401


def test_refresh_rotation_revokes_old(client):
    register(client)
    tokens = client.post(
        "/auth/login", json={"username": "alice", "password": STRONG_PASSWORD}
    ).json()
    old_refresh = tokens["refresh_token"]

    r1 = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200

    # Rejeu de l'ancien refresh -> révoqué (rotation).
    r2 = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert r2.status_code == 401


def test_logout_revokes_access_token(client):
    register(client)
    token = login(client)
    assert client.get("/users/me", headers=auth_header(token)).status_code == 200

    assert client.post("/auth/logout", headers=auth_header(token)).status_code == 200
    # Token révoqué -> 401 ensuite.
    assert client.get("/users/me", headers=auth_header(token)).status_code == 401


def test_health_is_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'none'" in resp.headers.get("Content-Security-Policy", "")
    # API authentifiée : pas de mise en cache par un proxy partagé (CWE-524).
    assert resp.headers.get("Cache-Control") == "no-store"
