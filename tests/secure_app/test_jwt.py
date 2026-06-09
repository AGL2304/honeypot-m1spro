"""Tests de robustesse JWT (J3) : alg:none, mauvais type, signature falsifiée."""

from __future__ import annotations

import jwt

from secure_app import security
from secure_app.config import get_settings

from .conftest import auth_header, login, register


def test_alg_none_token_is_rejected(client):
    register(client)
    # Token forgé avec alg=none (sans signature) : l'attaque classique de
    # confusion d'algorithme. La whitelist [HS256] au décodage doit le rejeter.
    forged = jwt.encode(
        {"sub": "anyone", "type": "access", "jti": "x", "exp": 9999999999},
        key="",
        algorithm="none",
    )
    resp = client.get("/users/me", headers=auth_header(forged))
    assert resp.status_code == 401


def test_token_signed_with_wrong_key_is_rejected(client):
    register(client)
    forged = jwt.encode(
        {"sub": "anyone", "type": "access", "jti": "y", "exp": 9999999999},
        key="attacker-controlled-key-not-the-real-one!",
        algorithm="HS256",
    )
    resp = client.get("/users/me", headers=auth_header(forged))
    assert resp.status_code == 401


def test_refresh_token_cannot_be_used_as_access(client):
    register(client)
    settings = get_settings()
    # Un refresh token valide ne doit PAS authentifier une route protégée
    # (vérification du claim `type`).
    refresh = security.create_refresh_token("some-user-id")
    resp = client.get("/users/me", headers=auth_header(refresh))
    assert resp.status_code == 401
    assert settings.jwt_algorithm == "HS256"


def test_access_token_missing_required_claims_rejected(client):
    register(client)
    settings = get_settings()
    # Token sans `jti`/`type` : `require` au décodage doit le refuser.
    incomplete = jwt.encode(
        {"sub": "anyone", "exp": 9999999999},
        key=settings.secret_key,
        algorithm="HS256",
    )
    resp = client.get("/users/me", headers=auth_header(incomplete))
    assert resp.status_code == 401


def test_valid_access_token_accepted(client):
    register(client)
    token = login(client)
    assert client.get("/users/me", headers=auth_header(token)).status_code == 200
