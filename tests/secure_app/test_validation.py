"""Tests de validation d'entrée (J1) : mots de passe faibles, usernames réservés."""

from __future__ import annotations

import pytest

from .conftest import STRONG_PASSWORD


@pytest.mark.parametrize(
    "password",
    [
        "short1!A",          # trop court (<12)
        "alllowercase123!",  # pas de majuscule
        "ALLUPPERCASE123!",  # pas de minuscule
        "NoDigitsHere!!!",   # pas de chiffre
        "NoSpecialChar123",  # pas de caractère spécial
    ],
)
def test_weak_password_rejected(client, password):
    resp = client.post(
        "/auth/register",
        json={"username": "newuser", "email": "new@example.com", "password": password},
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("username", ["admin", "root", "ab", "bad name", "with;semi"])
def test_invalid_or_reserved_username_rejected(client, username):
    resp = client.post(
        "/auth/register",
        json={"username": username, "email": "u@example.com", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 422


def test_invalid_email_rejected(client):
    resp = client.post(
        "/auth/register",
        json={"username": "validuser", "email": "not-an-email", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 422


def test_valid_registration_accepted(client):
    resp = client.post(
        "/auth/register",
        json={"username": "validuser", "email": "valid@example.com", "password": STRONG_PASSWORD},
    )
    assert resp.status_code == 201
