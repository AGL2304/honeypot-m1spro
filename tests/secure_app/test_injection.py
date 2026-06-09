"""Tests anti-injection (J1) : SQLi au login, command-injection au /ping."""

from __future__ import annotations

from .conftest import STRONG_PASSWORD, auth_header, login, register


def test_sql_injection_login_is_rejected(client):
    register(client)
    # Payload classique : si concaténé, contournerait l'auth. Ici requête
    # paramétrée -> traité comme un username littéral inexistant -> 401.
    resp = client.post(
        "/auth/login",
        json={"username": "alice' OR '1'='1", "password": "anything"},
    )
    assert resp.status_code == 401


def test_sql_injection_drop_table_is_inert(client):
    register(client)
    client.post(
        "/auth/login",
        json={"username": "alice'; DROP TABLE users;--", "password": "x"},
    )
    # La table existe toujours : un login légitime fonctionne ensuite.
    assert client.post(
        "/auth/login", json={"username": "alice", "password": STRONG_PASSWORD}
    ).status_code == 200


def test_command_injection_in_ping_is_rejected(client):
    register(client)
    token = login(client)
    # Métacaractères shell : doivent échouer à la validation (400), jamais exécutés.
    payloads = [
        "127.0.0.1; rm -rf /",
        "localhost && whoami",
        "$(reboot)",
        "8.8.8.8 | cat /etc/passwd",
    ]
    for payload in payloads:
        resp = client.post("/tools/ping", json={"host": payload}, headers=auth_header(token))
        assert resp.status_code == 400, payload


def test_ping_requires_auth(client):
    resp = client.post("/tools/ping", json={"host": "127.0.0.1"})
    assert resp.status_code == 401


def test_extra_fields_forbidden_mass_assignment(client):
    # extra="forbid" : un champ inconnu (ex. tentative d'élévation) est rejeté.
    resp = client.post(
        "/auth/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": STRONG_PASSWORD,
            "is_admin": True,
        },
    )
    assert resp.status_code == 422
