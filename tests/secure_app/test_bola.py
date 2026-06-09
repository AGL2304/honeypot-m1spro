"""Tests anti-BOLA/IDOR (J4) : un utilisateur ne lit/supprime que ses notes."""

from __future__ import annotations

from .conftest import auth_header, login, register


def _make_note(client, token, title="secret", body="contenu privé"):
    resp = client.post(
        "/notes", json={"title": title, "body": body}, headers=auth_header(token)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_user_cannot_read_another_users_note(client):
    register(client, username="alice")
    register(client, username="bob")
    alice = login(client, "alice")
    bob = login(client, "bob")

    note_id = _make_note(client, alice)

    # Bob devine l'UUID d'Alice -> 404 (pas 403 : on ne confirme pas l'existence).
    resp = client.get(f"/notes/{note_id}", headers=auth_header(bob))
    assert resp.status_code == 404

    # Alice, propriétaire, y accède.
    assert client.get(f"/notes/{note_id}", headers=auth_header(alice)).status_code == 200


def test_user_cannot_delete_another_users_note(client):
    register(client, username="alice")
    register(client, username="bob")
    alice = login(client, "alice")
    bob = login(client, "bob")

    note_id = _make_note(client, alice)
    assert client.delete(f"/notes/{note_id}", headers=auth_header(bob)).status_code == 404
    # La note d'Alice est intacte.
    assert client.get(f"/notes/{note_id}", headers=auth_header(alice)).status_code == 200


def test_list_only_returns_own_notes(client):
    register(client, username="alice")
    register(client, username="bob")
    alice = login(client, "alice")
    bob = login(client, "bob")

    _make_note(client, alice, title="a1")
    _make_note(client, bob, title="b1")

    alice_notes = client.get("/notes", headers=auth_header(alice)).json()
    assert {n["title"] for n in alice_notes} == {"a1"}
