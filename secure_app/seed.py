"""Données de démonstration (seed) — comptes, notes et secrets de départ.

But : que l'IHM et le comparatif J5 aient des données « réalistes » dès le
premier démarrage (sinon la base secure est vide). Idempotent : ne s'exécute
que si la table ``users`` est vide. Les mêmes comptes existent côté ``vuln_app``
(avec mot de passe EN CLAIR et secrets dumpables) -> c'est tout le contraste.

⚠️ Comptes de démo à mot de passe connu : acceptable pour une vitrine
pédagogique éphémère, JAMAIS pour un déploiement réel.
"""

from __future__ import annotations

import logging
import sqlite3

from . import crypto, repository, security

logger = logging.getLogger("secure_app.seed")

# Mot de passe commun aux comptes de démo (fort : 12+, classes mixtes).
DEMO_PASSWORD = "Sup3r-S3cret!Pass"  # noqa: S105 (mot de passe de démo assumé, pas un secret de prod)

# UUID fixes -> seed rejouable sans doublon (INSERT OR IGNORE).
_ALICE = "11111111-1111-4111-8111-111111111111"
_BOB = "22222222-2222-4222-8222-222222222222"

_USERS = [
    (_ALICE, "alice", "alice@example.com"),
    (_BOB, "bob", "bob@example.com"),
]

# Secrets de départ par utilisateur (label, valeur en clair -> chiffrée au seed).
_SECRETS = {
    _ALICE: [
        ("Clé API production", "sk-live-9f2c7b1a4e8d6049b3aa12ce77f03d5e"),
        ("Mot de passe BDD", "P@ssw0rd-Prod-2026!"),
        ("Code de récupération", "RX7Q-22KD-9F1A-MM30"),
    ],
    _BOB: [
        ("Token GitHub", "ghp_8sd7Fk2LmN0pQrS1tUvWxYz3aB4cD5eF6gH"),
        ("PIN carte", "4071"),
    ],
}

_NOTES = {
    _ALICE: [
        ("Réunion sécurité", "Préparer le comparatif secure vs vuln pour le jury J5."),
        ("Idée", "Activer le MFA sur tous les comptes admin."),
    ],
    _BOB: [
        ("Todo", "Renouveler le certificat TLS avant expiration."),
    ],
}


def seed_if_empty(conn: sqlite3.Connection) -> None:
    """Insère les données de démo si la base ne contient aucun utilisateur."""
    try:
        if repository.count_users(conn) > 0:
            return  # déjà initialisée -> on ne touche à rien
        password_hash = security.hash_password(DEMO_PASSWORD)
        for user_id, username, email in _USERS:
            repository.create_user_with_id(
                conn, user_id=user_id, username=username, email=email,
                password_hash=password_hash,
            )
        for owner_id, notes in _NOTES.items():
            for title, body in notes:
                repository.create_note(conn, owner_id=owner_id, title=title, body=body)
        for owner_id, secrets in _SECRETS.items():
            for label, value in secrets:
                repository.create_secret(
                    conn, owner_id=owner_id, label=label, value_enc=crypto.encrypt(value)
                )
        logger.info("Seed démo inséré (%d comptes).", len(_USERS))
    except Exception:
        # Fail-open : un échec de seed ne doit jamais empêcher l'app de démarrer.
        logger.exception("Seed démo ignoré (erreur).")
