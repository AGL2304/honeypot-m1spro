"""Chiffrement au repos des secrets — AES-256-GCM (J3 / secrets management).

Le coffre à secrets ne stocke JAMAIS le clair sur disque : chaque valeur est
chiffrée avec **AES-256-GCM** (AEAD : confidentialité + intégrité authentifiée).
La clé de chiffrement est *dérivée* de ``SECURE_APP_SECRET_KEY`` via HKDF-SHA256
avec un label dédié (séparation de domaine : la même clé maître sert aux JWT,
mais les sous-clés sont indépendantes).

Contraste avec ``vuln_app`` : là-bas la valeur est stockée EN CLAIR -> un dump
SQLi (sqlmap) ou une BOLA renvoie directement les secrets. Ici, même un vol de
la base SQLite ne livre que du ciphertext inutilisable sans la clé applicative.

Format stocké (base64 urlsafe) : ``nonce(12o) || ciphertext || tag(16o)``.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_settings

_NONCE_LEN = 12  # 96 bits, recommandé pour GCM
_INFO = b"secure_app/secrets/v1"  # label HKDF (séparation de domaine)


def _key() -> bytes:
    """Dérive une clé AES-256 (32 octets) depuis le secret applicatif (HKDF)."""
    master = get_settings().secret_key.encode("utf-8")
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=_INFO).derive(master)


def encrypt(plaintext: str) -> str:
    """Chiffre une valeur en clair -> token base64 (nonce||ct||tag)."""
    aes = AESGCM(_key())
    nonce = os.urandom(_NONCE_LEN)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt(token: str) -> str:
    """Déchiffre un token produit par :func:`encrypt`. Lève si altéré (tag GCM)."""
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    return AESGCM(_key()).decrypt(nonce, ct, None).decode("utf-8")
