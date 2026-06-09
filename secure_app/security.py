"""Primitives cryptographiques — hashing, JWT, MFA (J3).

- Mots de passe : **Argon2id** (vainqueur Password Hashing Competition 2015,
  memory-hard). Jamais de MD5/SHA1/SHA256-nu (cf. LinkedIn 2012, Adobe 2013).
- Jetons : **JWT** signés HS256 avec expiration courte, `jti` pour révocation,
  et **whitelist d'algorithmes** au décodage (bloque l'attaque `alg:none`).
- MFA : **TOTP** (RFC 6238) compatible Google Authenticator.

Anti-pattern à NE PAS reproduire (vu en J3) :
    jwt.decode(token, key, algorithms=["HS256", "none"])   # ❌ alg confusion
    jwt.decode(token, options={"verify_signature": False}) # ❌ signature ignorée
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .config import get_settings

# --- Mots de passe (Argon2id) --------------------------------------------
_settings = get_settings()
_hasher = PasswordHasher(
    time_cost=_settings.argon2_time_cost,
    memory_cost=_settings.argon2_memory_cost,
    parallelism=_settings.argon2_parallelism,
)


def hash_password(password: str) -> str:
    """Hash Argon2id (salt aléatoire intégré). Retourne le digest encodé."""
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Vérifie un mot de passe en temps quasi-constant (pas de leak par timing)."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        # Échec normal d'authentification : message générique côté appelant
        # (J5, pas d'oracle « mauvais user » vs « mauvais mot de passe »).
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True si les paramètres Argon2 ont évolué -> rehash au prochain login."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# --- JWT ------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(UTC)


def _create_token(sub: str, token_type: str, ttl_seconds: int, **claims: Any) -> str:
    settings = get_settings()
    payload: dict[str, Any] = {
        "sub": sub,
        "type": token_type,
        "jti": uuid.uuid4().hex,
        "iat": _now(),
        "exp": _now() + timedelta(seconds=ttl_seconds),
        **claims,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(user_id: str, **claims: Any) -> str:
    return _create_token(user_id, "access", get_settings().access_ttl_seconds, **claims)


def create_refresh_token(user_id: str) -> str:
    return _create_token(user_id, "refresh", get_settings().refresh_ttl_seconds)


def decode_token(token: str, *, expected_type: str) -> dict[str, Any] | None:
    """Décode + vérifie un JWT. None si invalide/expiré/mauvais type/révoqué.

    Sécurité : `algorithms` est une **whitelist** (un seul algo), `require`
    impose les claims critiques, et la révocation (`jti`) est consultée.
    """
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],  # whitelist stricte
            options={
                "verify_signature": True,
                "verify_exp": True,
                "require": ["exp", "sub", "jti", "type"],
            },
        )
    except jwt.InvalidTokenError:
        return None
    if payload.get("type") != expected_type:
        return None
    if is_revoked(payload["jti"]):
        return None
    return payload


# --- Révocation (blacklist en mémoire ; Redis avec TTL en prod) -----------
_revoked_jti: set[str] = set()


def revoke_token(jti: str) -> None:
    _revoked_jti.add(jti)


def is_revoked(jti: str) -> bool:
    return jti in _revoked_jti


def _reset_revocations_for_tests() -> None:
    """Helper réservé aux tests (réinitialise la blacklist en mémoire)."""
    _revoked_jti.clear()


# --- MFA / TOTP -----------------------------------------------------------
def generate_mfa_secret() -> str:
    """Secret base32 pour un nouvel enrôlement TOTP."""
    return pyotp.random_base32()


def mfa_provisioning_uri(secret: str, username: str, issuer: str = "secure_app") -> str:
    """URI otpauth:// à encoder en QR code (Google Authenticator / Authy)."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Vérifie un code TOTP (fenêtre ±1 pour tolérer le décalage d'horloge)."""
    if not code or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
