"""Configuration centralisée — aucun secret en dur (J3 / J5 secrets).

Tous les paramètres sensibles proviennent de variables d'environnement
(`SECURE_APP_*`). En l'absence de `SECURE_APP_SECRET_KEY`, on **génère une clé
éphémère** et on journalise un avertissement : pratique en dev, mais les JWT
émis ne survivront pas à un redémarrage — c'est volontaire pour ne JAMAIS
embarquer de secret par défaut exploitable (anti-pattern Uber 2016 / Toyota 2022).
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger("secure_app.config")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Variable %s invalide (%r) -> défaut %d", name, raw, default)
        return default


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Paramètres immuables de l'application (chargés une seule fois)."""

    env: str = field(default_factory=lambda: os.environ.get("SECURE_APP_ENV", "dev"))
    secret_key: str = ""

    # JWT — durées courtes (J3 : access bref + refresh plus long).
    access_ttl_seconds: int = field(default_factory=lambda: _env_int("SECURE_APP_ACCESS_TTL", 900))
    refresh_ttl_seconds: int = field(
        default_factory=lambda: _env_int("SECURE_APP_REFRESH_TTL", 7 * 24 * 3600)
    )
    jwt_algorithm: str = "HS256"

    # Base de données SQLite (requêtes paramétrées partout, cf. repository.py).
    db_path: str = field(
        default_factory=lambda: os.environ.get("SECURE_APP_DB_PATH", "secure_app.db")
    )

    # CORS — whitelist stricte (J4). JAMAIS "*" avec credentials.
    allowed_origins: list[str] = field(
        default_factory=lambda: _env_list(
            "SECURE_APP_ALLOWED_ORIGINS", ["http://localhost:3000", "http://127.0.0.1:3000"]
        )
    )

    # Rate limiting login (J4) — sliding window in-memory (Redis en prod).
    login_max_attempts: int = field(
        default_factory=lambda: _env_int("SECURE_APP_LOGIN_MAX_ATTEMPTS", 5)
    )
    login_window_seconds: int = field(
        default_factory=lambda: _env_int("SECURE_APP_LOGIN_WINDOW", 60)
    )

    # Argon2id (J3) — paramètres memory-hard (résistance GPU/ASIC).
    argon2_time_cost: int = field(default_factory=lambda: _env_int("SECURE_APP_ARGON2_TIME", 3))
    argon2_memory_cost: int = field(
        default_factory=lambda: _env_int("SECURE_APP_ARGON2_MEMORY", 65536)
    )
    argon2_parallelism: int = field(default_factory=lambda: _env_int("SECURE_APP_ARGON2_PAR", 4))

    # Données de démo (alice/bob + notes + secrets) insérées au démarrage si la
    # base est vierge. Activé par défaut (vitrine) ; désactivé dans les tests
    # (SECURE_APP_SEED_DEMO=0) pour ne pas pré-créer les comptes attendus.
    seed_demo: bool = field(
        default_factory=lambda: os.environ.get("SECURE_APP_SEED_DEMO", "1").lower()
        not in {"0", "false", "no"}
    )

    @property
    def is_prod(self) -> bool:
        return self.env.lower() in {"prod", "production"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Construit (et met en cache) les settings. Résout le secret JWT."""
    secret = os.environ.get("SECURE_APP_SECRET_KEY", "").strip()
    env = os.environ.get("SECURE_APP_ENV", "dev")

    if not secret:
        if env.lower() in {"prod", "production"}:
            # En production, refuser de démarrer sans secret fort (fail-closed).
            raise RuntimeError(
                "SECURE_APP_SECRET_KEY est obligatoire en production "
                "(min. 32 octets aléatoires). Refus de démarrer sans secret."
            )
        secret = secrets.token_urlsafe(48)
        logger.warning(
            "SECURE_APP_SECRET_KEY absent -> clé éphémère générée (dev). "
            "Les JWT seront invalidés à chaque redémarrage."
        )
    elif len(secret) < 32:
        raise RuntimeError("SECURE_APP_SECRET_KEY trop court (min. 32 caractères).")

    base = Settings(secret_key=secret)
    return base
