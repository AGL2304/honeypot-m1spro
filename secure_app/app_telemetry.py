"""Télémétrie *optionnelle* des requêtes HTTP -> PostgreSQL (dashboard comparatif).

But pédagogique (J5) : alimenter un tableau de bord Grafana qui compare, côte à
côte, le comportement de ``secure_app`` (les attaques sont **bloquées** -> 4xx :
401/403/422/429) et de ``vuln_app`` (les mêmes attaques **réussissent** -> 200).

Contrat de robustesse — *fail-open* :
  - Si ``APP_METRICS_DSN`` n'est pas défini, le module est inerte (no-op).
  - Toute erreur d'insertion est avalée : la télémétrie ne doit JAMAIS altérer la
    réponse rendue au client, ni faire tomber l'application.
  - L'écriture se fait dans un pool de threads -> ne bloque pas la boucle async.

La table est créée à la volée (idempotent) à la première écriture.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import threading
from typing import Any

log = logging.getLogger("app_telemetry")

# Configuration par variables d'environnement (injectées par docker compose).
_DSN = os.environ.get("APP_METRICS_DSN", "").strip()
_APP = os.environ.get("APP_METRICS_NAME", "app").strip() or "app"

# Un seul writer en arrière-plan : volumétrie de démo, pas de contention réelle.
_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="telemetry"
)
_lock = threading.Lock()
_conn: Any = None  # connexion psycopg réutilisée (recréée si elle tombe)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS app_requests (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    app         TEXT NOT NULL,
    client_ip   INET,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms  DOUBLE PRECISION,
    attack_type TEXT,
    blocked     BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_app_requests_ts ON app_requests (ts);
CREATE INDEX IF NOT EXISTS idx_app_requests_app ON app_requests (app);
"""


def enabled() -> bool:
    """La télémétrie est-elle active (DSN fourni) ?"""
    return bool(_DSN)


def _classify(path: str) -> str | None:
    """Étiquette la requête par famille d'attaque (heuristique sur le chemin).

    Ces chemins correspondent à la surface d'API commune secure_app/vuln_app :
    ce sont exactement les cibles du comparatif Kali (SQLi/brute-force sur le
    login, command injection sur /tools/ping, BOLA sur /notes, etc.).
    """
    if path.startswith("/auth/login"):
        return "login (SQLi / brute-force)"
    if path.startswith("/auth/register"):
        return "register"
    if path.startswith("/auth/refresh"):
        return "token refresh"
    if path.startswith("/tools/ping"):
        return "command injection"
    if path.startswith("/users/me"):
        return "secret exposure (JWT)"
    if path.startswith("/notes"):
        return "BOLA / IDOR"
    return None


def _get_conn() -> Any:
    """Retourne une connexion psycopg vivante (la (re)crée au besoin)."""
    global _conn
    import psycopg  # import paresseux : module inerte si psycopg absent

    if _conn is None or _conn.closed:
        _conn = psycopg.connect(_DSN, autocommit=True)
        _conn.execute(_SCHEMA)
    return _conn


def _do_insert(row: tuple[Any, ...]) -> None:
    global _conn
    try:
        with _lock:
            conn = _get_conn()
            conn.execute(
                "INSERT INTO app_requests "
                "(app, client_ip, method, path, status_code, latency_ms, "
                "attack_type, blocked) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                row,
            )
    except Exception as exc:  # fail-open : on n'altère jamais l'app
        _conn = None  # force une reconnexion au prochain appel
        log.debug("télémétrie ignorée (insertion KO) : %s", exc)


def record(
    *,
    client_ip: str | None,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float | None,
) -> None:
    """Enregistre une requête HTTP (best-effort, non bloquant)."""
    if not _DSN:
        return
    attack_type = _classify(path)
    blocked = status_code >= 400
    row = (
        _APP,
        client_ip,
        method,
        path,
        status_code,
        latency_ms,
        attack_type,
        blocked,
    )
    try:
        _executor.submit(_do_insert, row)
    except Exception as exc:  # pool saturé/fermé -> on abandonne silencieusement
        log.debug("télémétrie ignorée (soumission KO) : %s", exc)
