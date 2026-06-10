"""Télémétrie *optionnelle* des requêtes HTTP -> PostgreSQL (dashboard comparatif).

Copie autonome (vuln_app est packagé en image mono-fichier) du module homonyme de
secure_app. But pédagogique (J5) : alimenter un tableau de bord Grafana qui
compare, côte à côte, secure_app (attaques **bloquées** -> 4xx) et vuln_app (les
mêmes attaques **réussissent** -> 200).

Contrat *fail-open* : DSN absent -> inerte ; toute erreur d'insertion est avalée
(la télémétrie ne doit jamais altérer la réponse ni faire tomber l'app) ; écriture
dans un thread -> ne bloque pas la boucle async. Table créée à la volée.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import threading
from typing import Any

log = logging.getLogger("app_telemetry")

_DSN = os.environ.get("APP_METRICS_DSN", "").strip()
_APP = os.environ.get("APP_METRICS_NAME", "app").strip() or "app"

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="telemetry"
)
_lock = threading.Lock()
_conn: Any = None

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
    return bool(_DSN)


def _classify(path: str) -> str | None:
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
    global _conn
    import psycopg

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
    except Exception as exc:
        _conn = None
        log.debug("télémétrie ignorée (insertion KO) : %s", exc)


def record(
    *,
    client_ip: str | None,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float | None,
) -> None:
    if not _DSN:
        return
    attack_type = _classify(path)
    blocked = status_code >= 400
    row = (_APP, client_ip, method, path, status_code, latency_ms, attack_type, blocked)
    try:
        _executor.submit(_do_insert, row)
    except Exception as exc:
        log.debug("télémétrie ignorée (soumission KO) : %s", exc)
