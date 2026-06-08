"""Construction, validation et écriture des événements honeypot (contrat v1.0.0).

Tous les services importent ce module pour garantir que 100% des logs émis sont
conformes à schemas/event.schema.json. La validation est faite à l'émission afin
qu'un log non conforme casse les tests CI (B9).
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_VERSION = "1.0.0"

_SCHEMA_PATH = Path(
    os.environ.get(
        "EVENT_SCHEMA_PATH",
        Path(__file__).resolve().parents[2] / "schemas" / "event.schema.json",
    )
)

with _SCHEMA_PATH.open(encoding="utf-8") as _fh:
    _SCHEMA: dict[str, Any] = json.load(_fh)

_VALIDATOR = jsonschema.Draft202012Validator(_SCHEMA)

# Limite de taille des charges brutes capturées pour éviter une exfiltration de
# disque par un attaquant qui enverrait des payloads gigantesques.
_RAW_MAX_LEN = 4096

_write_lock = threading.Lock()


def new_session_id() -> str:
    return uuid.uuid4().hex


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _truncate(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > _RAW_MAX_LEN:
        return value[:_RAW_MAX_LEN] + "...[truncated]"
    return value


def build_event(
    *,
    service: str,
    src_ip: str,
    src_port: int,
    session_id: str,
    event_type: str,
    dst_port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    command: str | None = None,
    http: dict[str, Any] | None = None,
    raw: str | None = None,
) -> dict[str, Any]:
    """Construit un événement conforme au contrat et le valide immédiatement."""
    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "service": service,
        "src_ip": src_ip,
        "src_port": src_port,
        "session_id": session_id,
        "event_type": event_type,
    }
    if dst_port is not None:
        event["dst_port"] = dst_port
    if username is not None:
        event["username"] = username
    if password is not None:
        event["password"] = password
    if command is not None:
        event["command"] = _truncate(command)
    if http is not None:
        event["http"] = http
    if raw is not None:
        event["raw"] = _truncate(raw)

    _VALIDATOR.validate(event)
    return event


def validate_event(event: dict[str, Any]) -> None:
    """Lève jsonschema.ValidationError si l'événement n'est pas conforme."""
    _VALIDATOR.validate(event)


class EventWriter:
    """Écrit les événements en JSON Lines, un fichier par service.

    Le log shipper (B11) lit ces fichiers et les agrège vers l'analyzer.
    """

    def __init__(self, service: str, log_dir: str | os.PathLike[str] | None = None) -> None:
        base = Path(log_dir or os.environ.get("HONEYPOT_LOG_DIR", "/logs"))
        base.mkdir(parents=True, exist_ok=True)
        self._path = base / f"{service}.jsonl"

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with _write_lock, self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
