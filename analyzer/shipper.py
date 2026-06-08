"""Log shipper (B11) : agrège les .jsonl des services et les pousse vers l'analyzer.

- Suit (tail) chaque fichier /logs/<service>.jsonl en mémorisant l'offset.
- Concatène le flux unifié dans /logs/all-events.jsonl.
- POST chaque événement vers ANALYZER_URL/events.
- Déclenche la régénération des exports toutes les ~5 min (B17).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

ANALYZER_URL = os.environ.get("ANALYZER_URL", "http://analyzer:8000")
LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", "/logs"))
SERVICES = ("ssh", "http", "ftp", "telnet")
EXPORT_INTERVAL_S = 300
POLL_INTERVAL_S = 2.0


def _unified_path() -> Path:
    return LOG_DIR / "all-events.jsonl"


def _offsets_path() -> Path:
    return LOG_DIR / ".shipper_offsets.json"


def _load_offsets() -> dict[str, int]:
    """Reprend les offsets persistés : un restart ne doit pas re-pousser tout
    l'historique (l'analyzer déduplique, mais ré-émettre 20k events est lent et
    masque les nouveaux événements en fin de gros fichiers)."""
    try:
        data = json.loads(_offsets_path().read_text(encoding="utf-8"))
        return {s: int(data.get(s, 0)) for s in SERVICES}
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return {s: 0 for s in SERVICES}


def _save_offsets(offsets: dict[str, int]) -> None:
    try:
        _offsets_path().write_text(json.dumps(offsets), encoding="utf-8")
    except OSError:
        pass  # /logs en lecture seule ou plein : on retombe sur le mode mémoire


def _ship_line(client: httpx.Client, line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    with _unified_path().open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    try:
        client.post(f"{ANALYZER_URL}/events", json=event, timeout=5.0)
    except httpx.HTTPError:
        pass  # l'analyzer peut être momentanément indisponible


def run() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    offsets = _load_offsets()
    last_export = 0.0
    with httpx.Client() as client:
        while True:
            for service in SERVICES:
                path = LOG_DIR / f"{service}.jsonl"
                if not path.exists():
                    continue
                # Rotation/troncature : si le fichier a rétréci, on repart de 0.
                if path.stat().st_size < offsets[service]:
                    offsets[service] = 0
                with path.open(encoding="utf-8") as fh:
                    fh.seek(offsets[service])
                    for line in fh:
                        _ship_line(client, line)
                    offsets[service] = fh.tell()
            _save_offsets(offsets)

            now = time.time()
            if now - last_export >= EXPORT_INTERVAL_S:
                _trigger_exports()
                last_export = now
            time.sleep(POLL_INTERVAL_S)


def _trigger_exports() -> None:
    try:
        from .exports import generate_all

        generate_all()
    except Exception:  # noqa: BLE001, S110 - les exports ne doivent jamais tuer le shipper
        pass


if __name__ == "__main__":
    run()
