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
    offsets: dict[str, int] = {s: 0 for s in SERVICES}
    last_export = 0.0
    with httpx.Client() as client:
        while True:
            for service in SERVICES:
                path = LOG_DIR / f"{service}.jsonl"
                if not path.exists():
                    continue
                with path.open(encoding="utf-8") as fh:
                    fh.seek(offsets[service])
                    for line in fh:
                        _ship_line(client, line)
                    offsets[service] = fh.tell()

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
