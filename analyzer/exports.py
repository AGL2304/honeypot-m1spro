"""Génération automatique d'exports défensifs (B17/B24).

- exports/block_list.iptables : règles DROP pour les IP critiques
- exports/rules/*.yml          : règles Sigma à partir des sessions critiques
- exports/iocs.json            : IOCs au format STIX 2.1 (bonus)

À lancer périodiquement (toutes les 5 min) via cron ou boucle du shipper.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import db

_EXPORT_DIR = Path("exports")
_RULES_DIR = _EXPORT_DIR / "rules"
_ABUSE_THRESHOLD = 50


def _critical_attackers() -> list[dict[str, Any]]:
    return [
        a
        for a in db.attackers()
        if (a.get("abuse_score") or 0) >= _ABUSE_THRESHOLD
        or a.get("classification") in ("bruteforcer", "bot")
    ]


def generate_blocklist() -> Path:
    _EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# Généré automatiquement - block_list.iptables"]
    for a in _critical_attackers():
        ip = a["src_ip"]
        lines.append(f"-A INPUT -s {ip} -j DROP")
    path = _EXPORT_DIR / "block_list.iptables"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def generate_sigma() -> list[Path]:
    _RULES_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for a in _critical_attackers():
        ip = a["src_ip"]
        rule = {
            "title": f"Activité honeypot malveillante depuis {ip}",
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": f"IP classifiée {a.get('classification')} sur honeypot M1SPRO.",
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {"src_ip": ip},
                "condition": "selection",
            },
            "level": "high",
            "tags": ["attack.command_and_control", "attack.t1110"],
        }
        path = _RULES_DIR / f"honeypot_{ip.replace('.', '_').replace(':', '_')}.yml"
        path.write_text(_to_yaml(rule), encoding="utf-8")
        written.append(path)
    return written


def generate_stix() -> Path:
    _EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).isoformat()
    objects: list[dict[str, Any]] = []
    for a in _critical_attackers():
        ip = a["src_ip"]
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"Malicious IP {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            }
        )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path = _EXPORT_DIR / "iocs.json"
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return path


def _to_yaml(rule: dict[str, Any]) -> str:
    """Sérialiseur YAML minimal (évite une dépendance pyyaml)."""
    def emit(obj: Any, indent: int = 0) -> list[str]:
        pad = "  " * indent
        out: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    out.append(f"{pad}{k}:")
                    out.extend(emit(v, indent + 1))
                else:
                    out.append(f"{pad}{k}: {v}")
        elif isinstance(obj, list):
            for item in obj:
                out.append(f"{pad}- {item}")
        return out

    return "\n".join(emit(rule)) + "\n"


def generate_all() -> None:
    generate_blocklist()
    generate_sigma()
    generate_stix()


if __name__ == "__main__":
    generate_all()
