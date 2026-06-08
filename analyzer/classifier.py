"""Moteur de classification comportementale heuristique (B14).

Classe une session selon les 4 profils définis dans schemas/profiles.json :
bot, bruteforcer, humain, scanner_legitime. L'ordre de priorité évite les
ambiguïtés (un scanner connu prime sur un bruteforce, etc.).

Métriques : `python -m analyzer.evaluate` produit la matrice de confusion et la
précision/rappel par profil (objectif > 85% sur Hydra/bruteforcer et Nikto/scanner).
Le seuil est verrouillé en CI par tests/test_classifier_metrics.py.
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

_PROFILES_PATH = Path(__file__).resolve().parents[1] / "schemas" / "profiles.json"
with _PROFILES_PATH.open(encoding="utf-8") as _fh:
    _CFG = json.load(_fh)

_PROFILES: dict[str, Any] = _CFG["profiles"]
_PRIORITY: list[str] = _CFG["priority_order"]


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _features(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Extrait les caractéristiques d'une session à partir de ses événements."""
    times = sorted(_parse_ts(e.get("timestamp") or e.get("ts")) for e in events)
    intervals_ms = [
        (times[i] - times[i - 1]).total_seconds() * 1000 for i in range(1, len(times))
    ]
    auth = [e for e in events if e.get("event_type") == "auth_attempt"]
    cmds = [
        e.get("command")
        for e in events
        if e.get("event_type") == "command" and e.get("command")
    ]
    passwords = {e.get("password") for e in auth if e.get("password")}

    duration_s = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0
    return {
        "n_events": len(events),
        "duration_s": duration_s,
        "auth_attempts": len(auth),
        "distinct_passwords": len(passwords),
        "n_commands": len(cmds),
        "distinct_commands": len(set(cmds)),
        "mean_interval_ms": statistics.mean(intervals_ms) if intervals_ms else 0.0,
        "stddev_interval_ms": statistics.pstdev(intervals_ms) if len(intervals_ms) > 1 else 0.0,
        "single_connect_close": _is_connect_close(events),
        "known_scanner": any(
            (e.get("enrichment") or {}).get("known_scanner") for e in events
        ),
    }


def _is_connect_close(events: list[dict[str, Any]]) -> bool:
    types = [e.get("event_type") for e in events]
    interactive = {"command", "auth_success"}
    return not (interactive & set(types)) and len([t for t in types if t == "auth_attempt"]) <= 2


def _match_scanner(f: dict[str, Any], c: dict[str, Any]) -> bool:
    return (
        f["auth_attempts"] <= c["max_auth_attempts"]
        and f["n_commands"] <= c["max_commands"]
        and f["single_connect_close"]
        and (f["known_scanner"] or not c.get("known_scanner_asn"))
    )


def _match_bruteforcer(f: dict[str, Any], c: dict[str, Any]) -> bool:
    return (
        f["auth_attempts"] >= c["min_auth_attempts"]
        and f["distinct_passwords"] >= c["min_distinct_passwords"]
        and f["n_commands"] <= c["max_commands"]
    )


def _match_bot(f: dict[str, Any], c: dict[str, Any]) -> bool:
    return (
        f["duration_s"] <= c["max_session_duration_s"]
        and f["n_commands"] <= c["max_commands"]
        and f["auth_attempts"] >= c["min_auth_attempts"]
        and (f["mean_interval_ms"] <= c["max_mean_interval_ms"] or f["n_events"] <= 2)
    )


def _match_humain(f: dict[str, Any], c: dict[str, Any]) -> bool:
    return (
        f["n_commands"] >= c["min_commands"]
        and f["distinct_commands"] >= c["min_distinct_commands"]
        and f["mean_interval_ms"] >= c["min_mean_interval_ms"]
    )


_MATCHERS = {
    "scanner_legitime": _match_scanner,
    "bruteforcer": _match_bruteforcer,
    "bot": _match_bot,
    "humain": _match_humain,
}


class BehaviorClassifier:
    """Classe une session en un des 4 profils (ou None si indéterminé)."""

    def classify_session(self, events: list[dict[str, Any]]) -> str | None:
        if not events:
            return None
        f = _features(events)
        for profile in _PRIORITY:
            criteria = _PROFILES[profile]["criteria"]
            if _MATCHERS[profile](f, criteria):
                return profile
        return None

    def features(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return _features(events)
