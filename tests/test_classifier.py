"""Tests du moteur de classification heuristique (B14)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from analyzer.classifier import BehaviorClassifier

_BASE = datetime(2026, 6, 8, 10, 0, 0, tzinfo=UTC)


def _ev(offset_ms: int, event_type: str, **kw) -> dict:
    return {
        "timestamp": (_BASE + timedelta(milliseconds=offset_ms)).isoformat(),
        "event_type": event_type,
        **kw,
    }


def test_bruteforcer_session():
    events = [
        _ev(i * 120, "auth_attempt", username="admin", password=f"pw{i}")
        for i in range(30)
    ]
    assert BehaviorClassifier().classify_session(events) == "bruteforcer"


def test_scanner_legitime_session():
    events = [
        _ev(0, "connect", enrichment={"known_scanner": True}),
        _ev(50, "disconnect"),
    ]
    assert BehaviorClassifier().classify_session(events) == "scanner_legitime"


def test_humain_session():
    events = [
        _ev(0, "auth_success", username="admin"),
        _ev(1500, "command", command="whoami"),
        _ev(4200, "command", command="ls -la"),
        _ev(9000, "command", command="cat /etc/passwd"),
        _ev(15000, "command", command="uname -a"),
    ]
    assert BehaviorClassifier().classify_session(events) == "humain"


def test_bot_session():
    events = [
        _ev(0, "connect"),
        _ev(80, "auth_attempt", username="root", password="root"),
        _ev(150, "disconnect"),
    ]
    assert BehaviorClassifier().classify_session(events) == "bot"


def test_empty_session_is_none():
    assert BehaviorClassifier().classify_session([]) is None
