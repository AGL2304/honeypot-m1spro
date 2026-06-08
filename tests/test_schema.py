"""Vérifie que la lib commune produit des événements conformes (B9)."""

from __future__ import annotations

import pytest
from jsonschema import ValidationError

from honeypots.common.events import build_event, new_session_id, validate_event


def test_build_event_ssh_auth_is_valid():
    ev = build_event(
        service="ssh", src_ip="203.0.113.5", src_port=51234, dst_port=2222,
        session_id=new_session_id(), event_type="auth_attempt",
        username="root", password="123456",
    )
    validate_event(ev)
    assert ev["schema_version"] == "1.0.0"
    assert ev["service"] == "ssh"


def test_build_event_http_request_is_valid():
    ev = build_event(
        service="http", src_ip="198.51.100.7", src_port=40000, dst_port=8080,
        session_id=new_session_id(), event_type="http_request",
        http={"method": "GET", "path": "/.env", "headers": {}, "user_agent": "curl"},
    )
    validate_event(ev)


def test_invalid_service_rejected():
    with pytest.raises(ValidationError):
        build_event(
            service="smtp", src_ip="203.0.113.5", src_port=1, dst_port=1,
            session_id=new_session_id(), event_type="connect",
        )


def test_invalid_event_type_rejected():
    with pytest.raises(ValidationError):
        build_event(
            service="ssh", src_ip="203.0.113.5", src_port=1, dst_port=1,
            session_id=new_session_id(), event_type="login",
        )
