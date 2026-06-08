"""Couche d'accès PostgreSQL (psycopg 3) pour les événements honeypot."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row

_DSN = (
    f"host={os.environ.get('POSTGRES_HOST', 'localhost')} "
    f"port={os.environ.get('POSTGRES_PORT', '5432')} "
    f"dbname={os.environ.get('POSTGRES_DB', 'honeypot')} "
    f"user={os.environ.get('POSTGRES_USER', 'honeypot')} "
    f"password={os.environ.get('POSTGRES_PASSWORD', 'honeypot')}"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            BIGSERIAL PRIMARY KEY,
    event_id      UUID UNIQUE NOT NULL,
    ts            TIMESTAMPTZ NOT NULL,
    service       TEXT NOT NULL,
    src_ip        INET NOT NULL,
    src_port      INTEGER,
    dst_port      INTEGER,
    session_id    TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    username      TEXT,
    password      TEXT,
    command       TEXT,
    http_method   TEXT,
    http_path     TEXT,
    user_agent    TEXT,
    raw           TEXT,
    classification TEXT,
    country       TEXT,
    latitude      DOUBLE PRECISION,
    longitude     DOUBLE PRECISION,
    abuse_score   INTEGER,
    enrichment    JSONB
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON events (service);
CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id);
"""


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    with psycopg.connect(_DSN, row_factory=dict_row) as conn:
        yield conn


def init_db() -> None:
    with connect() as conn:
        conn.execute(_SCHEMA)
        conn.commit()


def insert_event(event: dict[str, Any], enrichment: dict[str, Any],
                 classification: str | None) -> None:
    http = event.get("http") or {}
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO events (event_id, ts, service, src_ip, src_port, dst_port,
                session_id, event_type, username, password, command,
                http_method, http_path, user_agent, raw, classification,
                country, latitude, longitude, abuse_score, enrichment)
            VALUES (%(event_id)s, %(ts)s, %(service)s, %(src_ip)s, %(src_port)s,
                %(dst_port)s, %(session_id)s, %(event_type)s, %(username)s,
                %(password)s, %(command)s, %(http_method)s, %(http_path)s,
                %(user_agent)s, %(raw)s, %(classification)s, %(country)s,
                %(latitude)s, %(longitude)s, %(abuse_score)s, %(enrichment)s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            {
                "event_id": event["event_id"],
                "ts": event["timestamp"],
                "service": event["service"],
                "src_ip": event["src_ip"],
                "src_port": event.get("src_port"),
                "dst_port": event.get("dst_port"),
                "session_id": event["session_id"],
                "event_type": event["event_type"],
                "username": event.get("username"),
                "password": event.get("password"),
                "command": event.get("command"),
                "http_method": http.get("method"),
                "http_path": http.get("path"),
                "user_agent": http.get("user_agent"),
                "raw": event.get("raw"),
                "classification": classification,
                "country": enrichment.get("country"),
                "latitude": enrichment.get("latitude"),
                "longitude": enrichment.get("longitude"),
                "abuse_score": enrichment.get("abuse_score"),
                "enrichment": psycopg.types.json.Json(enrichment) if enrichment else None,
            },
        )
        conn.commit()


def session_events(session_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        cur = conn.execute(
            "SELECT * FROM events WHERE session_id = %s ORDER BY ts", (session_id,)
        )
        return cur.fetchall()


def stats() -> dict[str, Any]:
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        uniq = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) AS c FROM events"
        ).fetchone()["c"]
        by_service = conn.execute(
            "SELECT service, COUNT(*) AS c FROM events GROUP BY service"
        ).fetchall()
        top_creds = conn.execute(
            """SELECT username, password, COUNT(*) AS c FROM events
               WHERE event_type='auth_attempt' GROUP BY username, password
               ORDER BY c DESC LIMIT 10"""
        ).fetchall()
        by_class = conn.execute(
            "SELECT classification, COUNT(*) AS c FROM events "
            "WHERE classification IS NOT NULL GROUP BY classification"
        ).fetchall()
    return {
        "total_events": total,
        "unique_ips": uniq,
        "by_service": by_service,
        "top_credentials": top_creds,
        "by_classification": by_class,
    }


def attackers() -> list[dict[str, Any]]:
    with connect() as conn:
        return conn.execute(
            """SELECT src_ip, country, MAX(abuse_score) AS abuse_score,
                      COUNT(*) AS events, MAX(classification) AS classification
               FROM events GROUP BY src_ip, country
               ORDER BY events DESC LIMIT 100"""
        ).fetchall()
