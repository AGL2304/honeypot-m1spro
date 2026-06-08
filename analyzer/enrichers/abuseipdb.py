"""Réputation IP via AbuseIPDB avec cache SQLite local et throttling 1 req/s (B15)."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any

import httpx

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_CACHE_TTL_S = 24 * 3600


class AbuseIPDBEnricher:
    def __init__(self, cache_path: str | None = None) -> None:
        self._key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self._cache_path = cache_path or os.environ.get(
            "ABUSEIPDB_CACHE", "/data/abuseipdb_cache.sqlite"
        )
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._init_cache()

    def _init_cache(self) -> None:
        with sqlite3.connect(self._cache_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(ip TEXT PRIMARY KEY, score INTEGER, country TEXT, ts REAL)"
            )

    def _cached(self, ip: str) -> dict[str, Any] | None:
        with sqlite3.connect(self._cache_path) as conn:
            row = conn.execute(
                "SELECT score, country, ts FROM cache WHERE ip = ?", (ip,)
            ).fetchone()
        if row and time.time() - row[2] < _CACHE_TTL_S:
            return {"abuse_score": row[0], "abuse_country": row[1]}
        return None

    def _store(self, ip: str, score: int, country: str | None) -> None:
        with sqlite3.connect(self._cache_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (ip, score, country, ts) VALUES (?,?,?,?)",
                (ip, score, country, time.time()),
            )

    def lookup(self, ip: str) -> dict[str, Any]:
        cached = self._cached(ip)
        if cached is not None:
            return cached
        if not self._key:
            return {}
        with self._lock:
            elapsed = time.time() - self._last_call
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)  # throttle 1 req/s
            self._last_call = time.time()
            try:
                resp = httpx.get(
                    _API_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": self._key, "Accept": "application/json"},
                    timeout=5.0,
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
            except (httpx.HTTPError, ValueError):
                return {}
        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode")
        self._store(ip, score, country)
        return {"abuse_score": score, "abuse_country": country}
