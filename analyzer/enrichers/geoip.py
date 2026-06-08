"""Géolocalisation IP via MaxMind GeoLite2 en base offline (B15)."""

from __future__ import annotations

import os
from typing import Any

try:
    import maxminddb
except ImportError:  # la lib peut manquer en CI lint
    maxminddb = None  # type: ignore[assignment]


class GeoIPEnricher:
    def __init__(self, db_path: str | None = None) -> None:
        self._path = db_path or os.environ.get(
            "GEOIP_DB_PATH", "/data/geoip/GeoLite2-City.mmdb"
        )
        self._reader = None
        if maxminddb is not None and os.path.exists(self._path):
            self._reader = maxminddb.open_database(self._path)

    def lookup(self, ip: str) -> dict[str, Any]:
        if self._reader is None:
            return {}
        try:
            rec = self._reader.get(ip)
        except (ValueError, KeyError):
            return {}
        if not rec:
            return {}
        country = (rec.get("country") or {}).get("names", {}).get("en")
        loc = rec.get("location") or {}
        return {
            "country": country,
            "latitude": loc.get("latitude"),
            "longitude": loc.get("longitude"),
        }
