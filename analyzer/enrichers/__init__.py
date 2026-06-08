"""Enrichisseurs d'événements : géolocalisation et réputation IP."""

from __future__ import annotations

import ipaddress
from typing import Any

from .abuseipdb import AbuseIPDBEnricher
from .geoip import GeoIPEnricher

_geoip = GeoIPEnricher()
_abuse = AbuseIPDBEnricher()


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def enrich(ip: str) -> dict[str, Any]:
    """Agrège geo + réputation. Ne sollicite pas les API sur des IP privées."""
    data: dict[str, Any] = {}
    data.update(_geoip.lookup(ip))
    if _is_public(ip):
        data.update(_abuse.lookup(ip))
    return data
