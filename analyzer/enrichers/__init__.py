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


def enrich(ip: str, provided: dict[str, Any] | None = None) -> dict[str, Any]:
    """Agrège geo + réputation. Ne sollicite pas les API sur des IP privées.

    `provided` : enrichissement éventuellement porté par l'événement lui-même
    (replay d'un dataset déjà géolocalisé, B23). Les enrichisseurs temps réel ont
    la priorité ; le contenu fourni ne sert que de repli quand l'enrichissement
    live est vide (ex. base GeoLite2 absente en déploiement BYOD)."""
    data: dict[str, Any] = dict(provided or {})
    live: dict[str, Any] = {}
    live.update(_geoip.lookup(ip))
    if _is_public(ip):
        live.update(_abuse.lookup(ip))
    data.update({k: v for k, v in live.items() if v is not None})
    return data
