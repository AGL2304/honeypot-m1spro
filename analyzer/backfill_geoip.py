"""Backfill géoIP des événements déjà stockés (allume la carte Grafana).

Contexte : en déploiement public réel, le honeypot capture de vraies IP
publiques. Si la base MaxMind GeoLite2 est déposée *après coup*, les événements
déjà en base ont ``latitude``/``longitude`` à ``NULL`` -> le panneau
« Sources géolocalisées » reste vide. Ce script les géolocalise rétroactivement.

Idempotent : ne touche qu'aux lignes encore non géolocalisées (``latitude IS
NULL``) et ignore les IP privées/réservées (non géolocalisables).

Usage (dans le conteneur analyzer, qui monte la base et accède à PostgreSQL) :

    docker compose exec analyzer python -m analyzer.backfill_geoip
"""

from __future__ import annotations

import ipaddress

from .db import connect
from .enrichers.geoip import GeoIPEnricher


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def main() -> None:
    geo = GeoIPEnricher()
    if geo._reader is None:  # base absente -> rien à faire
        raise SystemExit(
            "Base GeoLite2 introuvable (cf. GEOIP_DB_PATH=/data/geoip/"
            "GeoLite2-City.mmdb). Dépose data/geoip/GeoLite2-City.mmdb sur l'hôte, "
            "redémarre l'analyzer, puis relance ce script."
        )

    with connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT host(src_ip) AS ip FROM events WHERE latitude IS NULL"
        ).fetchall()
        ips = [r["ip"] for r in rows]
        print(f"{len(ips)} IP(s) sans géoloc à traiter.")

        geoloc_ips = 0
        updated_rows = 0
        skipped_private = 0
        no_location = 0

        for ip in ips:
            if not _is_public(ip):
                skipped_private += 1
                continue
            loc = geo.lookup(ip)
            lat, lon = loc.get("latitude"), loc.get("longitude")
            if lat is None or lon is None:
                no_location += 1
                continue
            cur = conn.execute(
                "UPDATE events SET latitude=%s, longitude=%s, country=%s "
                "WHERE src_ip = %s::inet AND latitude IS NULL",
                (lat, lon, loc.get("country"), ip),
            )
            geoloc_ips += 1
            updated_rows += cur.rowcount

        conn.commit()

    print(
        f"OK : {geoloc_ips} IP(s) géolocalisée(s) -> {updated_rows} événement(s) mis à jour.\n"
        f"   ({skipped_private} IP privées ignorées, {no_location} sans position MaxMind)"
    )


if __name__ == "__main__":
    main()
