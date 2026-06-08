#!/usr/bin/env python3
"""Replay d'un dataset d'attaques à IP publiques (B23).

Objectif : alimenter le pipeline avec des sessions d'attaque *déjà géolocalisées*
provenant du monde entier, afin de :
  - allumer le panneau geomap « Sources géolocalisées » SANS base MaxMind
    (chaque event porte son propre `enrichment` geo, repris par l'analyzer) ;
  - démontrer les 4 profils du classifieur (bruteforcer / bot / scanner_legitime
    / humain) sur des sources réalistes et variées.

Les IP utilisées appartiennent aux plages de DOCUMENTATION RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) : elles n'appartiennent à
personne -> aucune donnée personnelle réelle (conforme charte RGPD), et elles ne
sollicitent pas AbuseIPDB (non « globales »). La géoloc attachée est fictive mais
plausible (vraies coordonnées de villes) pour peupler la carte.

Usage (depuis le conteneur analyzer, qui résout l'hôte `analyzer`) :
    dc exec -T analyzer python - < attacks/replay_dataset.py
ou via le wrapper :
    bash attacks/replay_dataset.sh

Génération du fichier dataset (hors ligne, sans expédition) :
    python attacks/replay_dataset.py --write data/datasets/public-attacks.jsonl --no-ship
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

# (ip, pays, latitude, longitude, profil, service)  -- IP = documentation RFC 5737
SOURCES: list[tuple[str, str, float, float, str, str]] = [
    ("203.0.113.10", "Russia", 55.7558, 37.6173, "bruteforcer", "ssh"),
    ("198.51.100.23", "China", 39.9042, 116.4074, "bot", "ssh"),
    ("192.0.2.44", "Brazil", -23.5505, -46.6333, "bruteforcer", "ftp"),
    ("203.0.113.77", "United States", 39.0438, -77.4874, "scanner_legitime", "http"),
    ("198.51.100.88", "Germany", 50.1109, 8.6821, "bot", "telnet"),
    ("192.0.2.130", "India", 19.0760, 72.8777, "bruteforcer", "ssh"),
    ("203.0.113.150", "Netherlands", 52.3676, 4.9041, "scanner_legitime", "http"),
    ("198.51.100.200", "Singapore", 1.3521, 103.8198, "bot", "http"),
    ("192.0.2.210", "Nigeria", 6.5244, 3.3792, "bruteforcer", "telnet"),
    ("203.0.113.222", "Australia", -33.8688, 151.2093, "humain", "ssh"),
]

# 22 mots de passe distincts (style rockyou) pour les sessions de bruteforce.
_PASSWORDS = [
    "123456", "password", "admin", "root", "123456789", "qwerty", "12345678",
    "111111", "1234567", "dragon", "letmein", "monkey", "abc123", "iloveyou",
    "000000", "password1", "qwerty123", "admin123", "root123", "toor",
    "welcome", "changeme",
]

_HTTP_PATHS = ["/", "/robots.txt", "/.env", "/admin", "/wp-login.php",
               "/phpmyadmin/", "/.git/config", "/server-status"]

_HUMAN_COMMANDS = ["ls -la", "whoami", "cat /etc/passwd", "uname -a",
                   "ps aux", "sudo -l", "cat ~/.bash_history"]

_UA_SCANNER = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
_UA_BOT = "Go-http-client/1.1"


def _enrichment(src: tuple[str, str, float, float, str, str]) -> dict[str, Any]:
    _ip, country, lat, lon, profile, _svc = src
    enr: dict[str, Any] = {"country": country, "latitude": lat, "longitude": lon,
                           "source": "dataset-replay"}
    if profile == "scanner_legitime":
        # Le classifieur exige ce flag pour le profil scanner_legitime.
        enr["known_scanner"] = True
        enr["asn"] = "AS-SCANNER (recherche / GreyNoise RIOT)"
    return enr


def _event(src: tuple[str, str, float, float, str, str], session_id: str,
           ts: datetime, event_type: str, **extra: Any) -> dict[str, Any]:
    ip, _country, _lat, _lon, _profile, service = src
    ev: dict[str, Any] = {
        "schema_version": "1.0.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "service": service,
        "src_ip": ip,
        "src_port": 40000 + (hash(session_id) % 20000),
        "dst_port": {"ssh": 22, "http": 80, "ftp": 21, "telnet": 23}[service],
        "session_id": session_id,
        "event_type": event_type,
        "enrichment": _enrichment(src),
    }
    ev.update(extra)
    return ev


def _session(src: tuple[str, str, float, float, str, str], start: datetime) -> list[dict[str, Any]]:
    profile = src[4]
    sid = uuid.uuid4().hex
    evs: list[dict[str, Any]] = []
    t = start

    def step(ms: float) -> datetime:
        nonlocal t
        t = t + timedelta(milliseconds=ms)
        return t

    if profile == "bruteforcer":
        evs.append(_event(src, sid, t, "connect"))
        for pw in _PASSWORDS:  # 22 tentatives, 22 mots de passe distincts
            evs.append(_event(src, sid, step(450), "auth_attempt",
                              username="root", password=pw))
        evs.append(_event(src, sid, step(300), "disconnect"))

    elif profile == "bot":
        evs.append(_event(src, sid, t, "connect"))
        for pw in ("admin", "root", "123456"):  # rafale très rapide
            evs.append(_event(src, sid, step(90), "auth_attempt",
                              username="admin", password=pw))
        evs.append(_event(src, sid, step(90), "disconnect"))

    elif profile == "scanner_legitime":
        evs.append(_event(src, sid, t, "connect"))
        for path in _HTTP_PATHS[:5]:  # bannière-grabbing, aucune auth
            evs.append(_event(src, sid, step(250), "http_request",
                              http={"method": "GET", "path": path,
                                    "user_agent": _UA_SCANNER}))
        evs.append(_event(src, sid, step(200), "disconnect"))

    elif profile == "humain":  # session interactive, rythme irrégulier
        evs.append(_event(src, sid, t, "connect"))
        evs.append(_event(src, sid, step(1200), "auth_attempt",
                          username="admin", password="P@ssw0rd!"))  # noqa: S106 (dataset synthétique)
        evs.append(_event(src, sid, step(800), "auth_success", username="admin"))
        for i, cmd in enumerate(_HUMAN_COMMANDS):
            evs.append(_event(src, sid, step(1500 + (i % 3) * 900), "command",
                              command=cmd))
        evs.append(_event(src, sid, step(2000), "disconnect"))

    return evs


def build_dataset(base: datetime | None = None) -> list[dict[str, Any]]:
    """Construit le dataset complet, sessions étalées sur la dernière heure."""
    base = base or datetime.now(UTC)
    events: list[dict[str, Any]] = []
    for i, src in enumerate(SOURCES):
        # chaque source démarre à un instant différent dans la dernière heure
        start = base - timedelta(minutes=55 - i * 5)
        events.extend(_session(src, start))
    return events


def ship(events: list[dict[str, Any]], analyzer_url: str) -> tuple[int, int]:
    ok = err = 0
    url = analyzer_url.rstrip("/") + "/events"
    for ev in events:
        data = json.dumps(ev).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 (URL interne contrôlée http://analyzer)
            url, data=data, headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                if 200 <= resp.status < 300:
                    ok += 1
                else:
                    err += 1
        except (urllib.error.URLError, OSError) as exc:
            err += 1
            print(f"  ! échec POST ({exc})", file=sys.stderr)
    return ok, err


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay dataset d'attaques géolocalisées (B23)")
    ap.add_argument("--analyzer", default=os.environ.get("ANALYZER_URL", "http://analyzer:8000"),
                    help="URL de l'analyzer (défaut: $ANALYZER_URL ou http://analyzer:8000)")
    ap.add_argument("--write", metavar="PATH", help="écrit le dataset en JSONL et n'expédie pas")
    ap.add_argument("--no-ship", action="store_true", help="ne pas expédier vers l'analyzer")
    args = ap.parse_args()

    events = build_dataset()
    by_profile: dict[str, int] = {}
    by_country: dict[str, int] = {}
    for src in SOURCES:
        by_profile[src[4]] = by_profile.get(src[4], 0) + 1
        by_country[src[1]] = by_country.get(src[1], 0) + 1

    print(f"Dataset : {len(events)} événements / {len(SOURCES)} sources publiques")
    print(f"  profils  : {by_profile}")
    print(f"  pays     : {len(by_country)} pays distincts -> {sorted(by_country)}")

    if args.write:
        os.makedirs(os.path.dirname(args.write) or ".", exist_ok=True)
        with open(args.write, "w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        print(f"Écrit -> {args.write}")
        return 0

    if args.no_ship:
        return 0

    print(f"Expédition vers {args.analyzer} ...")
    ok, err = ship(events, args.analyzer)
    print(f"Résultat : {ok} ingérés, {err} échecs")
    return 0 if err == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
