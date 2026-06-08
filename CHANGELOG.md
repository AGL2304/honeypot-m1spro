# Changelog

Toutes les évolutions notables de ce projet sont documentées dans ce fichier.

Le format s'inspire de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet suit le [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

### À venir (P4 → P5)
- Audit de détectabilité réel sur cible exposée : remplir
  `docs/stealth-audit-initial.md` et `docs/stealth-audit-final.md` (scores /30).
- Exposition Internet sur VPS jetable (J5) + capture du trafic réel (B23).
- Peuplement d'une instance MISP de test + push des IOC (B24, bonus).
- Bonus : classification par apprentissage automatique (clustering DBSCAN) en
  complément de l'heuristique.

## [1.0.0] — 2026-06-08

Première version : bootstrap complet du monorepo, stack déployable de bout en bout
(`docker compose up`) et industrialisée en CI/CD.

### Ajouté

#### Services honeypot (P1–P2)
- Contrat de log unifié et versionné `schemas/event.schema.json` v1.0.0, validé à
  l'émission, avec 4 profils attaquants chiffrés `schemas/profiles.json` (B3).
- Bibliothèque partagée `honeypots/common/events.py` (construction, validation,
  écriture JSONL) et `fakeshell.py` (faux shell Debian crédible) (B6).
- Service **SSH** `asyncssh` : capture login/pass, faux shell, génération auto de la
  clé d'hôte, bannière OpenSSH Debian (B4/B6/B19).
- Service **HTTP** `FastAPI` : 6 routes piégées + catch-all, bannière Apache (B7).
- Service **FTP** `pyftpdlib` : faux filesystem appât, capture USER/PASS/LIST/RETR (B8).
- Service **Telnet** asyncio réutilisant le faux shell (4e service retenu).
- Log shipper `analyzer/shipper.py` : agrégation des JSONL + push vers l'API (B11).

#### Pipeline d'analyse (P3)
- API d'ingestion/consultation `analyzer/api.py` (POST/GET `/events`, `/stats`,
  `/attackers`, `/health`) sur **PostgreSQL** `analyzer/db.py` (B13).
- Moteur de classification heuristique `analyzer/classifier.py` —
  `BehaviorClassifier.classify_session()`, 4 profils (B14).
- Enrichissement IP : `enrichers/geoip.py` (MaxMind GeoLite2 offline) et
  `enrichers/abuseipdb.py` (cache SQLite + throttling 1 req/s) (B15).
- Dashboard **Grafana** provisionné (datasource PostgreSQL + dashboard live) (B16).
- Exports automatiques `analyzer/exports.py` : `block_list.iptables`, règles
  **Sigma**, IOC **STIX 2.1** (B17, bonus).

#### Validation offensive
- Scripts d'auto-attaque `attacks/run_{ssh_bruteforce,http_scan,ftp_brute,all}.sh`
  (Hydra, Nikto, dirsearch, curl) (B5/B10).
- Assertions de capture `attacks/assert_logs.py` (volume + conformité au schéma).

#### Industrialisation & sécurité
- Dockerfiles durcis par service (non-root `1000:1000`, slim) + `infra/docker-compose.yml`
  orchestrant les 4 honeypots, PostgreSQL, analyzer, shipper, Grafana (B12).
- Durcissement runtime : `read_only`, `cap_drop: ALL`, `no-new-privileges`, réseau
  interne isolé pour PostgreSQL/analyzer (NIST SP 800-190).
- CI GitHub Actions `.github/workflows/ci.yml` : `ruff` + `bandit` + `semgrep` +
  validation schéma + `pytest`, puis build des 5 images + scan **Trivy** (B2/B9/B12).
- Suite de tests `tests/` : schéma, classifier (4 profils), faux shell — 15 tests.

#### Documentation (P0)
- Charte de collecte RGPD `docs/charte-rgpd.md` (B0).
- Note de cadrage `docs/note-cadrage.md` (taxonomie, MITRE Engage/ATT&CK, cadre légal).
- Gabarits d'audit de détectabilité `docs/stealth-audit-{initial,final}.md` (B18/B22).
- `README.md` complet + `.env.example`.

### Choix d'arbitrage
- 4e service : **Telnet** (cible des botnets IoT).
- Stack de stockage/visualisation : **PostgreSQL + Grafana** (option « pro »).
- CI : **GitHub Actions**.

### Sécurité
- Patterns inhérents au honeypot justifiés et tracés dans `pyproject.toml`
  (bandit `skips` B104/B105/B110/B311, ruff per-file-ignores) — pas de masquage
  de vraies vulnérabilités.
- Troncature des charges brutes (`raw`) à 4 Ko (anti-saturation disque).

[Non publié]: https://example.com/compare/v1.0.0...HEAD
[1.0.0]: https://example.com/releases/v1.0.0
