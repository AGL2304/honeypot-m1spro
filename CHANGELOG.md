# Changelog

Toutes les évolutions notables de ce projet sont documentées dans ce fichier.

Le format s'inspire de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet suit le [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté
- **Métrique de classification mesurée (B14)** : `analyzer/evaluate.py` génère un
  jeu de sessions étiquetées déterministe, calcule la **matrice de confusion** et
  la précision/rappel/F1 par profil (`python -m analyzer.evaluate`). Seuil **> 85 %**
  verrouillé en CI par `tests/test_classifier_metrics.py`.
- **Faux filesystem enrichi (B20)** : 40+ fichiers appâts navigables via `cd`/`ls`/
  `cat` (résolution de chemins ~, relatifs, `..`), dont `~/.ssh/{known_hosts,
  authorized_keys,id_rsa,config}`, `~/Documents/` (passwords.txt, budget…) et
  `~/projects/{webapp,api,scripts}` (.env appâts, scripts de déploiement).
- **Réponses système complétées (B21)** : commandes `who`, `last`, `uptime`,
  `/proc/meminfo`, `/proc/version` ajoutées au faux shell.

### Modifié
- **Alignement P5 sur le syllabus révisé (07/05/2026, sans VPS)** : la doc
  (`README.md`, `docs/note-cadrage.md`, `docs/charte-rgpd.md`, audits de
  détectabilité) ne décrit plus une exposition Internet sur VPS mais le modèle
  **BYOD / LAN de salle + rejeu de datasets + attaques inter-équipes**. Le
  Honeyscore Shodan est marqué N/A faute d'IP publique (on se rabat sur nmap NSE
  et p0f depuis l'équipe adverse sur le LAN).
- **Ports hôte configurables** via `.env` (`SSH_PORT`/`HTTP_PORT`/`FTP_PORT`/
  `TELNET_PORT`) ; défaut HTTP porté à **8080** (le 80 est souvent déjà pris sous
  WSL/Kali).
- **CI Trivy** restreinte aux vulnérabilités (`scanners: vuln`) : le secret-scanner
  signalait les faux secrets-appâts du honeypot comme de vraies clés Stripe. Le gate
  CVE `CRITICAL` reste actif. `trivy-action` épinglé en **v0.36.0** (les tags
  antérieurs cassaient sur `setup-trivy@v0.2.2`) ; `fail-fast: false` sur la matrice.
- **Packaging** : déclaration explicite des packages (`[tool.setuptools.packages.find]`)
  pour réparer `pip install -e ".[dev]"` (échec d'auto-découverte flat-layout).

### Corrigé
- **Exports défensifs (B17/B24) cassés en production** — détectés en test bout-en-bout :
  1. le service **shipper** régénère les exports via `db.attackers()` mais le compose
     ne lui passait pas les identifiants PostgreSQL → `connection refused` avalé
     silencieusement par `_trigger_exports()`. Variables `POSTGRES_*` ajoutées au
     service `shipper`.
  2. `analyzer/exports.py` plantait sur `'IPv4Address' object has no attribute
     'replace'` : `db.attackers()` renvoie `src_ip` comme objet INET (psycopg), pas
     comme `str`. Normalisation `str(a["src_ip"])` dans blocklist/sigma/stix +
     test de non-régression `tests/test_exports.py`.
- **FTP** : authorizer réellement permissif (accepte tout couple user/mot de passe),
  l'événement `auth_success` porte désormais le mot de passe validé, et le **mode
  passif** fonctionne sous Docker (plage de ports fixe 30000-30009 publiée).
- **Grafana** : dashboard enrichi + UID de datasource stable (`honeypot-pg`).
- **Lint** : `isinstance` avec type union (ruff UP038) dans `analyzer/exports.py`.
- **Déploiement** : stack rendue fonctionnelle et testable sous Windows et Kali.

### À venir (P4 → P5)
- Audit de détectabilité réel en conditions BYOD/LAN : remplir
  `docs/stealth-audit-initial.md` et `docs/stealth-audit-final.md` (scores /30).
- **P5 (révisé, syllabus 07/05/2026 — sans VPS)** : rejeu de jeux de données
  d'attaques + campagne d'attaques inter-équipes sur le LAN de la salle (B23),
  puis capture et classification du trafic réel ainsi généré.
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
