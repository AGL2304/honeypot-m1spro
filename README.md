# Honeypot M1SPRO — multi-services, analyse comportementale & furtivité

Honeypot **medium-interaction** multi-services (SSH · HTTP · FTP · Telnet) écrit en
Python 3.12, entièrement conteneurisé, avec un pipeline complet
**collecte → classification → enrichissement → dashboard**, des scripts
d'auto-attaque pour valider la chaîne de détection, et une industrialisation CI/CD
(lint · SAST · tests · scan d'images).

> ⚠️ **Cadre d'usage** — Projet pédagogique École IT, M1 U3 CyberSécurité
> (Semaine 13, module M1SPRO). Dispositif **défensif et de recherche uniquement**.
> Toute mise en service implique la lecture et la signature de la
> [charte de collecte RGPD](docs/charte-rgpd.md).

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Structure du dépôt](#structure-du-dépôt)
- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [Services exposés](#services-exposés)
- [Attaques de validation](#attaques-de-validation)
- [Pipeline d'analyse](#pipeline-danalyse)
- [Dashboard](#dashboard)
- [Exports défensifs](#exports-défensifs-ioc)
- [Développement](#développement)
- [CI/CD](#cicd)
- [Durcissement](#durcissement-sécurité)
- [Furtivité](#furtivité-anti-détection)
- [Avancement par brique](#avancement-par-brique-b0--b25)
- [Cadre légal & éthique](#cadre-légal--éthique)
- [Dépannage](#dépannage)
- [Équipe](#équipe)

---

## Fonctionnalités

- **4 services honeypot** émettant tous le même contrat de log versionné
  ([`schemas/event.schema.json`](schemas/event.schema.json) v1.0.0) :
  - **SSH** (`asyncssh`) — faux shell Debian crédible, capture login/pass + commandes.
  - **HTTP** (`FastAPI`) — 6 routes piégées (`/admin`, `/wp-login.php`, `/.env`,
    `/.git/config`, `/phpinfo.php`, `/api/v1/users`) + catch-all, payloads loggés.
  - **FTP** (`pyftpdlib`) — faux filesystem appât (`secrets.txt`, `db_dump.sql`…).
  - **Telnet** (asyncio) — cible des botnets IoT (Mirai/Gafgyt), réutilise le faux shell.
- **Pipeline d'analyse** : log shipper → API d'ingestion → PostgreSQL → classifier
  heuristique **4 profils** → enrichissement **GeoIP + AbuseIPDB**.
- **Dashboard Grafana** provisionné (KPI, carte géo, time-series, profils).
- **Exports défensifs** auto-générés : `block_list.iptables`, règles **Sigma**, IOC **STIX 2.1**.
- **Scripts d'auto-attaque** (Hydra, Nikto, curl) avec **assertions de capture**.
- **CI/CD** : `ruff` + `bandit` + `semgrep` + `pytest` + validation schéma + build + **Trivy**.
- **Durcissement** : conteneurs non-root, read-only, `cap-drop ALL`, réseau interne isolé.

## Architecture

```
                         Internet / Lab
                  22        80        21        23
                  │         │         │         │
            ┌─────▼───┐ ┌───▼────┐ ┌──▼────┐ ┌──▼──────┐
            │  ssh    │ │  http  │ │  ftp  │ │ telnet  │   honeypots (medium-interaction)
            └────┬────┘ └───┬────┘ └──┬────┘ └────┬────┘
                 └──────────┴────┬────┴───────────┘
                                 │  /logs/*.jsonl  (contrat v1.0.0)
                          ┌──────▼───────┐
                          │   shipper    │  agrège + POST
                          └──────┬───────┘
                          ┌──────▼───────┐    enrich (GeoIP / AbuseIPDB)
                          │   analyzer   │───────────────────────┐
                          │  (FastAPI)   │   classify (4 profils) │
                          └──────┬───────┘                        │
                                 │                                 │
                          ┌──────▼───────┐                  ┌──────▼───────┐
                          │  PostgreSQL  │◀─────────────────│   Grafana    │ :3000
                          └──────┬───────┘                  └──────────────┘
                                 │
                       exports/  ▼  block_list.iptables · rules/*.yml (Sigma) · iocs.json (STIX)
```

Le **contrat de log unique** est la pierre angulaire : tout service produit des
événements validés contre le JSON Schema *à l'émission* — un log non conforme fait
échouer la CI (B9).

## Structure du dépôt

```
.
├── honeypots/
│   ├── common/            # lib partagée : émission d'événements + faux shell
│   │   ├── events.py      #   build_event/validate_event/EventWriter
│   │   └── fakeshell.py   #   faux shell Debian (SSH + Telnet)
│   ├── ssh/               # service SSH (asyncssh) + Dockerfile
│   ├── http/              # service HTTP (FastAPI) + Dockerfile
│   ├── ftp/               # service FTP (pyftpdlib) + Dockerfile
│   └── telnet/            # service Telnet (asyncio) + Dockerfile
├── analyzer/
│   ├── api.py             # API d'ingestion/consultation (FastAPI)
│   ├── db.py              # couche PostgreSQL (psycopg 3)
│   ├── classifier.py      # BehaviorClassifier — 4 profils heuristiques
│   ├── enrichers/         # geoip.py (MaxMind) + abuseipdb.py (cache+throttle)
│   ├── shipper.py         # log shipper (tail jsonl → API)
│   ├── exports.py         # Sigma / STIX / blocklist
│   └── Dockerfile
├── dashboard/grafana/     # provisioning (datasource + dashboard) + modèle JSON
├── attacks/               # run_*.sh (Hydra/Nikto) + assert_logs.py
├── schemas/               # event.schema.json (v1.0.0) + profiles.json
├── infra/                 # docker-compose.yml (orchestration durcie)
├── docs/                  # charte RGPD, note de cadrage, audits de détectabilité
├── tests/                 # pytest : schéma, classifier, faux shell
├── exports/               # sorties générées (gitignored sauf rules/.gitkeep)
├── data/geoip/            # déposer GeoLite2-City.mmdb ici
├── .github/workflows/     # ci.yml
├── pyproject.toml         # deps + config ruff/bandit/pytest
└── .env.example
```

## Prérequis

| Outil | Version | Usage |
|---|---|---|
| Docker + Docker Compose | récent | exécution de la stack |
| Python | ≥ 3.12 | développement / tests locaux |
| (lab) Kali | — | Hydra, Nikto, nmap, p0f pour attaques & audit |

Fichiers de données à fournir (non versionnés) :

- `data/geoip/GeoLite2-City.mmdb` — base MaxMind GeoLite2 (compte école).
- `ABUSEIPDB_API_KEY` dans `.env` — clé AbuseIPDB (compte école).
- `rockyou-top1000.txt` (NFS commun) — dictionnaire pour les bruteforce.

## Démarrage rapide

Objectif : un évaluateur relance toute la stack en **moins de 30 minutes** sur une
machine vierge.

```bash
# 1. Configuration
cp .env.example .env          # renseigner mots de passe + clé AbuseIPDB
#   (optionnel) déposer data/geoip/GeoLite2-City.mmdb

# 2. Build + lancement
cd infra
docker compose up --build -d

# 3. Vérifier
docker compose ps
curl -s http://localhost:80/.env        # doit renvoyer un faux .env
#   Dashboard : http://localhost:3000  (admin / cf .env)
```

Arrêt et nettoyage :

```bash
docker compose down            # arrêt
docker compose down -v         # arrêt + suppression des volumes (données)
```

## Configuration

Toutes les variables sont dans [`.env.example`](.env.example) :

| Variable | Rôle | Défaut |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | base d'événements | honeypot |
| `ANALYZER_URL` | endpoint d'ingestion pour le shipper | http://analyzer:8000 |
| `ABUSEIPDB_API_KEY` | enrichissement réputation | *(vide → désactivé)* |
| `GEOIP_DB_PATH` | base GeoLite2 | /data/geoip/GeoLite2-City.mmdb |
| `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` | accès Grafana | admin |

> Les services restent fonctionnels **sans** GeoIP ni AbuseIPDB : l'enrichissement
> est simplement omis (dégradation gracieuse).

## Services exposés

| Service | Port hôte | Port interne | Bannière (furtivité) |
|---|---|---|---|
| SSH | 22 | 2222 | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` |
| HTTP | 80 | 8080 | `Server: Apache/2.4.57 (Debian)` |
| FTP | 21 | 2121 | `220 (vsFTPd 3.0.5)` |
| Telnet | 23 | 2323 | `Ubuntu 22.04.4 LTS` |
| Analyzer API | *(interne)* | 8000 | — |
| Grafana | 3000 | 3000 | — |

Les ports bas (22/80/21/23) sont mappés vers des ports hauts internes : les
conteneurs n'ont **pas** besoin de `NET_BIND_SERVICE`, ce qui permet `cap-drop ALL`.

## Attaques de validation

Depuis la VM Kali (ou en local avec les outils installés) :

```bash
bash attacks/run_all.sh <ip_honeypot>          # batterie complète (B fin J2)
bash attacks/run_ssh_bruteforce.sh <ip> 2222   # Hydra SSH
bash attacks/run_http_scan.sh <ip> 8080        # Nikto + dirsearch + curl
bash attacks/run_ftp_brute.sh <ip> 2121        # Hydra FTP
```

Chaque script appelle ensuite `attacks/assert_logs.py` : **échec** (exit ≠ 0) si le
nombre d'événements capturés est trop faible ou si une ligne n'est pas conforme au
schéma. C'est la garantie automatisée de la chaîne de capture.

## Pipeline d'analyse

| Endpoint | Méthode | Rôle |
|---|---|---|
| `/events` | POST | ingère un événement (valide → enrichit → classe → persiste) |
| `/events` | GET | derniers événements |
| `/stats` | GET | KPIs agrégés (volume, IP uniques, top credentials, profils) |
| `/attackers` | GET | top des IP attaquantes |
| `/health` | GET | sonde |

**Classification (4 profils)** — seuils chiffrés dans
[`schemas/profiles.json`](schemas/profiles.json), ordre de priorité
`scanner_legitime → bruteforcer → bot → humain` :

| Profil | Signature comportementale |
|---|---|
| `bot` | session ultra-courte, intervalles quasi constants, ~0 commande |
| `bruteforcer` | nombreuses tentatives d'auth, forte diversité de mots de passe |
| `humain` | rythme irrégulier, commandes variées et contextuelles |
| `scanner_legitime` | connect/close, ASN scanner connu (GreyNoise RIOT) |

## Dashboard

Grafana auto-provisionné (datasource PostgreSQL + dashboard `Honeypot M1SPRO - Live`,
refresh 5 s) : KPI cards, time-series par service, camembert des profils, carte
géolocalisée des sources, top credentials. Projetable et lisible à 3 mètres (B16).

## Exports défensifs (IOC)

Régénérés périodiquement par le shipper (toutes les ~5 min) via
[`analyzer/exports.py`](analyzer/exports.py) :

- `exports/block_list.iptables` — règles DROP pour les IP critiques.
- `exports/rules/*.yml` — règles **Sigma** (convertibles Splunk/Elastic/QRadar).
- `exports/iocs.json` — bundle **STIX 2.1** d'indicateurs (bonus).

## Développement

```bash
python -m venv .venv
source .venv/bin/activate            # Windows : .venv\Scripts\activate
pip install -e ".[dev]"

ruff check .                                       # lint
bandit -r honeypots analyzer -c pyproject.toml    # SAST
pytest -q                                          # tests
```

## CI/CD

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — deux jobs :

1. **lint-sast-test** : `ruff` → `bandit` → `semgrep` → validation schéma → `pytest`.
2. **build-scan** (matrice 5 images) : `docker build` → **Trivy** (échec sur CVE `CRITICAL`).

## Durcissement (sécurité)

Aligné NIST SP 800-190 (B12). Tous les conteneurs applicatifs :

- `USER 1000:1000` (non-root), `read_only: true`, `cap_drop: ALL`,
  `no-new-privileges:true`.
- Réseau **interne isolé** (`hp_internal`) pour PostgreSQL et l'analyzer
  (pas d'accès direct depuis l'extérieur).
- Charges brutes (`raw`) tronquées à 4 Ko (anti-saturation disque).

## Furtivité (anti-détection)

Bannières plausibles (B19), faux filesystem riche `.bash_history`/`.bashrc`/`/proc`
(B20), réponses système cohérentes `ps`/`netstat` + jitter aléatoire 50–300 ms (B21).
Audit mesuré avant/après dans
[`docs/stealth-audit-initial.md`](docs/stealth-audit-initial.md) →
[`docs/stealth-audit-final.md`](docs/stealth-audit-final.md) (score /30).

## Avancement par brique (B0 → B25)

| Phase | Briques | État |
|---|---|---|
| P0 — Fondations | B0–B1 | ✅ charte RGPD + note de cadrage |
| P1 — Premier service | B2–B5 | ✅ repo, CI, schéma, SSH, script Hydra |
| P2 — Multi-protocole | B6–B12 | ✅ faux shell, HTTP, FTP, Telnet, shipper, durcissement |
| P3 — Pipeline d'analyse | B13–B17 | ✅ API, classifier, enrichers, Grafana, exports |
| P4 — Furtivité mesurée | B18–B22 | 🟡 mécanismes en place, **audits à remplir sur cible réelle** |
| P5 — Exposition + restitution | B23–B25 | ⏳ J5 (VPS, capture réelle, démo jury) |

## Cadre légal & éthique

- **RGPD** : l'IP est une donnée personnelle ; base = intérêt légitime ;
  minimisation + anonymisation avant remise. Voir [charte](docs/charte-rgpd.md).
- **Article 323-1** : système dédié, isolé, sans donnée de tiers, pas d'entrapment.
- **ENISA** : charte signée, durée de conservation bornée, retrait de l'exposition
  en fin de fenêtre de démo.

## Dépannage

| Symptôme | Piste |
|---|---|
| Grafana « no data » | vérifier que `shipper` et `analyzer` tournent ; la base se remplit après les premières attaques |
| Pas d'enrichissement géo | `data/geoip/GeoLite2-City.mmdb` absent → dégradation normale |
| `abuse_score` toujours absent | `ABUSEIPDB_API_KEY` vide ou quota épuisé |
| Port 22/80 déjà utilisé | arrêter le service hôte ou remapper dans `infra/docker-compose.yml` |
| CI rouge sur Trivy | mettre à jour l'image de base / dépendances signalées CRITICAL |

## Équipe

Projet en équipe de 4, deux binômes en parallèle :

- **Binôme A — Offensive & Validation** : scripts d'attaque, profils attaquants,
  audit de détectabilité, contre-mesures de furtivité.
- **Binôme B — Construction & Blue Team** : services honeypot, CI/CD, durcissement,
  pipeline de logs, classifier, enrichissement, dashboard.

Voir l'historique des versions dans [CHANGELOG.md](CHANGELOG.md).
