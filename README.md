# Honeypot M1SPRO — multi-services, analyse comportementale & furtivité

Honeypot **medium-interaction** multi-services (SSH, HTTP, FTP, Telnet) en Python,
conteneurisé, avec pipeline complet de collecte → classification → enrichissement
→ dashboard, et industrialisé en CI/CD.

> Projet pédagogique École IT — M1 U3 CyberSécurité (Semaine 13). Usage **défensif
> et de recherche uniquement**. Lire [docs/charte-rgpd.md](docs/charte-rgpd.md).

## Architecture

```
honeypots/{ssh,http,ftp,telnet}  → services appâts (émettent du JSON conforme)
        │  (/logs/*.jsonl)
analyzer/shipper.py              → agrège et pousse vers l'API
analyzer/api.py                  → ingestion FastAPI → PostgreSQL
analyzer/classifier.py           → 4 profils (bot/bruteforcer/humain/scanner)
analyzer/enrichers/              → GeoIP (MaxMind) + AbuseIPDB
dashboard/grafana/               → dashboard live provisionné
exports/                         → block_list.iptables, Sigma, STIX (IOC)
attacks/                         → scripts d'auto-attaque (Hydra, Nikto) + assertions
```

Contrat de logs unique et versionné : [schemas/event.schema.json](schemas/event.schema.json) (v1.0.0).

## Démarrage rapide (< 30 min sur machine vierge)

```bash
cp .env.example .env          # renseigner mots de passe + clé AbuseIPDB
# (optionnel) déposer data/geoip/GeoLite2-City.mmdb pour la géoloc
cd infra
docker compose up --build -d
```

| Service | Port exposé | Port interne |
|---|---|---|
| SSH | 22 | 2222 |
| HTTP | 80 | 8080 |
| FTP | 21 | 2121 |
| Telnet | 23 | 2323 |
| Analyzer API | (interne) | 8000 |
| Grafana | 3000 | 3000 |

Dashboard : http://localhost:3000 (admin / cf. `.env`).

## Lancer les attaques de validation

```bash
# Depuis la VM Kali (ou en local)
bash attacks/run_all.sh <ip_honeypot>
# ou ciblé :
bash attacks/run_ssh_bruteforce.sh <ip> 2222
```

Chaque script vérifie ensuite la capture via `attacks/assert_logs.py`
(échec si < N événements ou logs non conformes au schéma).

## Développement

```bash
python -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -e ".[dev]"
ruff check .          # lint
bandit -r honeypots analyzer -c pyproject.toml   # SAST
pytest -q             # tests (schéma, classifier, faux shell)
```

## CI/CD

`.github/workflows/ci.yml` : ruff → bandit → semgrep → validation schéma → pytest,
puis build des 5 images + scan Trivy (échec sur CVE CRITICAL).

## Durcissement (B12)

Tous les conteneurs : `USER 1000:1000`, `read_only: true`, `cap_drop: ALL`,
`no-new-privileges`, réseau interne isolé (`hp_internal`) pour Postgres/analyzer.

## Furtivité (B18-B22)

Bannières plausibles, faux filesystem riche, réponses système cohérentes
(`ps`/`netstat`/`/proc`), jitter aléatoire. Audit avant/après :
[docs/stealth-audit-initial.md](docs/stealth-audit-initial.md) →
[docs/stealth-audit-final.md](docs/stealth-audit-final.md).

## Bonus

Exports STIX 2.1 (`exports/iocs.json`), règles Sigma (`exports/rules/*.yml`),
block-list iptables — générés automatiquement par `analyzer/exports.py`.

## Avancement par brique

P0 charte+cadrage · P1 schéma+SSH+Hydra · P2 HTTP/FTP/Telnet+durcissement ·
P3 API+classifier+enrichers+Grafana+exports · P4 gabarits d'audit furtivité ·
P5 (J5) exposition VPS + restitution.
