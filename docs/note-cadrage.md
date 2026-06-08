# Note de cadrage — Honeypot M1SPRO (2-4 pages)

## 1. Taxonomie du honeypot (Spitzner)

| Axe | Choix | Justification |
|---|---|---|
| **Niveau d'interaction** | **Medium-interaction** | Faux shell scripté + routes HTTP/FTP simulées : capture riche (commandes, payloads) sans exécuter de vrai code → risque de pivot quasi nul. |
| **Finalité** | **Research / production hybride** | Observation comportementale + génération d'IOC défensifs. |
| **Placement** | **Exposé (VPS jetable J5)** + lab interne | Capture du trafic Internet réel pendant la démo, isolé du SI de l'école. |
| **Données réelles** | Aucune | Seulement des appâts (fake `.env`, `secrets.txt`, faux fs). |

## 2. Périmètre technique

- **Services** : SSH (asyncssh), HTTP (FastAPI), FTP (pyftpdlib), **Telnet** (4e service retenu — cible privilégiée des botnets IoT Mirai/Gafgyt).
- **Pipeline** : log shipper → API d'ingestion (FastAPI) → PostgreSQL → classifier heuristique 4 profils → enrichissement GeoIP + AbuseIPDB → dashboard Grafana.
- **Industrialisation** : Docker Compose, CI GitHub Actions (ruff + bandit + semgrep + pytest + Trivy).

## 3. MITRE Engage (cadre de deception)

Le dispositif s'aligne sur les activités MITRE Engage :
- **Collect** : capture des credentials, commandes, payloads.
- **Detect** : classification comportementale, alertes via exports Sigma.
- **Prevent / Direct** : appâts (lures) orientant l'attaquant (`/.env`, `secrets.txt`).
- **Disrupt** : génération de `block_list.iptables`.

## 4. Mapping MITRE ATT&CK (techniques attendues)

| Technique | ID | Observable honeypot |
|---|---|---|
| Brute Force | T1110 | Tentatives SSH/FTP massives |
| Valid Accounts | T1078 | Réutilisation de credentials |
| Exploit Public-Facing App | T1190 | Scans `/wp-login.php`, `/.git/config` |
| Ingress Tool Transfer | T1105 | `wget`/`curl` dans le faux shell |
| System Information Discovery | T1082 | `uname -a`, `cat /proc/cpuinfo` |

## 5. Cadre légal (synthèse)

- **RGPD** : IP = donnée personnelle (Breyer C-582/14), base = intérêt légitime, minimisation + anonymisation avant remise. Détail dans [charte-rgpd.md](charte-rgpd.md).
- **Article 323-1** : système dédié sans donnée de tiers, pas d'entrapment.
- **ENISA** : charte de collecte signée, durée de conservation bornée, retrait de l'exposition en fin de démo.

## 6. Architecture (vue logique)

```
[Internet] → ports 22/80/21/23
   │
   ├─ honeypot-ssh ─┐
   ├─ honeypot-http ┤  *.jsonl   ┌───────────┐   ┌────────────┐
   ├─ honeypot-ftp ─┼─ /logs ──→ │  shipper  │→─→│  analyzer  │
   └─ honeypot-telnet┘            └───────────┘   │  (FastAPI) │
                                                  └─────┬──────┘
                                  enrich (GeoIP/AbuseIPDB) │
                                                  ┌───────▼──────┐
                                                  │  PostgreSQL  │←── Grafana (dashboard)
                                                  └──────────────┘
                                  exports: block_list.iptables, Sigma, STIX
```

## 7. Risques et contre-mesures

| Risque | Contre-mesure |
|---|---|
| Pivot depuis un conteneur | non-root, read-only, cap-drop ALL, réseau interne isolé |
| Détection du honeypot | bannières plausibles (B19), faux fs riche (B20), jitter (B21) |
| Saturation disque (payloads) | troncature `raw` à 4 Ko |
| Fuite de données perso | anonymisation IP avant remise |
