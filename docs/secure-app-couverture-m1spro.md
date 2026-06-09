# Couverture du programme M1SPRO « Sécurité en Programmation » — `secure_app`

Ce document trace, jour par jour, **où** chaque notion du cours est mise en
pratique dans le projet, et **justifie** les points volontairement hors
périmètre (argumentaire jury). Il complète le honeypot (volet offensif/collecte)
par le volet **défense applicative**.

## Vue d'ensemble

| Jour | Thème | Couverture | Où |
|---|---|---|---|
| J1 | Injections / OWASP Top 10 | ✅ Complet | `database.py`, `repository.py`, `routers/tools.py`, `schemas.py`, `validators.py` |
| J2 | Sécurité mémoire / buffer overflow | ✅ Démo dédiée | `labs/j2-buffer-overflow/` (C) + CI `j2-memory-safety` |
| J3 | Authentification & secrets | ✅ Complet | `security.py`, `config.py`, `routers/auth.py` |
| J4 | Sécurité des API | ✅ Complet | `routers/notes.py`, `ratelimit.py`, `main.py` |
| J5 | SAST / DAST / DevSecOps | ✅ Complet | `.github/workflows/ci.yml` (Bandit, Semgrep, Trivy, ZAP) |

## J1 — Injections (A03)

- **Injection SQL** : 100 % des requêtes sont paramétrées (liaison `?`), aucune
  concaténation (`repository.py`). Démontré : `' OR '1'='1` et `DROP TABLE`
  renvoient 401, table intacte.
- **Command injection (CWE-78)** : `/tools/ping` valide l'entrée (IP/hostname)
  puis exécute `subprocess.run([...], shell=False)` avec binaire en chemin
  absolu. `127.0.0.1; rm -rf /` → 400 avant tout appel OS.
- **Validation d'entrée** : schémas Pydantic stricts (`extra="forbid"` →
  anti mass-assignment) + whitelist (`validators.py`).

### Pourquoi pas NoSQL / LDAP injection ?
Hors périmètre **par choix d'architecture** : la stack n'utilise ni base
documentaire (Mongo) ni annuaire LDAP. La défense de fond — *ne jamais
interpoler d'entrée non validée dans une requête* — est néanmoins démontrée sur
SQL et sur les commandes système, et se transpose à l'identique.

## J2 — Sécurité mémoire

`secure_app` est écrite en **Python**, un langage *memory-safe* à ramasse-miettes :
les buffer overflows, use-after-free et autres corruptions de tas/pile ne s'y
appliquent pas (pas d'arithmétique de pointeurs, bornes vérifiées). Choisir un
langage memory-safe **est** la contre-mesure recommandée (cf. recommandations
NSA/CISA 2023 « Memory Safe Languages »).

Pour couvrir la notion malgré tout, un lab **C** dédié (`labs/j2-buffer-overflow/`)
montre l'exploit (écrasement d'un flag d'authentification par débordement de
pile), puis sa correction (bornage) et les mitigations compilateur (canari,
NX, ASLR/PIE, RELRO, `_FORTIFY_SOURCE`). La CI le compile et prouve que le
canari intercepte l'overflow et que la version durcie y résiste.

## J3 — Authentification & secrets (A02, A07)

- **Hachage** : Argon2id (memory-hard) via `argon2-cffi`, rehash transparent si
  les paramètres durcissent. Jamais de MD5/SHA nu.
- **JWT** : HS256, **whitelist d'algorithmes** au décodage (bloque `alg:none`),
  claims requis (`exp/sub/jti/type`), TTL access court + refresh rotatif,
  révocation par `jti` (logout/rotation).
- **MFA** : TOTP (RFC 6238) compatible Google Authenticator.
- **Secrets** : exclusivement via variables d'environnement ; **fail-closed** en
  prod (refus de démarrer sans `SECURE_APP_SECRET_KEY` ≥ 32 octets).
- **Pas d'oracle** : messages d'erreur génériques (on ne distingue pas
  « mauvais user » de « mauvais mot de passe »).

### Et OAuth2 / OIDC ?
La notion d'« access token porteur + refresh + révocation » est implémentée à la
main (JWT Bearer), ce qui couvre les mécanismes étudiés. Un serveur OAuth2/OIDC
complet (authorization code, PKCE) relève d'un IdP tiers (Keycloak…) et sortirait
du périmètre d'une démo auto-portée ; il est mentionné comme évolution.

## J4 — Sécurité des API (OWASP API Top 10)

- **API1 BOLA/IDOR** : filtrage systématique par `owner_id`, identifiants UUID
  (non énumérables), **404** (et non 403) pour ne pas confirmer l'existence.
- **API4 Rate limiting** : sliding-window par IP sur le login (429 + Retry-After).
- **API8/A05 CORS** : whitelist stricte d'origines, jamais `*` avec credentials.
- **En-têtes de sécurité** : CSP, `X-Frame-Options: DENY`, `nosniff`, HSTS (prod),
  Referrer-Policy, Permissions-Policy.
- **API3 property-level** : `UserOut` n'expose jamais `password_hash`/`mfa_secret`.

### Et mTLS / CSRF ?
- **mTLS** : pertinent en service-à-service derrière un mesh ; pour une API
  publique authentifiée par token, il est délégué à la couche infra (reverse
  proxy / ingress) et hors périmètre applicatif.
- **CSRF** : non applicable ici — l'authentification se fait par en-tête
  `Authorization: Bearer`, pas par cookie de session ; il n'y a donc pas de
  vecteur CSRF (le navigateur n'attache pas automatiquement le token).

## J5 — SAST / DAST / DevSecOps

- **SAST** : `ruff` (lint + règles sécurité `S`), **Bandit** (`-r secure_app`),
  **Semgrep** (`p/python`) — dans le job `lint-sast-test`.
- **Scan d'images** : **Trivy** (gate CVE CRITICAL) sur chaque conteneur.
- **DAST** : **OWASP ZAP baseline** (`dast-zap`) attaque dynamiquement le
  conteneur `secure_app` en marche ; rapport publié en artefact.
- **Test live boîte noire** : `secure-app-live` rejoue 19 contrôles
  attaque/défense contre le conteneur réel.
- **Hygiène** : secrets jamais journalisés (filtre de caviardage), erreurs
  génériques sans stack trace, durcissement conteneur (non-root, rootfs
  read-only, `cap_drop: ALL`, `no-new-privileges`), `.env` gitignoré.

## Comment rejouer

```bash
# J1/J3/J4 — tests unitaires (37) + démo live (19 contrôles)
pytest tests/secure_app -q
# (live) cf. secure_app/demo_attack_defense.ps1 contre le conteneur

# J2 — démo mémoire (Linux/WSL)
bash labs/j2-buffer-overflow/run_demo.sh

# J5 — toute la chaîne SAST/DAST tourne en CI à chaque push (.github/workflows/ci.yml)
```
