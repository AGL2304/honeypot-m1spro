# vuln_app — jumeau VOLONTAIREMENT VULNÉRABLE de `secure_app`

> ## ⚠️ AVERTISSEMENT
> Cette application est **intentionnellement non sécurisée**, à but **pédagogique
> uniquement** (comme DVWA / OWASP Juice Shop). Elle sert à montrer le comparatif
> « avant / après » de `secure_app` en soutenance M1SPRO.
>
> **NE JAMAIS** la déployer en production, l'exposer durablement sur Internet, ni
> y mettre de vraies données. À lancer sur ta propre machine, derrière un
> pare-feu, et à **éteindre après la démo**.

## But

Même surface d'API que `secure_app`, mais **chaque mitigation a été retirée**.
Les **mêmes commandes Kali** qui échouent contre `secure_app` (port **8001**)
**réussissent** contre `vuln_app` (port **8002**).

## Vulnérabilités plantées (miroir du programme)

| Jour | Vulnérabilité | Implémentation dans `vuln_app` | `secure_app` |
|------|---------------|-------------------------------|--------------|
| J1 | **Injection SQL** | login par concaténation de chaînes | requêtes paramétrées |
| J1 | **Command injection** | `subprocess(shell=True)` + f-string sur `/tools/ping` | `shell=False` + validation |
| J3 | **Auth cassée** | mots de passe **en clair**, JWT **sans vérif de signature** (alg:none accepté) | Argon2id, JWT HS256 + whitelist d'algo |
| J3 | **Fuite de secret** | `/users/me` renvoie le mot de passe | aucun secret renvoyé |
| J4 | **BOLA / IDOR** | `/notes/{id}` ne vérifie pas le propriétaire | scoping owner + 404 |
| J4 | **Pas de rate limit** | brute-force illimité (jamais de 429) | sliding-window → 429 |
| J4 | **Fuite d'info** | erreurs = stack trace, docs exposées, **aucun en-tête de sécurité** | erreurs génériques, CSP/HSTS/nosniff… |

## Lancer

### Option A — uvicorn (le plus simple)

```bash
cd vuln_app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn vuln_app.main:app --host 0.0.0.0 --port 8002
# (depuis la racine du repo, pour que l'import "vuln_app.main" résolve)
```

### Option B — docker (isolé)

```bash
docker run --rm -p 8002:8002 -v "$PWD/vuln_app:/app" -w / python:3.12-slim \
  sh -c "pip install -q -r /app/requirements.txt && \
         apt-get update -q && apt-get install -y -q iputils-ping && \
         python -m uvicorn vuln_app.main:app --host 0.0.0.0 --port 8002"
```

## Démo comparative (attaque les deux côte à côte)

Avec `secure_app` sur 8001 **et** `vuln_app` sur 8002 :

```bash
chmod +x vuln_app/demo_comparatif.sh
SECURE=http://IP:8001 VULN=http://IP:8002 ./vuln_app/demo_comparatif.sh
```

Sortie attendue (extrait) :

```
-- J1 Injection SQL ( ' OR '1'='1 ) --
Bypass login SQLi    | VULN 200=bypass!   | SÉCURISÉ 401=bloqué
-- J4 Brute-force login --
séquence des codes   | VULN  401 401 ...  (jamais 429) | SÉCURISÉ 401 401 401 401 401 429 429  (429!)
```

La colonne **VULN** tombe sur chaque attaque, la colonne **SÉCURISÉ** tient.

## Nettoyage après la démo

```bash
# arrêter le process / conteneur, puis :
rm -f vuln_app/vuln.db
# et refermer le port si tu l'avais ouvert :
sudo ufw delete allow 8002/tcp
```
