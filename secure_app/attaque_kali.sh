#!/usr/bin/env bash
# =============================================================================
# secure_app — démo ATTAQUE / DÉFENSE depuis Kali Linux (ligne de commande)
# Pendant Linux du demo_attack_defense.ps1 (fil rouge SDLC M1SPRO, J1->J5).
#
# Chaque "attaque" est lancée pour de vrai avec des outils Kali / curl, et on
# vérifie que la DÉFENSE tient (le code de retour attendu = la mitigation).
#
# Usage :
#   chmod +x attaque_kali.sh
#   ./attaque_kali.sh                       # cible http://localhost:8001
#   BASE=http://164.92.x.x:8001 ./attaque_kali.sh   # cible la droplet prod
#
# Le cœur de la démo n'utilise que `curl` + `jq` (toujours présents sous Kali).
# Les sections « OUTILS LOURDS » (hydra/sqlmap/nikto/nmap/ffuf/jwt_tool) sont
# fournies en commandes prêtes à copier ; activer avec  HEAVY=1 ./attaque_kali.sh
# =============================================================================
set -u

BASE="${BASE:-http://localhost:8001}"
PW="Sup3r-S3cret!Pass"
HEAVY="${HEAVY:-0}"
PASS=0
FAIL=0

# Couleurs (désactivables avec NO_COLOR=1).
if [ -z "${NO_COLOR:-}" ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; Z=$'\e[0m'
else
  G=""; R=""; Y=""; C=""; Z=""
fi

need() { command -v "$1" >/dev/null 2>&1; }
for bin in curl jq; do
  need "$bin" || { echo "${R}Manque '$bin'. Installe-le :  sudo apt install -y $bin${Z}"; exit 2; }
done

# status PATH [METHOD] [JSON_BODY] [TOKEN]  -> imprime le code HTTP
status() {
  local path="$1" method="${2:-GET}" body="${3:-}" token="${4:-}"
  local args=(-s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  curl "${args[@]}"
}

# body PATH [METHOD] [JSON_BODY] [TOKEN]  -> imprime le corps de la réponse
body() {
  local path="$1" method="${2:-GET}" b="${3:-}" token="${4:-}"
  local args=(-s -X "$method" "$BASE$path")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$b" ]; then args+=(-H 'Content-Type: application/json' -d "$b"); fi
  curl "${args[@]}"
}

check() { # LABEL  GOT  EXPECTED
  local label="$1" got="$2" exp="$3"
  if [ "$got" = "$exp" ]; then
    printf '%s[PASS]%s %-52s -> %s\n' "$G" "$Z" "$label" "$got"; PASS=$((PASS+1))
  else
    printf '%s[FAIL]%s %-52s -> %s (attendu %s)\n' "$R" "$Z" "$label" "$got" "$exp"; FAIL=$((FAIL+1))
  fi
}

# JWT alg:none forgé à la main (base64url, sans dépendance).
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
forge_alg_none() {
  local h p
  h=$(printf '%s' '{"alg":"none","typ":"JWT"}' | b64url)
  p=$(printf '%s' '{"sub":"x","type":"access","jti":"1","exp":9999999999}' | b64url)
  printf '%s.%s.' "$h" "$p"
}

echo
echo "${C}=== secure_app : démo attaque/défense Kali (M1SPRO) — cible $BASE ===${Z}"

# --- Santé -------------------------------------------------------------------
check "health public" "$(status /health)" 200

# --- J3 : comptes + login ----------------------------------------------------
echo; echo "${Y}-- J3 Authentification --${Z}"
check "register alice (201)" \
  "$(status /auth/register POST '{"username":"alice","email":"alice@example.com","password":"'"$PW"'"}')" 201
check "register bob   (201)" \
  "$(status /auth/register POST '{"username":"bob","email":"bob@example.com","password":"'"$PW"'"}')" 201
check "register alice en double -> 409 neutre" \
  "$(status /auth/register POST '{"username":"alice","email":"alice@example.com","password":"'"$PW"'"}')" 409

TOK_ALICE=$(body /auth/login POST '{"username":"alice","password":"'"$PW"'"}' | jq -r '.access_token')
TOK_BOB=$(body   /auth/login POST '{"username":"bob","password":"'"$PW"'"}'   | jq -r '.access_token')
check "login alice -> jeton non vide" "$([ -n "$TOK_ALICE" ] && [ "$TOK_ALICE" != null ] && echo ok || echo ko)" ok

ME=$(body /users/me GET '' "$TOK_ALICE")
check "/users/me (200)" "$(status /users/me GET '' "$TOK_ALICE")" 200
if echo "$ME" | grep -Eq 'password_hash|mfa_secret'; then
  check "/users/me ne fuit aucun secret" "fuite!" "ok"
else
  check "/users/me ne fuit aucun secret" "ok" "ok"
fi

# --- J1 : injection SQL (paramétrée -> neutralisée) --------------------------
echo; echo "${Y}-- J1 Injection SQL (neutralisée) --${Z}"
check "SQLi ' OR '1'='1 -> 401" \
  "$(status /auth/login POST '{"username":"alice'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}')" 401
check "SQLi DROP TABLE -> 401" \
  "$(status /auth/login POST '{"username":"alice'"'"'; DROP TABLE users;--","password":"x"}')" 401
check "table users intacte (login ok)" \
  "$(status /auth/login POST '{"username":"alice","password":"'"$PW"'"}')" 200

# --- J4 : BOLA / IDOR --------------------------------------------------------
echo; echo "${Y}-- J4 BOLA / IDOR --${Z}"
NOTE_ID=$(body /notes POST '{"title":"secret","body":"prive alice"}' "$TOK_ALICE" | jq -r '.id')
check "bob lit la note d'alice    -> 404" "$(status "/notes/$NOTE_ID" GET    '' "$TOK_BOB")"   404
check "alice lit sa note          -> 200" "$(status "/notes/$NOTE_ID" GET    '' "$TOK_ALICE")" 200
check "bob supprime la note alice -> 404" "$(status "/notes/$NOTE_ID" DELETE '' "$TOK_BOB")"   404

# --- J1 : command injection (/tools/ping, subprocess shell=False) ------------
echo; echo "${Y}-- J1 Command injection (/tools/ping) --${Z}"
check "ping '127.0.0.1;id' -> 400" \
  "$(status /tools/ping POST '{"host":"127.0.0.1;id"}' "$TOK_ALICE")" 400
check "ping '8.8.8.8 | cat /etc/passwd' -> 400" \
  "$(status /tools/ping POST '{"host":"8.8.8.8 | cat /etc/passwd"}' "$TOK_ALICE")" 400
check "ping sans auth -> 401" \
  "$(status /tools/ping POST '{"host":"127.0.0.1"}')" 401

# --- J3 : JWT alg:none / jeton bidon -----------------------------------------
echo; echo "${Y}-- J3 JWT alg:none forgé --${Z}"
check "token alg:none -> 401" "$(status /users/me GET '' "$(forge_alg_none)")" 401
check "token bidon    -> 401" "$(status /users/me GET '' 'aaa.bbb.ccc')"        401

# --- J4 : rate limiting login (anti brute-force) -----------------------------
echo; echo "${Y}-- J4 Rate limiting login (anti brute-force) --${Z}"
CODES=""
LAST=""
for i in $(seq 1 7); do
  LAST=$(status /auth/login POST '{"username":"alice","password":"bad'"$i"'"}')
  CODES="$CODES $LAST"
done
echo "    séquence des codes :${CODES}"
check "7e tentative bloquée -> 429" "$LAST" 429

# --- J4 : en-têtes de sécurité (durcissement navigateur) ---------------------
echo; echo "${Y}-- J4 En-têtes de sécurité --${Z}"
HDRS=$(curl -s -D - -o /dev/null "$BASE/health")
hashdr() { echo "$HDRS" | grep -iq "$1"; }
check "CSP default-src 'none'"       "$(hashdr "content-security-policy: default-src 'none'" && echo ok || echo ko)" ok
check "X-Content-Type-Options nosniff" "$(hashdr 'x-content-type-options: nosniff' && echo ok || echo ko)" ok
check "X-Frame-Options DENY"         "$(hashdr 'x-frame-options: deny' && echo ok || echo ko)" ok
check "Cache-Control no-store"       "$(hashdr 'cache-control: no-store' && echo ok || echo ko)" ok

# =============================================================================
# OUTILS LOURDS Kali (activer avec HEAVY=1). Démontrent les MÊMES défenses avec
# l'outillage offensif standard — utile pour la soutenance J5.
# =============================================================================
if [ "$HEAVY" = "1" ]; then
  echo; echo "${C}=== Outils offensifs Kali (HEAVY=1) ===${Z}"
  H="${BASE#http://}"; H="${H#https://}"; HOST="${H%%:*}"; PORT="${H##*:}"; [ "$PORT" = "$HOST" ] && PORT=80

  if need nmap; then
    echo; echo "${Y}[nmap] scan de ports + scripts HTTP${Z}"
    nmap -sV -Pn -p "$PORT" --script http-security-headers,http-methods "$HOST"
  else echo "${Y}(nmap absent : sudo apt install -y nmap)${Z}"; fi

  if need nikto; then
    echo; echo "${Y}[nikto] scan de vulnérabilités web (attendu : peu/pas d'alertes)${Z}"
    nikto -host "$BASE" -maxtime 60s
  else echo "${Y}(nikto absent : sudo apt install -y nikto)${Z}"; fi

  if need hydra; then
    echo; echo "${Y}[hydra] brute-force login -> doit se faire jeter en 429${Z}"
    printf 'wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6\nwrong7\nwrong8\n' > /tmp/wl.txt
    hydra -l alice -P /tmp/wl.txt "$HOST" -s "$PORT" \
      http-post-form "/auth/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:C=/auth/login:H=Content-Type\: application/json:F=401" \
      || echo "${G}-> hydra stoppé : le rate-limiter (429) bloque le brute-force.${Z}"
  else echo "${Y}(hydra absent : sudo apt install -y hydra)${Z}"; fi

  if need sqlmap; then
    echo; echo "${Y}[sqlmap] tentative d'injection sur /auth/login (attendu : not injectable)${Z}"
    sqlmap -u "$BASE/auth/login" --method POST \
      --headers="Content-Type: application/json" \
      --data='{"username":"alice","password":"x"}' \
      -p username --batch --level=2 --risk=2 --flush-session \
      || echo "${G}-> requêtes paramétrées : aucune injection trouvée.${Z}"
  else echo "${Y}(sqlmap absent : sudo apt install -y sqlmap)${Z}"; fi

  if need ffuf; then
    echo; echo "${Y}[ffuf] énumération de chemins (l'API renvoie 404/401, pas de fuite)${Z}"
    wl=/usr/share/wordlists/dirb/common.txt
    [ -f "$wl" ] && ffuf -u "$BASE/FUZZ" -w "$wl" -mc 200,301,302,401,403 -t 20 \
      || echo "${Y}(wordlist dirb absente)${Z}"
  else echo "${Y}(ffuf absent : sudo apt install -y ffuf)${Z}"; fi

  if need jwt_tool; then
    echo; echo "${Y}[jwt_tool] attaques sur le JWT d'alice (alg:none, etc.)${Z}"
    jwt_tool "$TOK_ALICE" -X a   # injection alg:none -> le serveur doit refuser (401)
  else echo "${Y}(jwt_tool absent : pipx install jwt_tool  ou  git clone ticarpi/jwt_tool)${Z}"; fi
fi

# --- Bilan -------------------------------------------------------------------
echo
echo "${C}=== Bilan : ${PASS} PASS / ${FAIL} FAIL ===${Z}"
echo
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
