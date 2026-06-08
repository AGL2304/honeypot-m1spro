#!/usr/bin/env bash
# Smoke test bout-en-bout du honeypot M1SPRO (B25 - validation démo).
# En UNE commande, vérifie : conteneurs running, ports honeypot ouverts, base
# peuplée (/stats), classification active, exports défensifs générés.
#
#   bash attacks/smoke_test.sh [ip_cible]
#
# Exit 0 = tout vert (PASS), exit 1 = au moins un test KO (FAIL).
# Suppose que la stack tourne ET qu'au moins une vague d'attaques a été jouée
# (attacks/run_all.sh) ; sinon le test /stats échoue et indique quoi lancer.
set -uo pipefail
cd "$(dirname "$0")/.."            # se placer à la racine du repo

# Charge .env (ports hôtes + identifiants) si présent.
if [ -f .env ]; then set -a; . ./.env; set +a; fi

COMPOSE="docker compose -f infra/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

TARGET="${1:-127.0.0.1}"
SSH_PORT="${SSH_PORT:-22}"
HTTP_PORT="${HTTP_PORT:-8080}"
FTP_PORT="${FTP_PORT:-21}"
TELNET_PORT="${TELNET_PORT:-23}"

pass=0; fail=0
ok() { printf '  \033[32m[PASS]\033[0m %s\n' "$1"; pass=$((pass + 1)); }
ko() { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; fail=$((fail + 1)); }

echo "=== Smoke test honeypot M1SPRO (cible ${TARGET}) ==="

# --- 1. Conteneurs running -------------------------------------------------
echo "[1] Conteneurs"
for svc in honeypot-ssh honeypot-http honeypot-ftp honeypot-telnet \
           postgres analyzer shipper grafana; do
  cid=$($COMPOSE ps -q "$svc" 2>/dev/null)
  running=""
  [ -n "$cid" ] && running=$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)
  if [ "$running" = "true" ]; then ok "$svc running"; else ko "$svc NON running"; fi
done

# --- 2. Ports honeypot ouverts (côté hôte) ---------------------------------
echo "[2] Ports honeypot"
check_port() { timeout 3 bash -c ">/dev/tcp/$1/$2" 2>/dev/null; }
for entry in "ssh:${SSH_PORT}" "http:${HTTP_PORT}" "ftp:${FTP_PORT}" "telnet:${TELNET_PORT}"; do
  name=${entry%%:*}; port=${entry##*:}
  if check_port "$TARGET" "$port"; then ok "$name ouvert ($TARGET:$port)"
  else ko "$name fermé ($TARGET:$port)"; fi
done

# --- 3. Base peuplée + classification (via API analyzer) -------------------
echo "[3] Pipeline d'analyse (/stats)"
read -r total nsvc nclass <<EOF
$($COMPOSE exec -T analyzer python -c "
import urllib.request, json
d = json.load(urllib.request.urlopen('http://localhost:8000/stats'))
print(d.get('total_events', 0), len(d.get('by_service', [])), len(d.get('by_classification', [])))
" 2>/dev/null | tr -d '\r')
EOF
total=${total:-0}; nsvc=${nsvc:-0}; nclass=${nclass:-0}
if [ "$total" -gt 0 ] 2>/dev/null; then ok "PostgreSQL peuplé ($total événements)"
else ko "base vide — lance d'abord: bash attacks/run_all.sh $TARGET"; fi
if [ "$nsvc" -ge 1 ] 2>/dev/null; then ok "ventilation par service ($nsvc services)"
else ko "aucune ventilation par service"; fi
if [ "$nclass" -ge 1 ] 2>/dev/null; then ok "classification active ($nclass profils)"
else ko "aucune session classée"; fi

# --- 4. Exports défensifs (B17/B24) ----------------------------------------
echo "[4] Exports défensifs"
$COMPOSE exec -T shipper python -m analyzer.exports >/dev/null 2>&1 \
  || echo "  (régénération exports en erreur — vérification des fichiers existants)"
for f in exports/block_list.iptables exports/iocs.json; do
  if [ -s "$f" ]; then ok "$f généré"; else ko "$f manquant/vide"; fi
done
if [ -d exports/rules ]; then ok "exports/rules/ présent"; else ko "exports/rules/ manquant"; fi

# --- Bilan -----------------------------------------------------------------
echo "---------------------------------------------"
printf 'Résultat : %d PASS / %d FAIL\n' "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
  echo -e "\033[32m[OK] Smoke test réussi — stack prête pour la démo.\033[0m"
  exit 0
fi
echo -e "\033[31m[KO] Smoke test échoué — voir les [FAIL] ci-dessus (section Dépannage du README).\033[0m"
exit 1
