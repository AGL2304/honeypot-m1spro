#!/usr/bin/env bash
# B10 - Scan HTTP (Nikto si présent + curl des routes piégées) contre le honeypot,
# puis assertion sur les logs (lus dans le volume Docker nommé).
# Port hôte par défaut : 80 (mappé -> 8080).
set -euo pipefail
cd "$(dirname "$0")/.."            # se placer à la racine du repo
# shellcheck source=attacks/_lib.sh
source attacks/_lib.sh

TARGET="${1:-127.0.0.1}"
PORT="${2:-80}"
MIN_EVENTS="${MIN_EVENTS:-6}"
BASE="http://${TARGET}:${PORT}"

if command -v nikto >/dev/null 2>&1; then
  echo "[*] Nikto -> ${BASE}"
  nikto -host "${BASE}" || true
else
  echo "[*] Nikto absent -> on saute (scan curl uniquement)"
fi

echo "[*] curl des routes piégées"
for path in /admin /wp-login.php /.env /.git/config /phpinfo.php /api/v1/users; do
  curl -s -o /dev/null -w "%{http_code} ${path}\n" "${BASE}${path}" || true
done

echo "[*] Vérification de la capture (volume Docker)..."
assert_capture http "$MIN_EVENTS"
