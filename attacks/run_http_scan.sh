#!/usr/bin/env bash
# B10 - Scan HTTP (Nikto + dirsearch + curl) contre le honeypot.
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-8080}"
BASE="http://${TARGET}:${PORT}"
LOGFILE="${HONEYPOT_LOG_DIR:-./logs}/http.jsonl"

echo "[*] Nikto -> ${BASE}"
nikto -host "${BASE}" || true

echo "[*] curl des routes piégées"
for path in /admin /wp-login.php /.env /.git/config /phpinfo.php /api/v1/users; do
  curl -s -o /dev/null -w "%{http_code} ${path}\n" "${BASE}${path}" || true
done

echo "[*] Vérification de la capture..."
python3 attacks/assert_logs.py --service http --min-events 6 --logfile "${LOGFILE}"
