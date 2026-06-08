#!/usr/bin/env bash
# Lance tous les scénarios d'attaque contre le honeypot déployé.
# Objectif : 100% des services capturent, logs valides (vérifiés dans le volume).
# Ports hôtes par défaut du déploiement : SSH 22, HTTP 80, FTP 21.
set -euo pipefail
cd "$(dirname "$0")/.."            # se placer à la racine du repo

TARGET="${1:-127.0.0.1}"

echo "=== Honeypot M1SPRO - batterie d'attaques (cible ${TARGET}) ==="
bash attacks/run_ssh_bruteforce.sh "${TARGET}" "${SSH_PORT:-22}"
bash attacks/run_http_scan.sh     "${TARGET}" "${HTTP_PORT:-80}"
bash attacks/run_ftp_brute.sh     "${TARGET}" "${FTP_PORT:-21}"
echo "=== Terminé. Vérifier le dashboard Grafana : http://localhost:3000 ==="
