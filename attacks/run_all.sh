#!/usr/bin/env bash
# Synchro fin J2 : lance tous les scénarios d'attaque depuis Kali.
# Objectif : 100% des services capturent en moins de 5 min, logs valides.
set -euo pipefail

TARGET="${1:-127.0.0.1}"

echo "=== Honeypot M1SPRO - batterie d'attaques ==="
bash attacks/run_ssh_bruteforce.sh "${TARGET}" 2222
bash attacks/run_http_scan.sh "${TARGET}" 8080
bash attacks/run_ftp_brute.sh "${TARGET}" 2121
echo "=== Terminé. Vérifier le dashboard Grafana. ==="
