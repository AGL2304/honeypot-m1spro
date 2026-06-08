#!/usr/bin/env bash
# B5 - Bruteforce SSH avec Hydra contre le honeypot, puis assertion sur les logs.
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-2222}"
WORDLIST="${WORDLIST:-/data/rockyou-top1000.txt}"
LOGFILE="${HONEYPOT_LOG_DIR:-./logs}/ssh.jsonl"

echo "[*] Hydra SSH bruteforce -> ${TARGET}:${PORT}"
hydra -l admin -P "${WORDLIST}" -t 4 -f "ssh://${TARGET}:${PORT}" || true

echo "[*] Vérification de la capture..."
python3 attacks/assert_logs.py --service ssh --min-events 100 --logfile "${LOGFILE}"
