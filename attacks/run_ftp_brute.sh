#!/usr/bin/env bash
# B10 - Bruteforce FTP avec Hydra contre le honeypot.
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-2121}"
WORDLIST="${WORDLIST:-/data/rockyou-top1000.txt}"
LOGFILE="${HONEYPOT_LOG_DIR:-./logs}/ftp.jsonl"

echo "[*] Hydra FTP bruteforce -> ${TARGET}:${PORT}"
hydra -l admin -P "${WORDLIST}" -t 4 -f "ftp://${TARGET}:${PORT}" || true

echo "[*] Vérification de la capture..."
python3 attacks/assert_logs.py --service ftp --min-events 50 --logfile "${LOGFILE}"
