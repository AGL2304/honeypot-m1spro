#!/usr/bin/env bash
# B10 - Bruteforce FTP avec Hydra contre le honeypot, puis assertion sur les logs
# (lus dans le volume Docker nommé). Port hôte par défaut : 21 (mappé -> 2121).
set -euo pipefail
cd "$(dirname "$0")/.."            # se placer à la racine du repo
# shellcheck source=attacks/_lib.sh
source attacks/_lib.sh

TARGET="${1:-127.0.0.1}"
PORT="${2:-21}"
MIN_EVENTS="${MIN_EVENTS:-20}"

WL=$(build_capped_wordlist) || {
  echo "[FAIL] aucune wordlist trouvée. Installe rockyou ou exporte WORDLIST=/chemin" >&2
  exit 1
}
echo "[*] Hydra FTP bruteforce -> ${TARGET}:${PORT}  (wordlist: $(wc -l < "$WL") essais)"
hydra -l admin -P "$WL" -t 4 "ftp://${TARGET}:${PORT}" || true
rm -f "$WL"

echo "[*] Vérification de la capture (volume Docker)..."
assert_capture ftp "$MIN_EVENTS"
