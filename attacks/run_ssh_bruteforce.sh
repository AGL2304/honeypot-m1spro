#!/usr/bin/env bash
# B5 - Bruteforce SSH avec Hydra contre le honeypot, puis assertion sur les logs
# (lus dans le volume Docker nommé). Port hôte par défaut : 22 (mappé -> 2222).
set -euo pipefail
cd "$(dirname "$0")/.."            # se placer à la racine du repo
# shellcheck source=attacks/_lib.sh
source attacks/_lib.sh

TARGET="${1:-127.0.0.1}"
PORT="${2:-22}"
MIN_EVENTS="${MIN_EVENTS:-30}"

WL=$(build_capped_wordlist) || {
  echo "[FAIL] aucune wordlist trouvée. Installe rockyou ou exporte WORDLIST=/chemin" >&2
  exit 1
}
echo "[*] Hydra SSH bruteforce -> ${TARGET}:${PORT}  (wordlist: $(wc -l < "$WL") essais)"
hydra -l admin -P "$WL" -t 4 "ssh://${TARGET}:${PORT}" || true
rm -f "$WL"

echo "[*] Vérification de la capture (volume Docker)..."
assert_capture ssh "$MIN_EVENTS"
