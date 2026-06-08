#!/usr/bin/env bash
# Fonctions communes aux scripts d'attaque.
# Adapté au déploiement réel : honeypots sur ports hôtes bas (22/80/21/23) et
# logs dans un VOLUME DOCKER NOMMÉ (`logs:/logs`), donc invisibles côté hôte.
# La validation lit le log directement dans le volume via `docker exec`.

# Localise une wordlist utilisable. Ordre :
#   1) $WORDLIST (si défini)         2) wordlist versionnée dans le repo
#   3) rockyou système (Kali)        4) rockyou système compressé (.gz -> décompresse)
resolve_wordlist() {
  local candidates=(
    "${WORDLIST:-}"
    "data/rockyou-top1000.txt"
    "/data/rockyou-top1000.txt"
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/wordlists/metasploit/unix_passwords.txt"
  )
  local w
  for w in "${candidates[@]}"; do
    [ -n "$w" ] && [ -f "$w" ] && { printf '%s\n' "$w"; return 0; }
  done
  # rockyou est livré compressé sur Kali, dans un dossier root-only : on le
  # décompresse vers data/ (accessible en écriture) une seule fois.
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    mkdir -p data 2>/dev/null || true
    [ -s data/rockyou.txt ] || gunzip -c /usr/share/wordlists/rockyou.txt.gz > data/rockyou.txt 2>/dev/null || true
    [ -s data/rockyou.txt ] && { printf '%s\n' data/rockyou.txt; return 0; }
  fi
  return 1
}

# Construit une wordlist plafonnée à $MAX_TRIES lignes dans un fichier temporaire
# (rockyou complet = 14M d'entrées : on garde l'essai rapide et démonstratif).
build_capped_wordlist() {
  local max="${MAX_TRIES:-200}" src tmp
  src=$(resolve_wordlist) || return 1
  tmp=$(mktemp)
  head -n "$max" "$src" > "$tmp"
  printf '%s\n' "$tmp"
}

# Récupère <service>.jsonl depuis le volume Docker nommé, via un conteneur qui le
# monte. Tolérant au préfixe de projet Compose (honeypot-m1spro-...).
fetch_log_from_volume() {
  local svc="$1" out="$2" cid
  cid=$(docker ps --filter "name=honeypot-${svc}" --format '{{.Names}}' | head -n1)
  [ -z "$cid" ] && cid=$(docker ps --filter "name=${svc}" --format '{{.Names}}' | head -n1)
  if [ -z "$cid" ]; then
    echo "[FAIL] conteneur du service '${svc}' introuvable (la stack est-elle démarrée ?)" >&2
    return 1
  fi
  docker exec "$cid" cat "/logs/${svc}.jsonl" > "$out" 2>/dev/null || true
}

# Valide la capture : extrait le log du volume puis lance assert_logs.py
# (qui contrôle le nombre d'événements ET la conformité au schéma).
assert_capture() {
  local svc="$1" min="$2" tmp rc
  tmp=$(mktemp)
  fetch_log_from_volume "$svc" "$tmp" || { rm -f "$tmp"; return 1; }
  python3 attacks/assert_logs.py --service "$svc" --min-events "$min" --logfile "$tmp"
  rc=$?
  rm -f "$tmp"
  return "$rc"
}
