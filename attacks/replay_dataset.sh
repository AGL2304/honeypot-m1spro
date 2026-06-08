#!/usr/bin/env bash
# Replay du dataset d'attaques géolocalisées (B23) vers l'analyzer.
# L'analyzer n'expose pas son port sur l'hôte (réseau hp_internal) : on exécute
# donc le replay DANS le conteneur analyzer, qui résout l'hôte `analyzer`.
#
#   bash attacks/replay_dataset.sh
#
# Effet : ~10 sources publiques (6 continents) injectées avec leur géoloc ->
# allume le panneau geomap SANS base MaxMind, et illustre les 4 profils.
set -euo pipefail
cd "$(dirname "$0")/.."            # racine du repo

COMPOSE="docker compose -f infra/docker-compose.yml"
[ -f .env ] && COMPOSE="$COMPOSE --env-file .env"

echo "=== Replay dataset géolocalisé (B23) ==="
# Le script est passé sur stdin : pas besoin qu'il soit présent dans l'image.
$COMPOSE exec -T analyzer python - < attacks/replay_dataset.py

echo
echo "Vérifier le dashboard Grafana (panneau « Sources géolocalisées »):"
echo "  http://localhost:3000/d/honeypot-live"
