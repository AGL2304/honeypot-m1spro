"""Assertions sur les logs après une attaque (B5/B10).

Vérifie qu'un fichier <service>.jsonl contient au moins N événements et que 100%
des lignes sont conformes au contrat event.schema.json. Code de sortie non nul si
la capture a échoué -> utilisable en CI et dans les scripts d'attaque.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Permet d'importer la lib commune quand lancé depuis la racine du repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from jsonschema import ValidationError  # noqa: E402

from honeypots.common.events import validate_event  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--logfile", required=True)
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"[FAIL] Fichier de log absent: {path}", file=sys.stderr)
        return 1

    total = 0
    invalid = 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                validate_event(json.loads(line))
            except (ValidationError, json.JSONDecodeError) as exc:
                invalid += 1
                print(f"[WARN] Ligne non conforme: {exc}", file=sys.stderr)

    print(f"[*] {args.service}: {total} événements, {invalid} non conformes")
    if total < args.min_events:
        print(f"[FAIL] Attendu >= {args.min_events}, capturé {total}", file=sys.stderr)
        return 1
    if invalid > 0:
        print(f"[FAIL] {invalid} événements non conformes au schéma", file=sys.stderr)
        return 1
    print("[OK] Capture validée")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
