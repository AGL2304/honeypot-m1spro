"""Fixtures pytest partagées."""

from __future__ import annotations

import sys
from pathlib import Path

# Rend le package racine importable sans installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
