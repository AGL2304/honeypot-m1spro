"""Rate limiting — sliding window en mémoire (J4 / API4).

Limite les requêtes par (clé, fenêtre) pour freiner le brute-force et le DoS.
Implémentation in-memory volontairement simple ; **en production on utilise
Redis** (sorted set + TTL) pour partager l'état entre instances.

Renvoie HTTP 429 + en-tête `Retry-After` quand la limite est franchie.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status


class SlidingWindowLimiter:
    """Compteur glissant : au plus `max_requests` par `window_seconds` et par clé."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Enregistre un hit. Retourne (autorisé, retry_after_secondes)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            # Purge des hits hors fenêtre.
            while bucket and bucket[0] <= now - self.window:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = int(self.window - (now - bucket[0])) + 1
                return False, max(retry_after, 1)
            bucket.append(now)
            return True, 0

    def reset(self) -> None:
        """Réinitialise tous les compteurs (utile pour les tests)."""
        with self._lock:
            self._hits.clear()


def client_ip(request: Request) -> str:
    """IP source. NB : `X-Forwarded-For` ne doit être lu que derrière un proxy
    de confiance — ici on prend l'IP directe par défaut (pas de spoofing)."""
    return request.client.host if request.client else "unknown"


def rate_limit_dependency(limiter: SlidingWindowLimiter, name: str):
    """Fabrique une dépendance FastAPI appliquant `limiter` par IP."""

    def _dependency(request: Request) -> None:
        key = f"{name}:{client_ip(request)}"
        allowed, retry_after = limiter.check(key)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Trop de requêtes, réessayez plus tard.",
                headers={"Retry-After": str(retry_after)},
            )

    return _dependency
