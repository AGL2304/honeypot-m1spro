"""Logging de sécurité — ne jamais journaliser de données sensibles (J5).

Règle de la checklist code review : « Pas de mots de passe, tokens, ou PII dans
les logs ». On fournit un filtre qui caviarde (redacts) les motifs sensibles, et
un helper `audit()` pour tracer les événements d'authentification (succès/échec)
avec l'IP — utile pour détecter le brute-force (corrélable avec le honeypot).
"""

from __future__ import annotations

import logging
import re

# Motifs caviardés si jamais ils transitent dans un message de log.
_REDACT_PATTERNS = [
    re.compile(r"(password\"?\s*[:=]\s*)\"?[^\s,\"}]+", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"(\b)eyJ[A-Za-z0-9._\-]{10,}", re.IGNORECASE),  # JWT (groupe 1 vide)
]


class RedactingFilter(logging.Filter):
    """Caviarde les secrets éventuels avant écriture du log."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern in _REDACT_PATTERNS:
            msg = pattern.sub(r"\1***REDACTED***", msg)
        record.msg = msg
        record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Configure le logging racine de l'application (idempotent)."""
    root = logging.getLogger("secure_app")
    if root.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s")
    )
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False


_audit_logger = logging.getLogger("secure_app.audit")


def audit(event: str, *, ip: str, username: str | None = None, ok: bool | None = None) -> None:
    """Trace un événement d'authentification/autorisation (sans secret).

    Ex.: audit("login", ip="1.2.3.4", username="alice", ok=False)
    """
    status = "" if ok is None else (" ok" if ok else " FAIL")
    user = f" user={username}" if username else ""
    _audit_logger.info("event=%s ip=%s%s%s", event, ip, user, status)
