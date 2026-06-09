"""Bibliothèque de validation réutilisable (TP2 J1 + SSRF J4).

Approche **whitelist > blacklist** : on définit ce qui EST autorisé, jamais ce
qui est interdit (impossible à énumérer exhaustivement, contournable en Unicode).

Fonctions pures, sans I/O, testables unitairement (cf. tests/secure_app).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

# --- Username -------------------------------------------------------------
# 3-30 caractères, alphanumérique + _ - , ne commence pas par un chiffre.
_USERNAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]{2,29}$")
_FORBIDDEN_USERNAMES = {
    "admin", "administrator", "root", "system", "sysadmin", "superuser",
    "operator", "support", "security", "moderator", "owner",
}

# --- Password -------------------------------------------------------------
_PASSWORD_MIN_LEN = 12
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
# Petit dictionnaire de mots de passe trop courants (extrait rockyou).
_COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "azerty", "motdepasse",
    "password1", "iloveyou", "admin123", "welcome", "changeme", "letmein",
    "p@ssw0rd", "passw0rd", "12345678", "qwerty123",
}

# --- Email ----------------------------------------------------------------
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
_EMAIL_MAX_LEN = 254  # RFC 5321
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "yopmail.com", "guerrillamail.com", "10minutemail.com",
    "trashmail.com", "tempmail.com",
}


def validate_username(username: str) -> bool:
    """Username : 3-30 chars, [a-zA-Z0-9_-], début non numérique, pas réservé."""
    if not isinstance(username, str) or not _USERNAME_RE.match(username):
        return False
    return username.lower() not in _FORBIDDEN_USERNAMES


def validate_password(password: str) -> tuple[bool, list[str]]:
    """Vérifie la robustesse. Retourne (valide, [messages d'erreur])."""
    errors: list[str] = []
    if not isinstance(password, str):
        return False, ["Le mot de passe doit être une chaîne."]
    if len(password) < _PASSWORD_MIN_LEN:
        errors.append(f"Minimum {_PASSWORD_MIN_LEN} caractères.")
    if not _UPPER_RE.search(password):
        errors.append("Au moins une majuscule.")
    if not _LOWER_RE.search(password):
        errors.append("Au moins une minuscule.")
    if not _DIGIT_RE.search(password):
        errors.append("Au moins un chiffre.")
    if not _SPECIAL_RE.search(password):
        errors.append("Au moins un caractère spécial.")
    if password.lower() in _COMMON_PASSWORDS:
        errors.append("Mot de passe trop courant.")
    return (not errors), errors


def validate_email(email: str) -> bool:
    """Format RFC simplifié, longueur max, blocage des domaines jetables."""
    if not isinstance(email, str) or len(email) > _EMAIL_MAX_LEN:
        return False
    # Normalisation Unicode pour éviter les homoglyphes.
    email = unicodedata.normalize("NFKC", email).strip()
    if not _EMAIL_RE.match(email):
        return False
    domain = email.rsplit("@", 1)[-1].lower()
    return domain not in _DISPOSABLE_DOMAINS


def is_safe_hostname(host: str) -> bool:
    """Hostname plausible (lettres/chiffres/.- , <=253 chars). Pas une garantie DNS."""
    if not host or len(host) > 253:
        return False
    return all(part and re.match(r"^[a-zA-Z0-9-]{1,63}$", part) for part in host.split("."))


def validate_url(url: str, allowed_schemes: tuple[str, ...] = ("http", "https")) -> bool:
    """Valide une URL et **bloque les cibles internes** (prévention SSRF, J4).

    Refuse : schémas hors whitelist, hostnames absents, et toute IP littérale
    privée / loopback / link-local / réservée (ex. 169.254.169.254 = métadonnées
    cloud, cible classique de SSRF — cf. Capital One 2019).
    """
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        return False

    host = parsed.hostname
    # Si l'hôte est une IP littérale, rejeter les plages non publiques.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname (non-IP) : on valide juste le format ; la résolution DNS et
        # la re-vérification post-résolution doivent être faites par l'appelant.
        return is_safe_hostname(host)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )
