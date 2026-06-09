"""secure_app — API REST sécurisée (fil rouge SDLC M1SPRO).

Application compagnon du honeypot : elle met en pratique le programme
« Sécurité en Programmation » (5 jours) côté *défense applicative* —
là où le honeypot illustre la *collecte d'attaques*, cette API illustre
comment écrire du code qui y résiste.

Briques couvertes (mapping endpoint -> OWASP -> jour de cours) :
  - J1  Anti-injection
        * SQL paramétré          -> database.py / repository.py (A03, CWE-89)
        * Command-injection       -> routers/tools.py POST /tools/ping (CWE-78)
        * Validation stricte      -> schemas.py + validators.py (A03/A04)
  - J3  Authentification & secrets
        * Argon2id                -> security.hash_password (A02, A07)
        * JWT (whitelist algo)    -> security.decode_token (A07, bloque alg:none)
        * MFA TOTP                -> routers/auth.py /auth/mfa/* (A07)
        * Secrets via env         -> config.py (A05, fail-closed en prod)
  - J4  Durcissement API
        * Anti-BOLA/IDOR          -> routers/notes.py (API1, ownership + 404)
        * Rate limiting login     -> ratelimit.py (API4, anti brute-force)
        * CORS whitelist + headers-> main.py (A05/API8)
  - J5  DevSecOps
        * Bandit/Semgrep en CI    -> .github/workflows/ci.yml
        * Erreurs génériques      -> main.py (pas de stack trace, A09)
        * Logs caviardés          -> logging_conf.py (pas de secret/PII)
"""

__version__ = "1.0.0"
