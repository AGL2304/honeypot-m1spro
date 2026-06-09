"""Routes d'authentification (J3) — register, login+MFA, refresh, logout.

Décisions de sécurité :
  - Login **rate-limité par IP** (anti brute-force, J4) + audit succès/échec.
  - Réponses d'erreur **génériques** : on ne révèle jamais si c'est le username
    ou le mot de passe qui est faux (pas d'oracle, J5).
  - MFA TOTP exigé au login si l'utilisateur l'a activé.
  - Refresh token séparé ; logout révoque les `jti` (blacklist).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .. import repository, security
from ..config import get_settings
from ..dependencies import CurrentUser, DbConn
from ..logging_conf import audit
from ..ratelimit import SlidingWindowLimiter, client_ip, rate_limit_dependency
from ..schemas import (
    LoginIn,
    MessageOut,
    MfaSetupOut,
    MfaVerifyIn,
    RefreshIn,
    RegisterIn,
    TokenOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_settings = get_settings()
_login_limiter = SlidingWindowLimiter(
    _settings.login_max_attempts, _settings.login_window_seconds
)
login_rate_limit = rate_limit_dependency(_login_limiter, "login")

_bearer = HTTPBearer(auto_error=False)


@router.post("/register", response_model=MessageOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, conn: DbConn) -> MessageOut:
    """Crée un compte. Mot de passe hashé Argon2id, jamais stocké en clair."""
    if repository.username_or_email_exists(conn, payload.username, payload.email):
        # Message neutre : ne pas confirmer l'existence d'un compte (énumération).
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Impossible de créer ce compte.",
        )
    password_hash = security.hash_password(payload.password)
    repository.create_user(
        conn, username=payload.username, email=payload.email, password_hash=password_hash
    )
    return MessageOut(detail="Compte créé.")


@router.post("/login", response_model=TokenOut, dependencies=[Depends(login_rate_limit)])
def login(payload: LoginIn, request: Request, conn: DbConn) -> TokenOut:
    """Authentifie et délivre access + refresh tokens. MFA exigé si activé."""
    ip = client_ip(request)
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants invalides."
    )

    user = repository.get_user_by_username(conn, payload.username)
    # On vérifie le mot de passe même si l'utilisateur n'existe pas n'aurait pas
    # de hash : verify_password renvoie False proprement -> pas de timing oracle
    # exploitable de façon triviale, et message identique dans tous les cas.
    if user is None or not security.verify_password(user["password_hash"], payload.password):
        audit("login", ip=ip, username=payload.username, ok=False)
        raise invalid

    if user["mfa_enabled"]:
        if not payload.otp or not security.verify_totp(user["mfa_secret"], payload.otp):
            audit("login_mfa", ip=ip, username=payload.username, ok=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Code MFA requis ou invalide."
            )

    # Rehash transparent si les paramètres Argon2 ont durci entre-temps.
    if security.needs_rehash(user["password_hash"]):
        repository.update_password_hash(
            conn, user["id"], security.hash_password(payload.password)
        )

    audit("login", ip=ip, username=payload.username, ok=True)
    return TokenOut(
        access_token=security.create_access_token(user["id"]),
        refresh_token=security.create_refresh_token(user["id"]),
        expires_in=_settings.access_ttl_seconds,
    )


@router.post("/refresh", response_model=TokenOut)
def refresh(payload: RefreshIn, conn: DbConn) -> TokenOut:
    """Échange un refresh token valide contre une nouvelle paire de tokens.

    Rotation : l'ancien refresh est révoqué (anti-rejeu)."""
    decoded = security.decode_token(payload.refresh_token, expected_type="refresh")
    if decoded is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalide."
        )
    if repository.get_user_by_id(conn, decoded["sub"]) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalide."
        )
    security.revoke_token(decoded["jti"])  # rotation
    return TokenOut(
        access_token=security.create_access_token(decoded["sub"]),
        refresh_token=security.create_refresh_token(decoded["sub"]),
        expires_in=_settings.access_ttl_seconds,
    )


@router.post("/logout", response_model=MessageOut)
def logout(
    user: CurrentUser,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> MessageOut:
    """Révoque le token d'accès courant (blacklist du `jti`)."""
    if credentials is not None:
        decoded = security.decode_token(credentials.credentials, expected_type="access")
        if decoded is not None:
            security.revoke_token(decoded["jti"])
    return MessageOut(detail="Déconnecté.")


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(user: CurrentUser, conn: DbConn) -> MfaSetupOut:
    """Génère un secret TOTP et l'URI otpauth:// (à scanner). MFA pas encore actif."""
    secret = security.generate_mfa_secret()
    repository.set_mfa_secret(conn, user["id"], secret)
    uri = security.mfa_provisioning_uri(secret, user["username"])
    return MfaSetupOut(secret=secret, otpauth_uri=uri)


@router.post("/mfa/enable", response_model=MessageOut)
def mfa_enable(payload: MfaVerifyIn, user: CurrentUser, conn: DbConn) -> MessageOut:
    """Active le MFA après vérification d'un premier code TOTP."""
    full = repository.get_user_by_username(conn, user["username"])
    if full is None or not full["mfa_secret"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Appelez /mfa/setup d'abord."
        )
    if not security.verify_totp(full["mfa_secret"], payload.otp):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code MFA invalide.")
    repository.enable_mfa(conn, user["id"])
    return MessageOut(detail="MFA activé.")
