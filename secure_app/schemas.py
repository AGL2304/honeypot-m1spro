"""Schémas Pydantic — validation d'entrée stricte (J1).

Chaque payload entrant est validé (type, format, longueur) AVANT d'atteindre la
logique métier. On réutilise `validators.py` (whitelist) pour username/password.
Les modèles de sortie n'exposent QUE les champs voulus (pas de fuite de
`password_hash`, `mfa_secret`, etc. — anti mass-disclosure, API3).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .validators import validate_password, validate_username


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejette les champs inconnus (anti mass-assignment)

    username: str = Field(min_length=3, max_length=30)
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=256)

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: str) -> str:
        if not validate_username(v):
            raise ValueError("Username invalide (3-30, [a-zA-Z0-9_-], non réservé).")
        return v

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        # validate_email importé tardivement pour rester groupé avec sa logique.
        from .validators import validate_email

        if not validate_email(v):
            raise ValueError("Email invalide ou domaine jetable.")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        ok, errors = validate_password(v)
        if not ok:
            raise ValueError("Mot de passe faible : " + " ".join(errors))
        return v


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    otp: str | None = Field(default=None, max_length=8)


class RefreshIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=10, max_length=4096)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 (type de jeton OAuth2, pas un secret)
    expires_in: int


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    mfa_enabled: bool


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaVerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    otp: str = Field(min_length=6, max_length=8)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10_000)


class NoteOut(BaseModel):
    id: str
    owner_id: str
    title: str
    body: str


class PingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=253)


class MessageOut(BaseModel):
    detail: str
