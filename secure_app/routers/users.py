"""Routes utilisateur — profil protégé (J3/J4).

`/users/me` ne renvoie que les champs publics via `UserOut` : ni `password_hash`,
ni `mfa_secret` ne quittent jamais l'application (anti property-level disclosure,
API3).
"""

from __future__ import annotations

from fastapi import APIRouter

from ..dependencies import CurrentUser
from ..schemas import UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        mfa_enabled=bool(user["mfa_enabled"]),
    )
