"""Routes coffre à secrets — chiffrement au repos + anti-BOLA (J3/J4).

Décisions de sécurité (miroir « bien fait » de la faille vuln_app) :
  - Valeur **chiffrée AES-256-GCM** avant stockage (cf. ``crypto.py``) : la base
    ne contient que du ciphertext -> un dump SQLi ne livre rien d'exploitable.
  - **Ownership systématique** : toutes les requêtes filtrent par ``owner_id`` du
    porteur du token. Deviner l'UUID d'un secret d'autrui renvoie 404 (anti-BOLA).
  - La **liste** ne renvoie qu'un APERÇU masqué (jamais le clair en bloc) ; le
    clair n'est révélé que sur ``GET /secrets/{id}`` au propriétaire (anti
    property-level disclosure, API3).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from .. import crypto, repository
from ..dependencies import CurrentUser, DbConn
from ..schemas import MessageOut, SecretIn, SecretListItem, SecretOut

logger = logging.getLogger("secure_app.secrets")

router = APIRouter(prefix="/secrets", tags=["secrets"])


def _mask(value: str) -> str:
    """Aperçu non réversible : 2 premiers + 2 derniers caractères, reste masqué."""
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[:2]}{'•' * 6}{value[-2:]}"


@router.post("", response_model=SecretOut, status_code=status.HTTP_201_CREATED)
def create_secret(payload: SecretIn, user: CurrentUser, conn: DbConn) -> SecretOut:
    value_enc = crypto.encrypt(payload.value)  # chiffré AVANT le disque
    rec = repository.create_secret(
        conn, owner_id=user["id"], label=payload.label, value_enc=value_enc
    )
    return SecretOut(id=rec["id"], label=payload.label, value=payload.value, created_at="")


@router.get("", response_model=list[SecretListItem])
def list_secrets(user: CurrentUser, conn: DbConn) -> list[SecretListItem]:
    items: list[SecretListItem] = []
    for row in repository.list_secrets_for_owner(conn, user["id"]):
        try:
            preview = _mask(crypto.decrypt(row["value_enc"]))
        except Exception:  # ciphertext illisible (clé tournée) : on n'expose rien
            preview = "••••••"
        items.append(
            SecretListItem(
                id=row["id"], label=row["label"], preview=preview, created_at=row["created_at"]
            )
        )
    return items


@router.get("/{secret_id}", response_model=SecretOut)
def reveal_secret(secret_id: str, user: CurrentUser, conn: DbConn) -> SecretOut:
    row = repository.get_secret_for_owner(conn, secret_id, user["id"])
    if row is None:
        # 404 (pas 403) : on ne confirme pas l'existence du secret d'autrui.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret introuvable.")
    try:
        value = crypto.decrypt(row["value_enc"])
    except Exception:
        # On ne journalise QUE l'identifiant (UUID), jamais la valeur déchiffrée.
        # nosemgrep
        logger.exception("Déchiffrement impossible pour l'id %s", secret_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Erreur interne."
        ) from None
    return SecretOut(
        id=row["id"], label=row["label"], value=value, created_at=row["created_at"]
    )


@router.delete("/{secret_id}", response_model=MessageOut)
def delete_secret(secret_id: str, user: CurrentUser, conn: DbConn) -> MessageOut:
    if not repository.delete_secret_for_owner(conn, secret_id, user["id"]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret introuvable.")
    return MessageOut(detail="Secret supprimé.")
