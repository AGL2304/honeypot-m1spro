"""Routes notes — démonstration anti-BOLA/IDOR (J4 / API1).

Chaque note appartient à un utilisateur (`owner_id`). TOUTES les opérations
filtrent par `owner_id` du porteur du token : deviner l'UUID d'autrui renvoie
404, jamais la ressource. Les identifiants sont des **UUID** (non séquentiels,
non énumérables — cf. pattern professionnel J4).

Anti-pattern (vu en J4) :
    GET /api/orders/124   ->  renvoie la commande d'un autre user  # ❌ BOLA
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from .. import repository
from ..dependencies import CurrentUser, DbConn
from ..schemas import MessageOut, NoteIn, NoteOut

router = APIRouter(prefix="/notes", tags=["notes"])


@router.post("", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_note(payload: NoteIn, user: CurrentUser, conn: DbConn) -> NoteOut:
    note = repository.create_note(
        conn, owner_id=user["id"], title=payload.title, body=payload.body
    )
    return NoteOut(**note)


@router.get("", response_model=list[NoteOut])
def list_notes(user: CurrentUser, conn: DbConn) -> list[NoteOut]:
    return [NoteOut(**n) for n in repository.list_notes_for_owner(conn, user["id"])]


@router.get("/{note_id}", response_model=NoteOut)
def get_note(note_id: str, user: CurrentUser, conn: DbConn) -> NoteOut:
    note = repository.get_note_for_owner(conn, note_id, user["id"])
    if note is None:
        # 404 (pas 403) : on ne confirme même pas l'existence d'une note d'autrui.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note introuvable.")
    return NoteOut(**note)


@router.delete("/{note_id}", response_model=MessageOut)
def delete_note(note_id: str, user: CurrentUser, conn: DbConn) -> MessageOut:
    if not repository.delete_note_for_owner(conn, note_id, user["id"]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note introuvable.")
    return MessageOut(detail="Note supprimée.")
