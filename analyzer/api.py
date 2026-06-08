"""API d'ingestion et de consultation (B13) en FastAPI.

POST /events     : ingère un événement (validé, enrichi, classifié, persisté)
GET  /events     : derniers événements
GET  /stats      : KPIs agrégés pour le dashboard
GET  /attackers  : top des IP attaquantes
GET  /health     : sonde
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from jsonschema import ValidationError

from honeypots.common.events import validate_event

from . import db
from .classifier import BehaviorClassifier
from .enrichers import enrich

app = FastAPI(title="Honeypot Analyzer", version="1.0.0")
_classifier = BehaviorClassifier()


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/events")
def ingest(event: dict[str, Any]) -> dict[str, Any]:
    try:
        validate_event(event)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Schema invalide: {exc.message}") from exc

    enrichment = enrich(event["src_ip"], event.get("enrichment"))
    db.insert_event(event, enrichment, classification=None)

    # Re-classifie la session complète à chaque nouvel événement.
    session = db.session_events(event["session_id"])
    classification = _classifier.classify_session(session)
    if classification:
        with db.connect() as conn:
            conn.execute(
                "UPDATE events SET classification = %s WHERE session_id = %s",
                (classification, event["session_id"]),
            )
            conn.commit()

    return {"ingested": True, "classification": classification, "enrichment": enrichment}


@app.get("/events")
def list_events(limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    with db.connect() as conn:
        return conn.execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT %s", (limit,)
        ).fetchall()


@app.get("/stats")
def get_stats() -> dict[str, Any]:
    return db.stats()


@app.get("/attackers")
def get_attackers() -> list[dict[str, Any]]:
    return db.attackers()


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")  # noqa: S104


if __name__ == "__main__":
    main()
