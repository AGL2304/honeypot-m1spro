"""vuln_app — JUMEAU VOLONTAIREMENT VULNÉRABLE de secure_app (démo M1SPRO).

==============================================================================
  ⚠️  CODE INTENTIONNELLEMENT NON SÉCURISÉ — NE JAMAIS DÉPLOYER EN PROD  ⚠️
==============================================================================

Cette application reproduit *la même surface d'API* que ``secure_app`` mais en
RETIRANT chaque mitigation, afin de montrer le comparatif « avant / après » en
soutenance. Les MÊMES commandes Kali (curl/ffuf/hydra/sqlmap) qui échouent
contre secure_app (port 8001) RÉUSSISSENT ici (port 8002).

Vulnérabilités plantées volontairement (miroir du programme) :
  - J1  Injection SQL      : requêtes par concaténation de chaînes.
  - J1  Command injection  : subprocess(shell=True) avec f-string.
  - J3  Auth cassée        : mots de passe en clair, JWT sans vérif de signature
                             (alg:none accepté), pas de MFA.
  - J4  BOLA / IDOR        : /notes/{id} ne vérifie pas le propriétaire.
  - J4  Pas de rate limit  : brute-force illimité (jamais de 429).
  - J4  Fuite d'info       : /users/me renvoie le mot de passe, erreurs = stack
                             trace, docs exposées, aucun en-tête de sécurité.

Pédagogique uniquement. À lancer derrière un pare-feu, sur TA propre machine,
et à éteindre après la démo.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

import app_telemetry

# Base SQLite jetable (fichier local, recréé au besoin).
_DB = Path(__file__).parent / "vuln.db"

app = FastAPI(
    title="vuln_app — JUMEAU VULNÉRABLE (démo M1SPRO)",
    description="⚠️ Volontairement non sécurisé. Comparatif de secure_app.",
    version="0.0.0-insecure",
    # VULN J4 : docs interactives exposées sans restriction.
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# --- Télémétrie comparative (optionnelle, fail-open) -------------------------
# Enregistre chaque requête dans le PostgreSQL du honeypot pour le dashboard
# Grafana « secure vs vuln ». Inactif si APP_METRICS_DSN n'est pas défini.
@app.middleware("http")
async def request_telemetry(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    if app_telemetry.enabled():
        latency_ms = (time.perf_counter() - start) * 1000.0
        xff = request.headers.get("x-forwarded-for", "")
        client_ip = (
            xff.split(",")[0].strip()
            if xff
            else (request.client.host if request.client else None)
        )
        app_telemetry.record(
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            latency_ms=latency_ms,
        )
    return response


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB)
    conn.row_factory = sqlite3.Row
    return conn


@app.on_event("startup")
def _init_db() -> None:
    conn = _conn()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       TEXT PRIMARY KEY,
                username TEXT,
                email    TEXT,
                password TEXT          -- VULN J3 : mot de passe stocké EN CLAIR
            );
            CREATE TABLE IF NOT EXISTS notes (
                id       TEXT PRIMARY KEY,
                owner_id TEXT,
                title    TEXT,
                body     TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# --- JWT « maison » SANS vérification de signature (VULN J3) ------------------
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def issue_token(sub: str) -> str:
    """Émet un jeton… dont la signature ne sera jamais vérifiée."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": sub, "type": "access"}).encode())
    return f"{header}.{payload}.insecuresignature"


def decode_unverified(authorization: str | None) -> dict | None:
    """VULN J3 : décode le payload SANS vérifier la signature ni l'algorithme.

    -> un jeton ``alg:none`` forgé est accepté tel quel.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    try:
        parts = token.split(".")
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None


# --- Schémas (souples : pas de extra="forbid", contrairement à secure_app) ----
class RegisterIn(BaseModel):
    username: str
    email: str = ""
    password: str


class LoginIn(BaseModel):
    username: str
    password: str
    otp: str | None = None


class NoteIn(BaseModel):
    title: str
    body: str = ""


class PingIn(BaseModel):
    host: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": app.version, "warning": "INSECURE DEMO APP"}


# --- J3 : inscription (mot de passe en clair) --------------------------------
@app.post("/auth/register", status_code=201)
def register(data: RegisterIn) -> dict:
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), data.username, data.email, data.password),
        )
        conn.commit()
    finally:
        conn.close()
    return {"detail": "Compte créé."}


# --- J1 : login vulnérable à l'injection SQL (concaténation) ------------------
@app.post("/auth/login")
def login(data: LoginIn) -> JSONResponse:
    conn = _conn()
    try:
        # VULN J1 : la saisie est interpolée directement dans la requête.
        #   username = alice' OR '1'='1   -> contourne l'authentification
        #   username = alice'--           -> commente la vérif du mot de passe
        query = (
            "SELECT id, username FROM users "
            f"WHERE username = '{data.username}' AND password = '{data.password}'"
        )
        row = conn.execute(query).fetchone()
    finally:
        conn.close()

    if row is None:
        return JSONResponse(status_code=401, content={"detail": "Identifiants invalides."})

    tok = issue_token(row["id"])
    # VULN J4 : aucun rate limiting -> brute-force illimité, jamais de 429.
    return JSONResponse(
        status_code=200,
        content={"access_token": tok, "refresh_token": tok, "token_type": "bearer"},
    )


@app.post("/auth/refresh")
def refresh(payload: dict) -> dict:
    # On ré-émet bêtement un jeton à partir du refresh fourni (non vérifié).
    return {"access_token": payload.get("refresh_token", "x"),
            "refresh_token": payload.get("refresh_token", "x"),
            "token_type": "bearer"}


# --- J3 : /users/me fait confiance au jeton ET fuite le mot de passe ----------
@app.get("/users/me")
def users_me(authorization: str | None = Header(default=None)) -> JSONResponse:
    claims = decode_unverified(authorization)
    if claims is None:
        return JSONResponse(status_code=401, content={"detail": "Token manquant/illisible."})

    sub = claims.get("sub")
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id, username, email, password FROM users WHERE id = ?", (sub,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        # VULN J3 : jeton forgé (alg:none, sub bidon) -> on renvoie quand même 200
        # en faisant confiance aux claims non signés.
        return JSONResponse(status_code=200, content={
            "id": sub, "username": claims.get("username", "?"),
            "note": "claims non vérifiés acceptés",
        })

    # VULN J4 : fuite du mot de passe en clair dans la réponse.
    return JSONResponse(status_code=200, content={
        "id": row["id"], "username": row["username"], "email": row["email"],
        "password": row["password"],
    })


# --- J4 : notes SANS contrôle de propriétaire (BOLA / IDOR) -------------------
def _require_user(authorization: str | None) -> str | None:
    claims = decode_unverified(authorization)
    return claims.get("sub") if claims else None


@app.post("/notes", status_code=201)
def create_note(data: NoteIn, authorization: str | None = Header(default=None)) -> JSONResponse:
    uid = _require_user(authorization)
    if uid is None:
        return JSONResponse(status_code=401, content={"detail": "Auth requise."})
    nid = str(uuid.uuid4())
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
            (nid, uid, data.title, data.body),
        )
        conn.commit()
    finally:
        conn.close()
    return JSONResponse(status_code=201, content={"id": nid, "title": data.title, "body": data.body})


@app.get("/notes")
def list_notes(authorization: str | None = Header(default=None)) -> JSONResponse:
    uid = _require_user(authorization)
    if uid is None:
        return JSONResponse(status_code=401, content={"detail": "Auth requise."})
    conn = _conn()
    try:
        rows = conn.execute("SELECT id, title, body FROM notes WHERE owner_id = ?", (uid,)).fetchall()
    finally:
        conn.close()
    return JSONResponse(status_code=200, content=[dict(r) for r in rows])


@app.get("/notes/{note_id}")
def get_note(note_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
    if _require_user(authorization) is None:
        return JSONResponse(status_code=401, content={"detail": "Auth requise."})
    conn = _conn()
    try:
        # VULN J4 (BOLA) : on récupère la note SANS vérifier qu'elle appartient
        # à l'appelant -> n'importe qui lit la note de n'importe qui.
        row = conn.execute("SELECT id, owner_id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return JSONResponse(status_code=404, content={"detail": "Introuvable."})
    return JSONResponse(status_code=200, content=dict(row))


@app.delete("/notes/{note_id}")
def delete_note(note_id: str, authorization: str | None = Header(default=None)) -> JSONResponse:
    if _require_user(authorization) is None:
        return JSONResponse(status_code=401, content={"detail": "Auth requise."})
    conn = _conn()
    try:
        # VULN J4 (BOLA) : suppression sans contrôle de propriété.
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
        deleted = cur.rowcount
    finally:
        conn.close()
    if not deleted:
        return JSONResponse(status_code=404, content={"detail": "Introuvable."})
    return JSONResponse(status_code=200, content={"detail": "Supprimée."})


# --- J1 : command injection (/tools/ping via shell=True) ---------------------
@app.post("/tools/ping")
def ping(data: PingIn, authorization: str | None = Header(default=None)) -> JSONResponse:
    if _require_user(authorization) is None:
        return JSONResponse(status_code=401, content={"detail": "Auth requise."})
    # VULN J1 : la cible est injectée dans un shell -> `127.0.0.1;id` exécute id.
    cmd = f"ping -c 1 {data.host}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)  # noqa: S602
    return JSONResponse(status_code=200, content={
        "host": data.host,
        "returncode": proc.returncode,
        "reachable": proc.returncode == 0,
        # VULN J4 : on renvoie la sortie brute -> l'attaquant voit le résultat
        # de la commande injectée.
        "output": (proc.stdout + proc.stderr),
        "cmd": cmd,
    })


# --- J4 : gestion d'erreurs qui FUITE la stack trace -------------------------
@app.exception_handler(Exception)
async def leaky_handler(request: Request, exc: Exception) -> PlainTextResponse:
    import traceback
    # VULN A09/A05 : on renvoie la trace complète au client.
    return PlainTextResponse(status_code=500, content="".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    ))


# Note : AUCUN middleware d'en-têtes de sécurité, AUCUN CORS whitelist,
# AUCUN rate limiter -> c'est tout l'intérêt du comparatif.
