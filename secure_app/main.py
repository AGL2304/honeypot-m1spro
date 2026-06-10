"""Fabrique de l'application FastAPI sécurisée (J4/J5 — assemblage).

Ce module câble tout ce que le programme M1SPRO recommande au niveau du
*périmètre* de l'application :

  - **CORS whitelisté** (jamais ``*`` avec credentials) — A05/API8.
  - **En-têtes de sécurité** (HSTS, X-Content-Type-Options, frame-ancestors,
    CSP minimale, Referrer-Policy) — durcissement navigateur (J4).
  - **Gestion d'erreurs générique** : aucune stack trace, aucun détail interne
    renvoyé au client (anti fuite d'information, A05/A09).
  - Initialisation de la base au démarrage (idempotent).
  - Endpoint ``/health`` non authentifié pour les sondes.

L'application reste *fail-closed* : en production, l'absence de
``SECURE_APP_SECRET_KEY`` empêche le démarrage (cf. config.py).
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, app_telemetry, seed
from .config import get_settings
from .database import connect, init_db
from .logging_conf import configure_logging
from .routers import auth, notes, secrets, tools, users

logger = logging.getLogger("secure_app.main")

# Répertoire des fichiers statiques de l'IHM (HTML/CSS/JS auto-portés).
_STATIC_DIR = Path(__file__).parent / "static"

# CSP DÉDIÉE à la page de l'IHM : on autorise UNIQUEMENT nos propres ressources
# (`'self'`), sans `'unsafe-inline'` -> scripts/styles externes seulement. Les
# réponses de l'API gardent, elles, la CSP verrouillée `default-src 'none'`.
_UI_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# En-têtes de sécurité appliqués à chaque réponse (J4).
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # CSP minimale : API JSON, on interdit tout par défaut.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    # Politique de permissions navigateur : on coupe les capteurs.
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # API authentifiée : aucune réponse ne doit être mise en cache par un
    # cache partagé (proxy) -> évite la fuite de données utilisateur
    # (CWE-524, confirmé par le DAST OWASP ZAP).
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


def create_app() -> FastAPI:
    """Construit et configure l'instance FastAPI sécurisée."""
    configure_logging()
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Démarrage : initialise la base (idempotent).
        conn = connect(app.state.db_path)
        try:
            init_db(conn)
            seed.seed_if_empty(conn)  # données de démo si base vierge (idempotent)
        finally:
            conn.close()
        logger.info("secure_app démarrée (env=%s, version=%s)", settings.env, __version__)
        yield

    app = FastAPI(
        title="secure_app — API REST sécurisée (M1SPRO)",
        version=__version__,
        description=(
            "Application compagnon du honeypot : démonstration défensive du "
            "programme « Sécurité en Programmation » (anti-injection, auth/MFA, "
            "anti-BOLA, rate limiting, secrets, DevSecOps)."
        ),
        # On n'expose pas la doc interactive par défaut en production.
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None if settings.is_prod else "/redoc",
        openapi_url=None if settings.is_prod else "/openapi.json",
        lifespan=lifespan,
    )

    # Chemin DB exposé sur app.state (surchargé par les tests).
    app.state.db_path = settings.db_path

    # --- CORS : whitelist stricte, jamais "*" avec credentials (J4) ----------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    # --- En-têtes de sécurité sur chaque réponse -----------------------------
    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # HSTS seulement en prod (HTTPS) : inutile/contre-productif en dev HTTP.
        if settings.is_prod:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response

    # --- Télémétrie comparative (optionnelle, fail-open) ---------------------
    # Enregistre chaque requête (app, IP, méthode, chemin, code HTTP) dans
    # PostgreSQL pour le dashboard Grafana « secure vs vuln ». Inactif si
    # APP_METRICS_DSN n'est pas défini. Ne modifie jamais la réponse.
    @app.middleware("http")
    async def request_telemetry(request: Request, call_next):  # type: ignore[no-untyped-def]
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

    # --- Gestion d'erreurs générique (pas de stack trace / détail interne) ---
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        # On renvoie le détail prévu par le code applicatif (déjà neutre).
        headers = getattr(exc, "headers", None)
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # 422 générique : on ne renvoie pas la structure interne attendue.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Requête invalide."},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        # On journalise la trace côté serveur, JAMAIS côté client (A09/A05).
        logger.exception("Erreur non gérée sur %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Erreur interne."},
        )

    # --- Endpoint de santé (non authentifié) ---------------------------------
    @app.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- Routers métier ------------------------------------------------------
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(notes.router)
    app.include_router(secrets.router)
    app.include_router(tools.router)

    # --- IHM web multi-pages (front-end auto-porté, client de l'API) ----------
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

        # Chaque page HTML est lue une fois au démarrage et servie avec la CSP
        # spécifique à l'IHM (posée explicitement -> le middleware, qui utilise
        # setdefault, ne l'écrase pas). L'API JSON garde, elle, default-src 'none'.
        _pages = {
            "/": "index.html",
            "/login": "login.html",
            "/register": "register.html",
            "/dashboard": "dashboard.html",
            "/coffre": "secrets.html",  # /secrets est pris par l'API JSON
        }
        _html_cache = {
            path: (_STATIC_DIR / filename).read_text(encoding="utf-8")
            for path, filename in _pages.items()
        }

        def _make_page(path: str):
            html = _html_cache[path]

            def _serve() -> HTMLResponse:
                return HTMLResponse(
                    content=html, headers={"Content-Security-Policy": _UI_CSP}
                )

            return _serve

        for _path in _pages:
            app.add_api_route(
                _path, _make_page(_path), methods=["GET"], include_in_schema=False
            )

    return app


app = create_app()
