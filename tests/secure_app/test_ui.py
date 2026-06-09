"""Tests de l'IHM web multi-pages (front-end servi par l'app)."""

from __future__ import annotations

import pytest

UI_PAGES = ["/", "/login", "/register", "/dashboard"]


@pytest.mark.parametrize("path", UI_PAGES)
def test_ui_pages_served_with_dedicated_csp(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    csp = resp.headers.get("Content-Security-Policy", "")
    # CSP spécifique à l'IHM : nos ressources autorisées, mais PAS d'inline.
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_home_links_to_login_and_register(client):
    html = client.get("/").text
    assert 'href="/login"' in html
    assert 'href="/register"' in html
    # Pas de script inline : tout passe par des fichiers externes.
    assert "/static/common.js" in html


def test_pages_load_their_scripts(client):
    assert "/static/login.js" in client.get("/login").text
    assert "/static/register.js" in client.get("/register").text
    assert "/static/dashboard.js" in client.get("/dashboard").text


@pytest.mark.parametrize(
    "asset,ctype",
    [
        ("/static/common.js", "javascript"),
        ("/static/dashboard.js", "javascript"),
        ("/static/styles.css", "css"),
    ],
)
def test_static_assets_available(client, asset, ctype):
    resp = client.get(asset)
    assert resp.status_code == 200
    assert ctype in resp.headers["content-type"]


def test_api_keeps_locked_csp(client):
    # L'API JSON garde la CSP verrouillée (default-src 'none'), pas la CSP UI.
    resp = client.get("/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" not in csp
