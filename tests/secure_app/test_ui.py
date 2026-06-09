"""Tests de l'IHM web auto-portée (front-end servi par l'app)."""

from __future__ import annotations


def test_root_redirects_to_app(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/app"


def test_ui_page_served_with_dedicated_csp(client):
    resp = client.get("/app")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    csp = resp.headers.get("Content-Security-Policy", "")
    # CSP spécifique à l'IHM : nos ressources autorisées, mais PAS d'inline.
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    # Le HTML charge bien le JS/CSS externes (pas d'inline).
    assert "/static/app.js" in resp.text
    assert "/static/styles.css" in resp.text


def test_static_assets_available(client):
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    css = client.get("/static/styles.css")
    assert css.status_code == 200
    assert "css" in css.headers["content-type"]


def test_api_keeps_locked_csp(client):
    # L'API JSON garde la CSP verrouillée (default-src 'none'), pas la CSP UI.
    resp = client.get("/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" not in csp
