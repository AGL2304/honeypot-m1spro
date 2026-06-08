"""Honeypot HTTP (B7) basé sur FastAPI.

Routes piégées qui correspondent aux scans Internet les plus fréquents (rapport
SANS ISC). Chaque requête est loggée avec méthode, path, query, headers, body et
user-agent. Les réponses imitent un serveur Apache/Debian (bannière B19).
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from honeypots.common.events import EventWriter, build_event, new_session_id

SERVICE = "http"
LISTEN_PORT = int(os.environ.get("HTTP_PORT", "8080"))
SERVER_BANNER = os.environ.get("HTTP_BANNER", "Apache/2.4.57 (Debian)")

_writer = EventWriter(SERVICE)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _log(request: Request, event_type: str = "http_request") -> None:
    body = (await request.body()).decode("utf-8", errors="replace")
    _writer.write(
        build_event(
            service=SERVICE,
            src_ip=request.client.host if request.client else "0.0.0.0",
            src_port=request.client.port if request.client else 0,
            dst_port=LISTEN_PORT,
            session_id=new_session_id(),
            event_type=event_type,
            http={
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query or None,
                "headers": dict(request.headers),
                "body": body or None,
                "user_agent": request.headers.get("user-agent"),
            },
            raw=body or None,
        )
    )


@app.middleware("http")
async def banner_and_log(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Server"] = SERVER_BANNER
    response.headers["X-Powered-By"] = "PHP/8.1.2"
    return response


@app.get("/admin", response_class=HTMLResponse)
@app.get("/wp-login.php", response_class=HTMLResponse)
async def fake_login(request: Request) -> HTMLResponse:
    await _log(request)
    return HTMLResponse(
        "<html><head><title>Log In</title></head><body>"
        "<form method='post'><input name='log'><input name='pwd' type='password'>"
        "<input type='submit' value='Log In'></form></body></html>"
    )


@app.post("/admin")
@app.post("/wp-login.php")
async def fake_login_post(request: Request) -> HTMLResponse:
    await _log(request, event_type="auth_attempt")
    return HTMLResponse("<html><body>ERROR: Invalid username or password.</body></html>",
                        status_code=200)


@app.get("/.env", response_class=PlainTextResponse)
async def fake_env(request: Request) -> PlainTextResponse:
    await _log(request, event_type="file_access")
    return PlainTextResponse(
        "APP_ENV=production\nAPP_KEY=base64:Zm9vYmFy\n"
        "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=app\n"
        "DB_USERNAME=app\nDB_PASSWORD=S3cr3t_db_pass\n"
    )


@app.get("/.git/config", response_class=PlainTextResponse)
async def fake_git(request: Request) -> PlainTextResponse:
    await _log(request, event_type="file_access")
    return PlainTextResponse(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        "[remote \"origin\"]\n\turl = git@github.com:acme/internal-app.git\n"
    )


@app.get("/phpinfo.php", response_class=HTMLResponse)
async def fake_phpinfo(request: Request) -> HTMLResponse:
    await _log(request, event_type="file_access")
    return HTMLResponse("<h1>PHP Version 8.1.2</h1><table><tr><td>System</td>"
                        "<td>Linux srv-web-01 6.1.0-18-amd64</td></tr></table>")


@app.get("/api/v1/users")
async def fake_users(request: Request) -> JSONResponse:
    await _log(request)
    return JSONResponse({"error": "unauthorized"}, status_code=401)


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def catch_all(request: Request, full_path: str) -> Response:
    await _log(request)
    return PlainTextResponse("Not Found", status_code=404)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=LISTEN_PORT, server_header=False,  # noqa: S104
                log_level="warning")


if __name__ == "__main__":
    main()
