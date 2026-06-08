"""Honeypot FTP (B8) basé sur pyftpdlib.

Accepte toute connexion (authorizer permissif), présente un faux filesystem appât
(secrets.txt, backup.zip, db_dump.sql) et loggue USER/PASS/LIST/RETR via un handler
personnalisé. Bannière vsFTPd plausible (B19).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from honeypots.common.events import EventWriter, build_event, new_session_id

SERVICE = "ftp"
LISTEN_PORT = int(os.environ.get("FTP_PORT", "2121"))
BANNER = os.environ.get("FTP_BANNER", "vsFTPd 3.0.5")

_writer = EventWriter(SERVICE)

_BAIT_FILES = {
    "secrets.txt": "api_key=sk_live_51HxxxxREDACTED\nadmin_pass=Pr0d#2024\n",
    "db_dump.sql": "-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'admin','5f4dcc3b5aa7');\n",
    "backup.zip": "PK\x03\x04 fake archive content",
    "README.txt": "Backups quotidiens. Contact: ops@acme.internal\n",
}


def _build_bait_root() -> str:
    root = Path(tempfile.gettempdir()) / "ftp_bait"
    root.mkdir(parents=True, exist_ok=True)
    for name, content in _BAIT_FILES.items():
        (root / name).write_text(content, encoding="utf-8", errors="replace")
    return str(root)


class HoneypotFTPHandler(FTPHandler):
    banner = f"220 ({BANNER})"

    def on_connect(self) -> None:
        self._session_id = new_session_id()
        _emit(self, "connect")

    def on_login(self, username: str) -> None:
        _emit(self, "auth_success", username=username)

    def on_file_sent(self, file: str) -> None:
        _emit(self, "file_access", command=f"RETR {Path(file).name}")

    def ftp_USER(self, line: str) -> None:
        _emit(self, "auth_attempt", username=line)
        super().ftp_USER(line)

    def ftp_PASS(self, line: str) -> None:
        _emit(self, "auth_attempt", username=getattr(self, "username", None), password=line)
        super().ftp_PASS(line)

    def ftp_LIST(self, path: str) -> None:
        _emit(self, "ftp_command", command=f"LIST {path}")
        super().ftp_LIST(path)


def _emit(handler: FTPHandler, event_type: str, **kw) -> None:
    ip, port = handler.remote_ip, handler.remote_port
    _writer.write(
        build_event(
            service=SERVICE, src_ip=ip, src_port=port, dst_port=LISTEN_PORT,
            session_id=getattr(handler, "_session_id", new_session_id()),
            event_type=event_type, **kw,
        )
    )


def main() -> None:
    authorizer = DummyAuthorizer()
    # 'anonymous' + tout user grâce à un mot de passe accepté côté handler.
    authorizer.add_anonymous(_build_bait_root(), perm="elr")
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    server = FTPServer(("0.0.0.0", LISTEN_PORT), handler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
