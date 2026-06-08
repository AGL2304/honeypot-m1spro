"""Honeypot Telnet (4e service) en asyncio pur, réutilisant le faux shell.

Cible privilégiée des botnets IoT (Mirai, Gafgyt). Demande login/password puis
ouvre le même faux shell Debian que le service SSH. Tout est loggé au contrat.
"""

from __future__ import annotations

import asyncio
import os
import random

from honeypots.common.events import EventWriter, build_event, new_session_id
from honeypots.common.fakeshell import FakeShell

SERVICE = "telnet"
LISTEN_HOST = os.environ.get("TELNET_HOST", "0.0.0.0")  # noqa: S104
LISTEN_PORT = int(os.environ.get("TELNET_PORT", "2323"))

_writer = EventWriter(SERVICE)


async def _readline(reader: asyncio.StreamReader) -> str:
    data = await reader.readline()
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    ip, port = peer[0], peer[1]
    session = new_session_id()

    def emit(event_type: str, **kw) -> None:
        _writer.write(
            build_event(service=SERVICE, src_ip=ip, src_port=port, dst_port=LISTEN_PORT,
                        session_id=session, event_type=event_type, **kw)
        )

    emit("connect")
    try:
        writer.write(b"\r\nUbuntu 22.04.4 LTS\r\nlogin: ")
        await writer.drain()
        username = await _readline(reader)
        writer.write(b"Password: ")
        await writer.drain()
        password = await _readline(reader)
        emit("auth_attempt", username=username, password=password)
        emit("auth_success", username=username)

        shell = FakeShell()
        writer.write(("\r\n" + shell.prompt).encode())
        await writer.drain()
        while True:
            line = await _readline(reader)
            if not line and reader.at_eof():
                break
            emit("command", command=line)
            await asyncio.sleep(random.uniform(0.05, 0.30))  # noqa: S311
            out = shell.run(line)
            if out == "__EXIT__":
                break
            payload = (out + "\r\n" if out else "") + shell.prompt
            writer.write(payload.encode())
            await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        emit("disconnect")
        writer.close()


async def start() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


def main() -> None:
    asyncio.run(start())


if __name__ == "__main__":
    main()
