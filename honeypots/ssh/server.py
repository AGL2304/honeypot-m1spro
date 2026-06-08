"""Honeypot SSH (B4/B6) basé sur asyncssh.

- Accepte toute tentative d'authentification (password) et la loggue.
- Présente un faux shell Debian crédible (commun avec Telnet).
- Émet un événement JSON conforme par tentative et par commande.
- Bannière plausible (B19) et jitter aléatoire sur les réponses (B21).
"""

from __future__ import annotations

import asyncio
import logging
import os
import random

import asyncssh

from honeypots.common.events import EventWriter, build_event, new_session_id
from honeypots.common.fakeshell import FakeShell

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("honeypot.ssh")

SERVICE = "ssh"
LISTEN_HOST = os.environ.get("SSH_HOST", "0.0.0.0")  # noqa: S104 - exposition volontaire
LISTEN_PORT = int(os.environ.get("SSH_PORT", "2222"))
BANNER = os.environ.get("SSH_BANNER", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")
HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY", "/keys/ssh_host_key")

_writer = EventWriter(SERVICE)


def _jitter() -> float:
    return random.uniform(0.05, 0.30)  # noqa: S311 - non cryptographique, furtivité


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self.session_id = new_session_id()
        self.peer_ip = "0.0.0.0"
        self.peer_port = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.peer_ip, self.peer_port = conn.get_extra_info("peername")[:2]
        _writer.write(
            build_event(
                service=SERVICE,
                src_ip=self.peer_ip,
                src_port=self.peer_port,
                dst_port=LISTEN_PORT,
                session_id=self.session_id,
                event_type="connect",
            )
        )

    def begin_auth(self, username: str) -> bool:
        return True  # exiger une authentification (qu'on accepte toujours)

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        _writer.write(
            build_event(
                service=SERVICE,
                src_ip=self.peer_ip,
                src_port=self.peer_port,
                dst_port=LISTEN_PORT,
                session_id=self.session_id,
                event_type="auth_attempt",
                username=username,
                password=password,
            )
        )
        # Accepte ~30% des tentatives pour laisser certains attaquants entrer dans
        # le faux shell sans rendre l'accès trivial (furtivité).
        return random.random() < 0.30  # noqa: S311


async def _handle_shell(process: asyncssh.SSHServerProcess, session_id: str,
                        peer_ip: str, peer_port: int) -> None:
    _writer.write(
        build_event(
            service=SERVICE, src_ip=peer_ip, src_port=peer_port, dst_port=LISTEN_PORT,
            session_id=session_id, event_type="auth_success",
            username=process.get_extra_info("username"),
        )
    )
    shell = FakeShell()
    process.stdout.write(
        "Linux srv-web-01 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64\r\n"
        "Last login: Sun Jun  8 10:21:03 2025 from 10.13.0.7\r\n"
    )
    process.stdout.write(shell.prompt)
    try:
        async for line in process.stdin:
            line = line.rstrip("\n")
            _writer.write(
                build_event(
                    service=SERVICE, src_ip=peer_ip, src_port=peer_port,
                    dst_port=LISTEN_PORT, session_id=session_id,
                    event_type="command", command=line,
                )
            )
            await asyncio.sleep(_jitter())
            out = shell.run(line)
            if out == "__EXIT__":
                process.stdout.write("logout\r\n")
                break
            if out:
                process.stdout.write(out + "\r\n")
            process.stdout.write(shell.prompt)
    except asyncssh.BreakReceived:
        pass
    finally:
        _writer.write(
            build_event(
                service=SERVICE, src_ip=peer_ip, src_port=peer_port,
                dst_port=LISTEN_PORT, session_id=session_id, event_type="disconnect",
            )
        )
        process.exit(0)


def _ensure_host_key() -> None:
    if not os.path.exists(HOST_KEY_PATH):
        os.makedirs(os.path.dirname(HOST_KEY_PATH) or ".", exist_ok=True)
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(HOST_KEY_PATH)


async def start() -> None:
    _ensure_host_key()

    def factory() -> HoneypotSSHServer:
        return HoneypotSSHServer()

    async def process_handler(process: asyncssh.SSHServerProcess) -> None:
        conn = process.channel.get_connection()
        srv: HoneypotSSHServer = conn.get_owner()  # type: ignore[assignment]
        await _handle_shell(process, srv.session_id, srv.peer_ip, srv.peer_port)

    await asyncssh.listen(
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        server_factory=factory,
        server_host_keys=[HOST_KEY_PATH],
        server_version=BANNER.removeprefix("SSH-2.0-"),
        process_factory=process_handler,
    )
    logger.info("Honeypot SSH en écoute sur %s:%s", LISTEN_HOST, LISTEN_PORT)


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start())
    loop.run_forever()


if __name__ == "__main__":
    main()
