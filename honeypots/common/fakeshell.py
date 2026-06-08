"""Faux shell Debian crédible, partagé par les services SSH et Telnet (B6, B20, B21).

Objectif furtivité : répondre de façon cohérente aux commandes les plus tapées par
les attaquants en honeypot (analyse Cowrie), avec un faux filesystem riche et des
réponses système plausibles. Un jitter aléatoire est appliqué par l'appelant.
"""

from __future__ import annotations

HOSTNAME = "srv-web-01"
USER = "admin"

_FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash"""

_FAKE_UNAME = (
    "Linux srv-web-01 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC "
    "Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux"
)

_FAKE_CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
cpu cores\t: 4
processor\t: 1
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
processor\t: 2
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
processor\t: 3
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz"""

_FAKE_PS = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 167404 11200 ?        Ss   Jun07   0:03 /sbin/init
root       412  0.0  0.0  72308  6520 ?        Ss   Jun07   0:00 /lib/systemd/systemd-journald
root       640  0.0  0.0  15848  6200 ?        Ss   Jun07   0:00 /usr/sbin/sshd -D
root       712  0.0  0.0   8492  3200 ?        Ss   Jun07   0:00 /usr/sbin/cron -f
postgres   980  0.0  0.4 218400 33120 ?        Ss   Jun07   0:12 /usr/lib/postgresql/15/bin/postgres
www-data  1102  0.0  0.2 145200 18400 ?        S    Jun07   0:04 nginx: worker process
admin     2201  0.0  0.0  10100  3600 pts/0    Ss   10:21   0:00 -bash
admin     2240  0.0  0.0  10612  3320 pts/0    R+   10:24   0:00 ps aux"""

_FAKE_NETSTAT = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432         0.0.0.0:*               LISTEN
tcp        0      0 10.13.0.21:22          203.0.113.7:51234       ESTABLISHED"""

_BASH_HISTORY = """ls -la
cd /var/www
git pull
sudo apt update
sudo apt upgrade -y
docker ps
docker compose logs -f
vim config.yml
systemctl status nginx
tail -f /var/log/nginx/access.log
psql -U postgres
npm install
cat .env
exit"""

# Faux filesystem : chemin -> contenu (B20)
_FILES: dict[str, str] = {
    "/etc/passwd": _FAKE_PASSWD,
    "/proc/cpuinfo": _FAKE_CPUINFO,
    "/home/admin/.bash_history": _BASH_HISTORY,
    "/home/admin/.bashrc": "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -la'\n",
    "/home/admin/.profile": (
        "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n  . \"$HOME/.bashrc\"\nfi\n"
    ),
}

_LS_HOME = "Documents  projects  .bash_history  .bashrc  .profile  .ssh"
_LS_ROOT = "bin  boot  dev  etc  home  lib  proc  root  sbin  srv  tmp  usr  var"


class FakeShell:
    """État minimal d'une session shell (répertoire courant)."""

    def __init__(self) -> None:
        self.cwd = f"/home/{USER}"

    @property
    def prompt(self) -> str:
        short = "~" if self.cwd == f"/home/{USER}" else self.cwd
        return f"{USER}@{HOSTNAME}:{short}$ "

    def run(self, line: str) -> str:
        """Retourne la sortie simulée pour une ligne de commande."""
        line = line.strip()
        if not line:
            return ""
        parts = line.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == "whoami":
            return USER
        if cmd == "id":
            return f"uid=1000({USER}) gid=1000({USER}) groups=1000({USER}),27(sudo)"
        if cmd == "pwd":
            return self.cwd
        if cmd == "uname":
            return _FAKE_UNAME if "-a" in args else "Linux"
        if cmd == "hostname":
            return HOSTNAME
        if cmd == "history":
            return _BASH_HISTORY
        if cmd == "ps":
            return _FAKE_PS
        if cmd == "netstat":
            return _FAKE_NETSTAT
        if cmd in ("ll",) or (cmd == "ls"):
            return _LS_ROOT if (args and args[-1] == "/") else _LS_HOME
        if cmd == "cd":
            self.cwd = args[0] if args else f"/home/{USER}"
            return ""
        if cmd == "cat":
            if not args:
                return ""
            return _FILES.get(args[0], f"cat: {args[0]}: No such file or directory")
        if cmd == "echo":
            return " ".join(args)
        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"
        if cmd in ("wget", "curl"):
            # On loggue mais on ne télécharge rien.
            return ""
        # Commande inconnue : message bash plausible.
        return f"-bash: {cmd}: command not found"
