"""Faux shell Debian crédible, partagé par les services SSH et Telnet (B6, B20, B21).

Objectif furtivité : répondre de façon cohérente aux commandes les plus tapées par
les attaquants en honeypot (analyse Cowrie), avec un faux filesystem riche (30+
fichiers navigables, ~/.ssh, ~/Documents, ~/projects) et des réponses système
plausibles (ps, netstat, who, last, /proc). Un jitter aléatoire est appliqué par
l'appelant (SSH/Telnet) pour casser la régularité des latences.
"""

from __future__ import annotations

import posixpath

HOSTNAME = "srv-web-01"
USER = "admin"
_HOME = f"/home/{USER}"

# --------------------------------------------------------------------------- #
# Réponses système simulées (B21)
# --------------------------------------------------------------------------- #

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

_FAKE_MEMINFO = """MemTotal:        8167460 kB
MemFree:         1422680 kB
MemAvailable:    5984120 kB
Buffers:          184220 kB
Cached:          3920140 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB"""

_FAKE_VERSION = (
    "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) "
    "(gcc-12 (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1"
)

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

_FAKE_WHO = "admin    pts/0        2026-06-08 10:21 (10.13.0.9)"

_FAKE_LAST = """admin    pts/0        10.13.0.9        Mon Jun  8 10:21   still logged in
admin    pts/0        10.13.0.9        Sun Jun  7 18:02 - 19:44  (01:42)
admin    pts/0        10.13.0.9        Sat Jun  6 09:14 - 12:30  (03:16)
reboot   system boot  6.1.0-18-amd64   Sun Jun  7 09:00   still running
admin    pts/0        10.13.0.42       Fri Jun  5 21:09 - 22:55  (01:46)

wtmp begins Fri Jun  5 21:09:13 2026"""

_BASH_HISTORY = """ls -la
cd /var/www/html
git pull
sudo apt update
sudo apt upgrade -y
docker ps
docker compose logs -f
vim config.yml
systemctl status nginx
tail -f /var/log/nginx/access.log
psql -U postgres -d appdb
npm install
cat .env
nano ~/projects/webapp/.env
scp backup.zip admin@10.13.0.50:/backups/
exit"""

# --------------------------------------------------------------------------- #
# Faux filesystem riche (B20) : appâts crédibles, navigables via cd/ls/cat
# --------------------------------------------------------------------------- #

_FAKE_ENV = """DATABASE_URL=postgresql://appuser:S3cr3t_Pg_2026@127.0.0.1:5432/appdb
SECRET_KEY=django-insecure-9x2v!q8z@k1m4w7r0t3y6u
STRIPE_API_KEY=sk_live_51KdJ2xLm9Qtoo_fake_to_be_real_bait
JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9-bait
SMTP_PASSWORD=Mailgun_2026_pwd
DEBUG=False"""

_FAKE_ID_RSA = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAv4xK9F0Hq2bAIT_THIS_IS_A_HONEYPOT_DECOY_KEY_NOT_REAL
c2VjcmV0X2RlY295X2tleV9mb3JfaG9uZXlwb3Rfb25seV9ub3RfdXNhYmxlAAAAAAAA
-----END OPENSSH PRIVATE KEY-----"""

_FAKE_FILES_CONTENT = {
    # Système
    "/etc/passwd": _FAKE_PASSWD,
    "/etc/hostname": HOSTNAME,
    "/etc/os-release": (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian'
    ),
    "/etc/crontab": (
        "# /etc/crontab\n"
        "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
        "0 2\t* * *\troot\t/usr/local/bin/backup.sh\n"
    ),
    "/etc/ssh/sshd_config": (
        "Port 22\nPermitRootLogin prohibit-password\n"
        "PasswordAuthentication yes\nX11Forwarding no\nSubsystem sftp internal-sftp"
    ),
    "/etc/nginx/nginx.conf": (
        "user www-data;\nworker_processes auto;\n"
        "events { worker_connections 768; }\n"
        "http { include /etc/nginx/sites-enabled/*; }"
    ),
    "/proc/cpuinfo": _FAKE_CPUINFO,
    "/proc/meminfo": _FAKE_MEMINFO,
    "/proc/version": _FAKE_VERSION,
    "/var/www/html/index.html": "<!DOCTYPE html><html><body><h1>It works!</h1></body></html>",
    "/var/www/html/config.php": (
        "<?php\n$db_host='127.0.0.1';\n$db_user='appuser';\n"
        "$db_pass='S3cr3t_Pg_2026';\n$db_name='appdb';\n"
    ),
    "/var/log/auth.log": (
        "Jun  8 10:21:03 srv-web-01 sshd[640]: Accepted password for admin "
        "from 10.13.0.9 port 51234 ssh2\n"
        "Jun  8 10:19:47 srv-web-01 sshd[638]: Failed password for root "
        "from 203.0.113.7 port 40110 ssh2"
    ),
    "/var/log/syslog": (
        "Jun  8 10:20:01 srv-web-01 CRON[2188]: (root) CMD (/usr/local/bin/backup.sh)"
    ),
    # Home admin
    f"{_HOME}/.bash_history": _BASH_HISTORY,
    f"{_HOME}/.bashrc": (
        "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n"
        "alias ll='ls -alF'\nalias la='ls -A'\nexport EDITOR=vim\n"
    ),
    f"{_HOME}/.profile": (
        '# ~/.profile\nif [ -n "$BASH_VERSION" ]; then\n  . "$HOME/.bashrc"\nfi\n'
        'PATH="$HOME/bin:$PATH"\n'
    ),
    f"{_HOME}/.gitconfig": (
        "[user]\n\tname = Admin\n\temail = admin@example.com\n"
        "[credential]\n\thelper = store\n"
    ),
    f"{_HOME}/.viminfo": (
        "# This viminfo file was generated by Vim 9.0.\n# Command Line History:\n:wq"
    ),
    f"{_HOME}/.lesshst": ".less-history-file:",
    f"{_HOME}/.sudo_as_admin_successful": "",
    f"{_HOME}/notes.txt": (
        "TODO renouveler le certif TLS avant le 30/06\n"
        "Accès Grafana : admin / voir gestionnaire de mdp\n"
        "Penser à purger /var/log (disque à 78%)"
    ),
    f"{_HOME}/todo.txt": "- migrer la base vers PG16\n- activer fail2ban\n- audit sécu Q3",
    # ~/.ssh
    f"{_HOME}/.ssh/known_hosts": (
        "10.13.0.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDecoyHostKeyForBackupServer\n"
        "github.com ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    ),
    f"{_HOME}/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDecoyAuthorizedKeyHoneypot admin@srv-web-01"
    ),
    f"{_HOME}/.ssh/id_rsa": _FAKE_ID_RSA,
    f"{_HOME}/.ssh/id_rsa.pub": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDecoyPublicKeyHoneypot admin@srv-web-01"
    ),
    f"{_HOME}/.ssh/config": (
        "Host backup\n  HostName 10.13.0.50\n  User admin\n  IdentityFile ~/.ssh/id_rsa\n"
    ),
    # ~/Documents
    f"{_HOME}/Documents/passwords.txt": (
        "grafana: admin / Gr@fana_2026\n"
        "postgres: appuser / S3cr3t_Pg_2026\n"
        "routeur: admin / admin123\n"
        "wifi-bureau: M0nB3auR3seau!"
    ),
    f"{_HOME}/Documents/budget_2026.csv": (
        "poste,montant\nlicences,12000\ninfra cloud,8400\nformations,3500"
    ),
    f"{_HOME}/Documents/rapport_secu.txt": (
        "Audit interne T2 2026 : 3 vulnérabilités moyennes corrigées, "
        "MFA à généraliser, sauvegardes testées OK."
    ),
    f"{_HOME}/Documents/contacts.csv": (
        "nom,email,tel\nDupont,dupont@example.com,0601020304"
    ),
    f"{_HOME}/Documents/meeting_notes.md": "# Réunion infra\n- migration PG\n- renouveler certifs",
    # ~/projects/webapp
    f"{_HOME}/projects/webapp/.env": _FAKE_ENV,
    f"{_HOME}/projects/webapp/docker-compose.yml": (
        "services:\n  web:\n    build: .\n    ports: ['8000:8000']\n"
        "  db:\n    image: postgres:15\n"
    ),
    f"{_HOME}/projects/webapp/app.py": (
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/')\ndef root():\n    return {'status': 'ok'}\n"
    ),
    f"{_HOME}/projects/webapp/README.md": "# webapp\nApplication interne. `docker compose up`.",
    f"{_HOME}/projects/webapp/requirements.txt": (
        "fastapi==0.111.0\nuvicorn==0.30.0\npsycopg[binary]==3.2.1"
    ),
    # ~/projects/api
    f"{_HOME}/projects/api/main.py": "import sys\nprint('api service')\n",
    f"{_HOME}/projects/api/config.yml": "host: 0.0.0.0\nport: 9000\nlog_level: info",
    f"{_HOME}/projects/api/.env": "API_TOKEN=tok_live_decoy_honeypot_not_real_2026",
    # ~/projects/scripts
    f"{_HOME}/projects/scripts/backup.sh": (
        "#!/bin/bash\npg_dump -U appuser appdb | gzip > /backups/appdb_$(date +%F).sql.gz\n"
    ),
    f"{_HOME}/projects/scripts/deploy.sh": (
        "#!/bin/bash\ngit pull && docker compose up -d --build\n"
    ),
    f"{_HOME}/projects/scripts/restore_db.sh": (
        "#!/bin/bash\ngunzip -c \"$1\" | psql -U appuser appdb\n"
    ),
}

# Arborescence des répertoires : chemin -> entrées (fichiers + sous-dossiers)
_DIRS: dict[str, list[str]] = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "proc", "root", "sbin",
          "srv", "tmp", "usr", "var"],
    "/etc": ["passwd", "hostname", "os-release", "crontab", "ssh", "nginx"],
    "/etc/ssh": ["sshd_config"],
    "/etc/nginx": ["nginx.conf"],
    "/proc": ["cpuinfo", "meminfo", "version"],
    "/var": ["www", "log"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "config.php"],
    "/var/log": ["auth.log", "syslog"],
    "/home": [USER],
    _HOME: [
        "Documents", "projects", ".ssh", ".bash_history", ".bashrc", ".profile",
        ".gitconfig", ".viminfo", ".lesshst", ".sudo_as_admin_successful",
        "notes.txt", "todo.txt",
    ],
    f"{_HOME}/.ssh": ["known_hosts", "authorized_keys", "id_rsa", "id_rsa.pub", "config"],
    f"{_HOME}/Documents": [
        "passwords.txt", "budget_2026.csv", "rapport_secu.txt",
        "contacts.csv", "meeting_notes.md",
    ],
    f"{_HOME}/projects": ["webapp", "api", "scripts"],
    f"{_HOME}/projects/webapp": [
        ".env", "docker-compose.yml", "app.py", "README.md", "requirements.txt",
    ],
    f"{_HOME}/projects/api": ["main.py", "config.yml", ".env"],
    f"{_HOME}/projects/scripts": ["backup.sh", "deploy.sh", "restore_db.sh"],
}


class FakeShell:
    """État minimal d'une session shell (répertoire courant) + faux filesystem."""

    def __init__(self) -> None:
        self.cwd = _HOME

    @property
    def prompt(self) -> str:
        if self.cwd == _HOME:
            short = "~"
        elif self.cwd.startswith(_HOME + "/"):
            short = "~" + self.cwd[len(_HOME):]
        else:
            short = self.cwd
        return f"{USER}@{HOSTNAME}:{short}$ "

    def _resolve(self, target: str) -> str:
        """Résout un chemin (~, relatif, absolu, .., .) en chemin absolu normalisé."""
        if target == "~" or target.startswith("~/"):
            target = _HOME + target[1:]
        if not target.startswith("/"):
            target = posixpath.join(self.cwd, target)
        return posixpath.normpath(target)

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
        if cmd in ("who", "users"):
            return _FAKE_WHO if cmd == "who" else USER
        if cmd == "last":
            return _FAKE_LAST
        if cmd == "uptime":
            return " 10:24:55 up 1 day,  1:24,  1 user,  load average: 0.08, 0.03, 0.01"
        if cmd in ("ls", "ll", "dir"):
            return self._ls(cmd, args)
        if cmd == "cd":
            return self._cd(args)
        if cmd == "cat":
            return self._cat(args)
        if cmd == "echo":
            return " ".join(args)
        if cmd in ("exit", "logout", "quit"):
            return "__EXIT__"
        if cmd in ("wget", "curl"):
            # On loggue (côté appelant) mais on ne télécharge rien.
            return ""
        # Commande inconnue : message bash plausible.
        return f"-bash: {cmd}: command not found"

    def _ls(self, cmd: str, args: list[str]) -> str:
        show_hidden = cmd == "ll" or any(a.startswith("-") and "a" in a for a in args)
        paths = [a for a in args if not a.startswith("-")]
        raw = paths[0] if paths else self.cwd
        target = self._resolve(raw)
        if target in _DIRS:
            names = _DIRS[target]
            if not show_hidden:
                names = [n for n in names if not n.startswith(".")]
            return "  ".join(sorted(names))
        if target in _FAKE_FILES_CONTENT:
            return posixpath.basename(target)
        return f"ls: cannot access '{raw}': No such file or directory"

    def _cd(self, args: list[str]) -> str:
        if not args:
            self.cwd = _HOME
            return ""
        target = self._resolve(args[0])
        if target in _DIRS:
            self.cwd = target
            return ""
        if target in _FAKE_FILES_CONTENT:
            return f"-bash: cd: {args[0]}: Not a directory"
        return f"-bash: cd: {args[0]}: No such file or directory"

    def _cat(self, args: list[str]) -> str:
        if not args:
            return ""
        out: list[str] = []
        for a in args:
            if a.startswith("-"):
                continue
            target = self._resolve(a)
            if target in _FAKE_FILES_CONTENT:
                out.append(_FAKE_FILES_CONTENT[target])
            elif target in _DIRS:
                out.append(f"cat: {a}: Is a directory")
            else:
                out.append(f"cat: {a}: No such file or directory")
        return "\n".join(out)
