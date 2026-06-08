# Guide de test manuel (Windows / PowerShell)

Ce guide permet de **tester soi-même** la chaîne complète du honeypot M1SPRO sous
Windows avec Docker Desktop, sans VM Kali. Toutes les commandes sont en **PowerShell**.

> Les scripts `attacks/*.sh` (Hydra, Nikto, dirsearch) ciblent un environnement
> Linux/Kali. Ce guide les remplace par des commandes natives Windows pour une
> validation rapide en local.

---

## 0. Pièges spécifiques à Windows (à lire en premier)

| Piège | Conséquence | Solution |
|---|---|---|
| `curl` dans PowerShell est un **alias** de `Invoke-WebRequest` | `-s`, `-i`, `-X` non reconnus | utiliser **`curl.exe`** (avec `.exe`) |
| Port **80** occupé par haproxy (distro WSL Ubuntu) | `Bind for 0.0.0.0:80 failed` | honeypot HTTP remappé sur **8080** |
| Grafana ne sortait pas son port 3000 | `localhost:3000` injoignable | Grafana ajouté au réseau `hp_exposed` |

Cibles de test sous Windows : **SSH 22**, **HTTP 8080**, **FTP 21**, **Telnet 23**,
**Grafana 3000**.

---

## 1. Démarrer la stack

```powershell
cd C:\Users\dell\Projet_U3\infra
docker compose up --build -d
docker ps
```

Les 8 conteneurs doivent être `Up`. Vérifier que les **ports sont publiés**
(colonne PORTS), en particulier :

- `honeypot-http`  → `0.0.0.0:8080->8080/tcp`
- `grafana`        → `0.0.0.0:3000->3000/tcp`
- `postgres`       → `5432/tcp` *(interne uniquement — normal)*

---

## 2. Tester le honeypot HTTP (port 8080)

```powershell
# Faux fichier .env (leurre à secrets)
curl.exe -s http://localhost:8080/.env

# En-têtes de réponse (faux fingerprint Apache/PHP)
curl.exe -i http://localhost:8080/.env

# POST d'identifiants sur le faux formulaire admin (capture login/mot de passe)
curl.exe -s -X POST http://localhost:8080/admin -d "log=administrator&pwd=SuperSecret123!"

# Scan de chemins sensibles (codes HTTP)
foreach ($p in @('/wp-login.php','/phpmyadmin/','/.git/config','/api/v1/users')) {
  curl.exe -s -o NUL -w "  $p -> %{http_code}`n" http://localhost:8080$p
}
```

Attendu : faux `.env` avec identifiants bidons, en-têtes `Server: Apache/2.4.57`,
formulaire de login HTML, codes 200/401/404 selon les chemins.

---

## 3. Tester FTP (21) et Telnet (23) — fonction utilitaire TCP

FTP et Telnet sont des protocoles en clair : on dialogue directement en TCP.
Colle d'abord cette fonction dans ta session PowerShell :

```powershell
function Test-Tcp($name, $port, $lines) {
  Write-Host "===== $name (port $port) ====="
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('localhost', $port)
    $s = $c.GetStream(); $s.ReadTimeout = 1500
    Start-Sleep -Milliseconds 300
    $buf = New-Object byte[] 4096
    if ($s.DataAvailable) { $n = $s.Read($buf,0,4096); Write-Host ("<< " + [Text.Encoding]::ASCII.GetString($buf,0,$n).Trim()) }
    foreach ($l in $lines) {
      $b = [Text.Encoding]::ASCII.GetBytes($l + "`r`n")
      $s.Write($b,0,$b.Length); $s.Flush()
      Write-Host (">> " + $l)
      Start-Sleep -Milliseconds 400
      if ($s.DataAvailable) { $n = $s.Read($buf,0,4096); Write-Host ("<< " + [Text.Encoding]::ASCII.GetString($buf,0,$n).Trim()) }
    }
    $c.Close()
  } catch { Write-Host ("ERREUR: " + $_.Exception.Message) }
}
```

Puis lance les scénarios :

```powershell
# FTP : login anonyme + commandes
Test-Tcp "FTP" 21 @('USER anonymous','PASS attacker@evil.com','SYST','PWD','QUIT')

# TELNET : brute-force + commandes shell
Test-Tcp "TELNET" 23 @('root','admin','admin','toor','enable','ls')
```

Attendu :
- **FTP** : `220 (vsFTPd 3.0.5)`, `230 Login successful`, `215 UNIX Type: L8`.
- **TELNET** : faux shell Ubuntu `admin@srv-web-01:~$`, faux fichiers sur `ls`.

---

## 4. Tester SSH (22) — brute-force avec paramiko

`ssh.exe` ne permet pas d'envoyer un mot de passe en non-interactif sous Windows.
On utilise **paramiko** (à installer une fois dans le venv) :

```powershell
python -m pip install paramiko
```

Puis :

```powershell
$py = @'
import paramiko
paramiko.util.log_to_file("NUL")
creds = [("root","root"),("admin","admin"),("root","toor"),("ubuntu","password"),("oracle","123456")]
for u, p in creds:
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("localhost", port=22, username=u, password=p,
                  allow_agent=False, look_for_keys=False,
                  timeout=6, banner_timeout=6, auth_timeout=6)
        print(f"  [+] {u}:{p} -> CONNECTE")
        c.close()
    except paramiko.AuthenticationException:
        print(f"  [-] {u}:{p} -> auth refusee (tentative journalisee)")
    except Exception as e:
        print(f"  [!] {u}:{p} -> {type(e).__name__}: {e}")
'@
$py | python -
```

Attendu : la plupart des couples sont refusés (mais **journalisés**) ;
l'identifiant-piège `ubuntu:password` est accepté pour attirer l'attaquant.

---

## 5. Vérifier la capture en base PostgreSQL

```powershell
# Répartition des événements par service / type
docker exec honeypot-m1spro-postgres-1 psql -U honeypot -d honeypot -c "SELECT service, event_type, count(*) FROM events GROUP BY service, event_type ORDER BY service, event_type;"

# Identifiants capturés (credential harvesting)
docker exec honeypot-m1spro-postgres-1 psql -U honeypot -d honeypot -c "SELECT ts::time(0) AS heure, service, username, password FROM events WHERE username IS NOT NULL OR password IS NOT NULL ORDER BY ts DESC LIMIT 15;"

# Totaux globaux
docker exec honeypot-m1spro-postgres-1 psql -U honeypot -d honeypot -c "SELECT count(*) AS total_events, count(DISTINCT service) AS services, count(DISTINCT session_id) AS sessions FROM events;"
```

> `POSTGRES_USER` et `POSTGRES_DB` valent `honeypot` par défaut
> (voir `.env` / `.env.example`). Adapter si tu les as changés.

---

## 6. Vérifier Grafana (port 3000)

```powershell
# Santé du service
curl.exe -s http://localhost:3000/api/health

# Datasource PostgreSQL provisionnée
curl.exe -s -u "admin:admin" http://localhost:3000/api/datasources

# Test de connexion datasource -> PostgreSQL (remplacer <UID> par le uid ci-dessus)
# curl.exe -s -u "admin:admin" "http://localhost:3000/api/datasources/uid/<UID>/health"

# Dashboards provisionnés
curl.exe -s -u "admin:admin" "http://localhost:3000/api/search?type=dash-db"
```

Puis ouvrir **http://localhost:3000** → identifiants **admin / admin**
(ou la valeur de `GF_SECURITY_ADMIN_PASSWORD` dans `.env`).
Dashboard : **Honeypot M1SPRO - Live**.

---

## 7. Réinitialiser / arrêter

```powershell
# Arrêt simple
docker compose -f C:\Users\dell\Projet_U3\infra\docker-compose.yml down

# Arrêt + suppression des volumes (remet les données et les permissions à zéro)
docker compose -f C:\Users\dell\Projet_U3\infra\docker-compose.yml down -v

# Recréer un seul service (ex. après modif réseau/env de Grafana)
docker compose -f C:\Users\dell\Projet_U3\infra\docker-compose.yml up -d --force-recreate grafana
```

---

## 8. Dépannage Windows

| Symptôme | Cause | Solution |
|---|---|---|
| `Invoke-WebRequest ... Uri:` qui demande une saisie | `curl` = alias PowerShell | utiliser `curl.exe` |
| `Bind for 0.0.0.0:80 failed` | port 80 pris par haproxy (WSL) | déjà remappé sur 8080 ; ou `wsl -d Ubuntu -u root service haproxy stop` |
| `localhost:3000` ne répond pas | Grafana sur réseau `internal:true` uniquement | déjà corrigé (ajout `hp_exposed`) ; sinon `up -d --force-recreate grafana` |
| Login Grafana **401** alors que admin/admin | conteneur dans un état périmé (mot de passe vide) | `docker compose up -d --force-recreate grafana` |
| `unable to open database file` (analyzer) | volume `enrich_data` root:root | `docker volume rm honeypot-m1spro_enrich_data` puis rebuild |
| `PermissionError /keys/ssh_host_key` | volume `sshkeys` root:root | `docker volume rm honeypot-m1spro_sshkeys` puis rebuild |
| `Permission denied` sur `/logs` | volume `logs` root:root | `docker volume rm honeypot-m1spro_logs` puis rebuild |
| `abuse_score` / `country` vides en local | IP privée 192.168.x / pas de clé API | normal ; se remplit avec du trafic Internet réel |
