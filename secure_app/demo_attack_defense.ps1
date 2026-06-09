# Demo attaque/defense de secure_app (fil rouge SDLC M1SPRO).
# Usage : depuis n'importe ou, l'app doit ecouter sur http://localhost:8001
#   powershell -File .\secure_app\demo_attack_defense.ps1
# (ou, depuis infra\ :  & ..\secure_app\demo_attack_defense.ps1)

$ErrorActionPreference = "Stop"
$base = "http://localhost:8001"
$pw   = "Sup3r-S3cret!Pass"
$pass = 0
$fail = 0

function Call {
    param($method, $path, $body, $token)
    $headers = @{}
    if ($token) { $headers["Authorization"] = "Bearer $token" }
    try {
        if ($body) { $json = ($body | ConvertTo-Json -Compress) } else { $json = $null }
        $r = Invoke-WebRequest -Uri "$base$path" -Method $method -Headers $headers `
                -Body $json -ContentType "application/json" -UseBasicParsing
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $r.Content }
    } catch {
        # Portable Windows PowerShell 5.1 (WebException) ET PowerShell 7+ (HttpResponseException).
        $resp = $_.Exception.Response
        $code = -1
        $text = ""
        if ($resp) {
            try { $code = [int]$resp.StatusCode } catch {}
            # GetResponseStream() n'existe qu'en 5.1 ; en 7+ on lit autrement.
            try {
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $text = $sr.ReadToEnd()
            } catch {
                try { $text = $_.ErrorDetails.Message } catch {}
            }
        }
        return [pscustomobject]@{ Status = $code; Body = $text }
    }
}

function Check {
    param($label, $got, $expected)
    if ($got -eq $expected) {
        Write-Host ("[PASS] {0,-55} -> {1}" -f $label, $got) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ("[FAIL] {0,-55} -> {1} (attendu {2})" -f $label, $got, $expected) -ForegroundColor Red
        $script:fail++
    }
}

# Token JWT alg:none forge a la main (pas de dependance pyjwt).
function ForgeAlgNone {
    function B64Url($obj) {
        $json  = ($obj | ConvertTo-Json -Compress)
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    }
    $h = B64Url @{ alg = "none"; typ = "JWT" }
    $p = B64Url @{ sub = "x"; type = "access"; jti = "1"; exp = 9999999999 }
    return "$h.$p."
}

Write-Host "`n=== secure_app : demo attaque/defense (M1SPRO) ===`n" -ForegroundColor Cyan

# Sante
$h = Call GET /health
Check "health public" $h.Status 200

# --- J3 : comptes + login ---
Write-Host "`n-- J3 Authentification --" -ForegroundColor Yellow
Check "register alice (201)" (Call POST /auth/register @{username="alice";email="alice@example.com";password=$pw}).Status 201
Check "register bob   (201)" (Call POST /auth/register @{username="bob";email="bob@example.com";password=$pw}).Status 201
Check "register alice en double -> 409 neutre" (Call POST /auth/register @{username="alice";email="alice@example.com";password=$pw}).Status 409

$loginA = Call POST /auth/login @{username="alice";password=$pw}
Check "login alice (200)" $loginA.Status 200
$tokAlice = ($loginA.Body | ConvertFrom-Json).access_token
$tokBob   = ((Call POST /auth/login @{username="bob";password=$pw}).Body | ConvertFrom-Json).access_token

$me = Call GET /users/me $null $tokAlice
Check "/users/me (200)" $me.Status 200
if ($me.Body -match "password_hash" -or $me.Body -match "mfa_secret") {
    Check "/users/me ne fuit aucun secret" "fuite!" "ok"
} else {
    Check "/users/me ne fuit aucun secret" "ok" "ok"
}

# --- J1 : injection SQL ---
Write-Host "`n-- J1 Injection SQL (neutralisee) --" -ForegroundColor Yellow
Check "SQLi ' OR '1'='1 -> 401"        (Call POST /auth/login @{username="alice' OR '1'='1";password="x"}).Status 401
Check "SQLi DROP TABLE -> 401"         (Call POST /auth/login @{username="alice'; DROP TABLE users;--";password="x"}).Status 401
Check "table users intacte (login ok)" (Call POST /auth/login @{username="alice";password=$pw}).Status 200

# --- J4 : BOLA / IDOR ---
Write-Host "`n-- J4 BOLA / IDOR --" -ForegroundColor Yellow
$noteId = ((Call POST /notes @{title="secret";body="prive alice"} $tokAlice).Body | ConvertFrom-Json).id
Check "bob lit la note d'alice -> 404"  (Call GET "/notes/$noteId" $null $tokBob).Status 404
Check "alice lit sa note      -> 200"   (Call GET "/notes/$noteId" $null $tokAlice).Status 200
Check "bob supprime la note d'alice->404" (Call DELETE "/notes/$noteId" $null $tokBob).Status 404

# --- J1 : command injection ---
Write-Host "`n-- J1 Command injection (/tools/ping) --" -ForegroundColor Yellow
Check "ping '127.0.0.1; rm -rf /' -> 400" (Call POST /tools/ping @{host="127.0.0.1; rm -rf /"} $tokAlice).Status 400
Check "ping '8.8.8.8 | cat passwd' -> 400" (Call POST /tools/ping @{host="8.8.8.8 | cat /etc/passwd"} $tokAlice).Status 400
Check "ping sans auth -> 401"             (Call POST /tools/ping @{host="127.0.0.1"}).Status 401

# --- J3 : JWT alg:none ---
Write-Host "`n-- J3 JWT alg:none forge --" -ForegroundColor Yellow
$forged = ForgeAlgNone
Check "token alg:none -> 401" (Call GET /users/me $null $forged).Status 401
Check "token bidon    -> 401" (Call GET /users/me $null "aaa.bbb.ccc").Status 401

# --- J4 : rate limiting ---
Write-Host "`n-- J4 Rate limiting login (anti brute-force) --" -ForegroundColor Yellow
$codes = 1..7 | ForEach-Object { (Call POST /auth/login @{username="alice";password=("bad{0}" -f $_)}).Status }
Write-Host ("    sequence des codes : {0}" -f ($codes -join ", "))
Check "6e/7e tentative bloquee -> 429" ($codes[-1]) 429

# --- Bilan ---
Write-Host "`n=== Bilan : $pass PASS / $fail FAIL ===`n" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 } else { exit 0 }
