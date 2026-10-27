# admin-auth ON_RISK demo: TOTP only after a wrong password (ASCII output)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/demo-risk-mfa.ps1
$ErrorActionPreference = "Stop"

$script:base = if ($env:AA_BASE) { $env:AA_BASE } else { "http://localhost:8080" }
$script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$INITIAL_PASSWORD = "Admin@123456"
$ADMIN_PASSWORD = "Sup3r-Admin!2026"

function Step([string]$text) { Write-Host ""; Write-Host "=== $text ===" }

function Check([string]$name, [bool]$ok, [string]$detail) {
    $flag = if ($ok) { "PASS" } else { "FAIL" }
    Write-Host ("[{0}] {1} :: {2}" -f $flag, $name, $detail)
    if (-not $ok) { $script:failed++ }
}
$script:failed = 0

function Get-CsrfToken {
    Invoke-WebRequest -Uri "$($script:base)/admin-auth/api/csrf" -WebSession $script:session -UseBasicParsing | Out-Null
    $cookie = $script:session.Cookies.GetCookies([uri]$script:base) |
        Where-Object { $_.Name -eq "XSRF-TOKEN" } | Select-Object -First 1
    return [System.Uri]::UnescapeDataString($cookie.Value)
}

function Invoke-Api {
    param([string]$Method, [string]$Path, $Body = $null, [bool]$WithCsrf = $false)
    $request = [System.Net.HttpWebRequest]::Create("$($script:base)$Path")
    $request.Method = $Method
    $request.Accept = "application/json"
    $request.CookieContainer = $script:session.Cookies
    $request.AllowAutoRedirect = $false
    if ($WithCsrf) { $request.Headers.Add("X-XSRF-TOKEN", (Get-CsrfToken)) }
    if ($null -ne $Body) {
        $request.ContentType = "application/json"
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    try { $response = $request.GetResponse() } catch [System.Net.WebException] { $response = $_.Exception.Response }
    $status = [int]$response.StatusCode
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd(); $reader.Close(); $response.Close()
    $json = $null
    try { $json = $text | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ Status = $status; Body = $text; Json = $json }
}

function Login([string]$password) {
    return Invoke-Api -Method POST -Path "/admin-auth/api/login" -Body @{
        identityType = "EMAIL"; identifier = "admin@corp.example"; password = $password
    }
}

function ConvertFrom-Base32([string]$text) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $clean = $text.Trim().TrimEnd('=').Replace(" ", "").ToUpperInvariant()
    $buffer = 0; $bits = 0
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($ch in $clean.ToCharArray()) {
        $idx = $alphabet.IndexOf($ch)
        if ($idx -lt 0) { throw "Invalid Base32 character: $ch" }
        $buffer = ($buffer -shl 5) -bor $idx
        $bits += 5
        if ($bits -ge 8) { $bits -= 8; $bytes.Add([byte](($buffer -shr $bits) -band 0xFF)) }
    }
    return $bytes.ToArray()
}

function Get-Totp([string]$secret, [int]$secondsOffset = 0) {
    $key = ConvertFrom-Base32 $secret
    $unix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $secondsOffset
    $step = [long][Math]::Floor($unix / 30)
    $message = [BitConverter]::GetBytes($step)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($message) }
    $hmac = [System.Security.Cryptography.HMACSHA1]::new([byte[]]$key)
    try { $hash = $hmac.ComputeHash([byte[]]$message) } finally { $hmac.Dispose() }
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $binary = (($hash[$offset] -band 0x7F) -shl 24) -bor
              (($hash[$offset + 1] -band 0xFF) -shl 16) -bor
              (($hash[$offset + 2] -band 0xFF) -shl 8) -bor
              ($hash[$offset + 3] -band 0xFF)
    return (($binary % 1000000)).ToString("000000")
}

# 0) CSRF
Step "0. CSRF"
$csrf = Get-CsrfToken
Check "csrf token" ($csrf.Length -gt 0) "length=$($csrf.Length)"

# 1) first login (bootstrap admin, must change password)
Step "1. First login -> CHANGE_PASSWORD"
$login = Login $INITIAL_PASSWORD
Check "login next=CHANGE_PASSWORD" ($login.Json.next -eq "CHANGE_PASSWORD") "next=$($login.Json.next)"

# 2) initial password change -> ON_RISK: no TOTP on a clean login
Step "2. Change initial password -> should NOT ask TOTP"
$change = Invoke-Api -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{
    ticket = $login.Json.ticket; oldPassword = $INITIAL_PASSWORD; newPassword = $ADMIN_PASSWORD
} -WithCsrf $true
Check "next=OK (no TOTP, session established)" ($change.Json.next -eq "OK") "next=$($change.Json.next)"

# 3) bind TOTP while logged in (session-based, no ticket)
Step "3. Bind TOTP from the logged-in session"
$setup = Invoke-Api -Method POST -Path "/admin-auth/api/mfa/totp/setup/init" -Body @{} -WithCsrf $true
Check "setup/init" ($setup.Json.manualSecret.Length -ge 16) "secretLength=$($setup.Json.manualSecret.Length)"
$secret = $setup.Json.manualSecret
$confirm = Invoke-Api -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{
    ticket = $null; code = (Get-Totp $secret)
} -WithCsrf $true
Check "confirm -> recoveryCodes=10" ($confirm.Json.recoveryCodes.Count -eq 10) "codes=$($confirm.Json.recoveryCodes.Count)"

# 4) logout + clean login -> no TOTP
Step "4. Clean login after logout -> should NOT ask TOTP"
$logout = Invoke-Api -Method POST -Path "/admin-auth/api/logout" -Body @{} -WithCsrf $true
Check "logout" ($logout.Status -eq 200) "status=$($logout.Status)"
$cleanLogin = Login $ADMIN_PASSWORD
Check "next=OK (no TOTP)" ($cleanLogin.Json.next -eq "OK") "next=$($cleanLogin.Json.next)"

# 5) logout + wrong password -> risk
Step "5. Wrong password once"
$logout2 = Invoke-Api -Method POST -Path "/admin-auth/api/logout" -Body @{} -WithCsrf $true
$wrong = Login "Wrong-Password!123"
Check "wrong password -> 401 AUTH_FAILED" ($wrong.Status -eq 401 -and $wrong.Json.code -eq "AUTH_FAILED") "status=$($wrong.Status)"

# 6) correct password after a failure -> TOTP required
Step "6. Correct password after failure -> should ask TOTP"
$riskyLogin = Login $ADMIN_PASSWORD
Check "next=SELECT_FACTOR" ($riskyLogin.Json.next -eq "SELECT_FACTOR") "next=$($riskyLogin.Json.next) factors=$($riskyLogin.Json.factors -join ',')"
$verified = Invoke-Api -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{
    ticket = $riskyLogin.Json.ticket; factorType = "TOTP"; code = (Get-Totp $secret 30)
} -WithCsrf $true
Check "TOTP verify -> OK" ($verified.Json.next -eq "OK") "next=$($verified.Json.next)"

# 7) logout + clean login again -> risk cleared
Step "7. Login after successful TOTP -> should NOT ask TOTP"
$logout3 = Invoke-Api -Method POST -Path "/admin-auth/api/logout" -Body @{} -WithCsrf $true
$cleanLogin2 = Login $ADMIN_PASSWORD
Check "next=OK (risk cleared)" ($cleanLogin2.Json.next -eq "OK") "next=$($cleanLogin2.Json.next)"

Write-Host ""
Write-Host ("RESULT: {0}" -f ($(if ($script:failed -eq 0) { "ALL PASS" } else { "$($script:failed) FAILED" })))
Write-Host ("demo account: admin@corp.example / {0}" -f $ADMIN_PASSWORD)
Write-Host ("totp secret: {0}" -f $secret)
if ($script:failed -gt 0) { exit 1 }
exit 0
