# admin-auth full API test (ASCII output, PowerShell 5.1)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/api-test.ps1
$ErrorActionPreference = "Stop"

$script:base = if ($env:AA_BASE) { $env:AA_BASE } else { "http://localhost:8080" }
$script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:results = @()
$script:pwd0 = "Admin@123456"
$script:pwd1 = "Str0ng-Passw0rd!2026"
$script:pwd2 = "An0ther-Str0ng!2026"

function Section([string]$title) {
    Write-Host ""
    Write-Host "=== $title ==="
}

function Record([string]$name, [bool]$ok, [string]$detail) {
    $script:results += [pscustomobject]@{ Name = $name; OK = $ok; Detail = $detail }
    $flag = if ($ok) { "PASS" } else { "FAIL" }
    Write-Host ("[{0}] {1} :: {2}" -f $flag, $name, $detail)
}

function Get-CsrfToken {
    Invoke-WebRequest -Uri "$($script:base)/admin-auth/api/csrf" -WebSession $script:session -UseBasicParsing | Out-Null
    $cookie = $script:session.Cookies.GetCookies([uri]$script:base) |
        Where-Object { $_.Name -eq "XSRF-TOKEN" } | Select-Object -First 1
    if (-not $cookie) { throw "XSRF-TOKEN cookie missing" }
    return [System.Uri]::UnescapeDataString($cookie.Value)
}

function Send {
    param([string]$Method, [string]$Path, $Body = $null, [bool]$WithCsrf = $false)
    $request = [System.Net.HttpWebRequest]::Create("$($script:base)$Path")
    $request.Method = $Method
    $request.Accept = "application/json"
    $request.CookieContainer = $script:session.Cookies
    $request.AllowAutoRedirect = $false
    $request.Timeout = 30000
    if ($WithCsrf) { $request.Headers.Add("X-XSRF-TOKEN", (Get-CsrfToken)) }
    if ($null -ne $Body) {
        $request.ContentType = "application/json"
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    try {
        $response = $request.GetResponse()
    } catch [System.Net.WebException] {
        $response = $_.Exception.Response
    }
    if ($null -eq $response) { return [pscustomobject]@{ Status = 0; Body = "" } }
    $status = [int]$response.StatusCode
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd()
    $reader.Close()
    $response.Close()
    return [pscustomobject]@{ Status = $status; Body = $text }
}

function Get-NoRedirect([string]$Path) {
    $request = [System.Net.HttpWebRequest]::Create("$($script:base)$Path")
    $request.AllowAutoRedirect = $false
    $request.Method = "GET"
    try {
        $response = $request.GetResponse()
    } catch [System.Net.WebException] {
        $response = $_.Exception.Response
    }
    $status = [int]$response.StatusCode
    $location = [string]$response.Headers["Location"]
    $response.Close()
    return [pscustomobject]@{ Status = $status; Location = $location }
}

function Check {
    param([string]$Name, $Response, [int]$Status, [string]$Code = $null, [scriptblock]$Predicate = $null)
    $json = $null
    try { $json = $Response.Body | ConvertFrom-Json } catch { $json = $null }
    $ok = ($Response.Status -eq $Status)
    if ($ok -and $Code) { $ok = ($null -ne $json -and $json.code -eq $Code) }
    if ($ok -and $null -ne $Predicate) { $ok = [bool](& $Predicate $json) }
    $detail = "status=$($Response.Status)"
    if ($json -and $json.code) { $detail += " code=$($json.code)" }
    if (-not $ok) { $detail += " body=$($Response.Body)" }
    Record $Name $ok $detail
    return $json
}

function Login([string]$Identifier, [string]$Password) {
    return Send -Method POST -Path "/admin-auth/api/login" -Body @{
        identityType = "EMAIL"; identifier = $Identifier; password = $Password
    } -WithCsrf $false
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

# avoid false negatives when the current step is about to roll over
function Sync-Step {
    $remain = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 30
    if ($remain -gt 25) { Start-Sleep -Seconds (31 - $remain) }
}

# ============================================================ A. anonymous
Section "A. anonymous endpoints"
Check "GET / (public)" (Send -Method GET -Path "/") 200 $null { param($j) $j.message -eq "public ok" } | Out-Null
$redirect = Get-NoRedirect "/admin/hello"
Record "GET /admin/hello (anonymous) -> 302 login" ($redirect.Status -eq 302 -and $redirect.Location -like "*/admin-auth/login*") "status=$($redirect.Status) location=$($redirect.Location)"
Check "GET /admin-auth/login (page)" (Send -Method GET -Path "/admin-auth/login") 200 $null { param($j) $true } | Out-Null
$loginPage = Send -Method GET -Path "/admin-auth/login"
Record "login page contains form" ($loginPage.Body -match "aa-login-form") "status=$($loginPage.Status)"
Check "GET /api/csrf" (Send -Method GET -Path "/admin-auth/api/csrf") 200 $null { param($j) $j.token.Length -gt 0 } | Out-Null
Check "GET /api/me (anonymous) -> 401 AUTH_FAILED" (Send -Method GET -Path "/admin-auth/api/me") 401 "AUTH_FAILED" | Out-Null
Check "POST /api/login missing password -> 400 VALIDATION_FAILED" (Send -Method POST -Path "/admin-auth/api/login" -Body @{ identityType = "EMAIL"; identifier = "admin@corp.example" }) 400 "VALIDATION_FAILED" | Out-Null
Check "POST /api/login bad enum -> 400 VALIDATION_FAILED" (Send -Method POST -Path "/admin-auth/api/login" -Body @{ identityType = "NOPE"; identifier = "a@b.c"; password = "x" }) 400 "VALIDATION_FAILED" | Out-Null
Check "POST /api/login unknown identity -> 401 AUTH_FAILED" (Login "nobody@corp.example" "WrongPass!123") 401 "AUTH_FAILED" | Out-Null
for ($i = 2; $i -le 4; $i++) { Login "nobody@corp.example" "WrongPass!123" | Out-Null }
Check "5th failure -> 423 MFA_LOCKED" (Login "nobody@corp.example" "WrongPass!123") 423 "MFA_LOCKED" | Out-Null
Check "locked identity again -> 423 MFA_LOCKED" (Login "nobody@corp.example" "WrongPass!123") 423 "MFA_LOCKED" | Out-Null
Check "POST /api/mfa/verify fake ticket -> 401 TICKET_EXPIRED" (Send -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{ ticket = "fake-ticket"; factorType = "TOTP"; code = "123456" }) 401 "TICKET_EXPIRED" | Out-Null
Check "POST /api/mfa/otp/send -> 501 NOT_IMPLEMENTED" (Send -Method POST -Path "/admin-auth/api/mfa/otp/send" -Body @{ factorType = "EMAIL_OTP" }) 501 "NOT_IMPLEMENTED" | Out-Null
$noCsrf = Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{ ticket = "x"; oldPassword = "a"; newPassword = "b" } -WithCsrf $false
$noCsrfJson = $null; try { $noCsrfJson = $noCsrf.Body | ConvertFrom-Json } catch {}
Record "POST /api/password/change-initial without CSRF -> 403" ($noCsrf.Status -eq 403) "status=$($noCsrf.Status) body=$($noCsrf.Body)"
Check "POST /api/admin/users/1/mfa/reset (anonymous) -> 401" (Send -Method POST -Path "/admin-auth/api/admin/users/1/mfa/reset" -Body @{} -WithCsrf $true) 401 "AUTH_FAILED" | Out-Null

# ============================================================ B. login + initial password
Section "B. login and initial password change"
$login = Check "POST /api/login (correct) -> CHANGE_PASSWORD" (Login "admin@corp.example" $script:pwd0) 200 $null { param($j) $j.next -eq "CHANGE_PASSWORD" -and $j.ticket.Length -gt 0 }
$ticket1 = $login.ticket
Check "change-initial wrong old -> 400 PASSWORD_MISMATCH" (Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{ ticket = $ticket1; oldPassword = "BadOld!12345"; newPassword = $script:pwd1 } -WithCsrf $true) 400 "PASSWORD_MISMATCH" | Out-Null
Check "change-initial short new -> 400 VALIDATION_FAILED" (Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{ ticket = $ticket1; oldPassword = $script:pwd0; newPassword = "short" } -WithCsrf $true) 400 "VALIDATION_FAILED" | Out-Null
$change = Check "change-initial OK -> BIND_TOTP" (Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{ ticket = $ticket1; oldPassword = $script:pwd0; newPassword = $script:pwd1 } -WithCsrf $true) 200 $null { param($j) $j.next -eq "BIND_TOTP" -and $j.ticket.Length -gt 0 }
Check "reuse consumed ticket -> 401 TICKET_EXPIRED" (Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{ ticket = $ticket1; oldPassword = $script:pwd1; newPassword = "Whatever!12345" } -WithCsrf $true) 401 "TICKET_EXPIRED" | Out-Null

# ============================================================ C. bind TOTP
Section "C. TOTP binding"
$setup = Check "POST /api/mfa/totp/setup/init" (Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/init" -Body @{ ticket = $change.ticket }) 200 $null { param($j) $j.manualSecret.Length -ge 16 -and $j.otpauthUri -like "otpauth://totp/*" -and $j.qrSvg -like "<svg*" }
$secret1 = $setup.manualSecret
Check "confirm wrong code -> 401 AUTH_FAILED" (Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{ ticket = $change.ticket; code = "000000" }) 401 "AUTH_FAILED" | Out-Null
$confirm = Check "confirm correct -> OK + 10 recovery codes" (Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{ ticket = $change.ticket; code = (Get-Totp $secret1) }) 200 $null { param($j) $j.next -eq "OK" -and $j.recoveryCodes.Count -eq 10 }
$recoveryCodes = $confirm.recoveryCodes
Check "GET /api/me (bound)" (Send -Method GET -Path "/admin-auth/api/me") 200 $null { param($j) $j.role -eq "SUPER_ADMIN" -and $j.mfaVerified -eq $true -and $j.mfaBound -eq $true } | Out-Null
Check "GET /api/security/mfa" (Send -Method GET -Path "/admin-auth/api/security/mfa") 200 $null { param($j) $j.mfaState -eq 1 -and $j.factors.Count -ge 1 -and $j.factors[0].type -eq "TOTP" -and $j.factors[0].status -eq "ACTIVE" } | Out-Null
$hello = Send -Method GET -Path "/admin/hello"
Record "GET /admin/hello (authenticated) -> 200" ($hello.Status -eq 200 -and $hello.Body -match "hello, admin") "status=$($hello.Status)"

# ============================================================ D. authenticated account APIs
Section "D. authenticated account / admin APIs"
Check "disable MFA wrong password -> 400 PASSWORD_MISMATCH" (Send -Method POST -Path "/admin-auth/api/security/mfa/disable" -Body @{ password = "Wrong!123456" } -WithCsrf $true) 400 "PASSWORD_MISMATCH" | Out-Null
Check "disable MFA under REQUIRED_ALL -> 403 MFA_REQUIRED_BY_POLICY" (Send -Method POST -Path "/admin-auth/api/security/mfa/disable" -Body @{ password = $script:pwd1 } -WithCsrf $true) 403 "MFA_REQUIRED_BY_POLICY" | Out-Null
Check "GET /api/admin/audit" (Send -Method GET -Path "/admin-auth/api/admin/audit?limit=20") 200 $null { param($j) $j.items.Count -gt 0 } | Out-Null
Check "reset MFA for unknown user -> 200" (Send -Method POST -Path "/admin-auth/api/admin/users/999/mfa/reset" -Body @{} -WithCsrf $true) 200 $null { param($j) $j.ok -eq $true } | Out-Null
Check "require value=2 -> 400 VALIDATION_FAILED" (Send -Method POST -Path "/admin-auth/api/admin/users/1/mfa/require" -Body @{ value = 2 } -WithCsrf $true) 400 "VALIDATION_FAILED" | Out-Null
Check "password change wrong old -> 400 PASSWORD_MISMATCH" (Send -Method POST -Path "/admin-auth/api/password/change" -Body @{ oldPassword = "Wrong!123456"; newPassword = $script:pwd2 } -WithCsrf $true) 400 "PASSWORD_MISMATCH" | Out-Null
$changed = Check "password change OK -> RELOGIN" (Send -Method POST -Path "/admin-auth/api/password/change" -Body @{ oldPassword = $script:pwd1; newPassword = $script:pwd2 } -WithCsrf $true) 200 $null { param($j) $j.next -eq "RELOGIN" }
Check "session invalidated after password change -> 401" (Send -Method GET -Path "/admin-auth/api/me") 401 "AUTH_FAILED" | Out-Null

# ============================================================ E. re-login with MFA
Section "E. re-login and TOTP verify"
Check "old password -> 401 AUTH_FAILED" (Login "admin@corp.example" $script:pwd1) 401 "AUTH_FAILED" | Out-Null
$login2 = Check "login with new password -> SELECT_FACTOR" (Login "admin@corp.example" $script:pwd2) 200 $null { param($j) $j.next -eq "SELECT_FACTOR" -and ($j.factors -contains "TOTP") }
Sync-Step
Check "mfa verify wrong code -> 401 AUTH_FAILED" (Send -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{ ticket = $login2.ticket; factorType = "TOTP"; code = "000000" }) 401 "AUTH_FAILED" | Out-Null
Check "mfa verify correct -> OK" (Send -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{ ticket = $login2.ticket; factorType = "TOTP"; code = (Get-Totp $secret1 30) }) 200 $null { param($j) $j.next -eq "OK" } | Out-Null
Check "GET /api/me after MFA" (Send -Method GET -Path "/admin-auth/api/me") 200 $null { param($j) $j.mfaVerified -eq $true } | Out-Null
$hello2 = Send -Method GET -Path "/admin/hello"
Record "GET /admin/hello after re-login -> 200" ($hello2.Status -eq 200) "status=$($hello2.Status)"
Check "POST /api/logout" (Send -Method POST -Path "/admin-auth/api/logout" -Body @{} -WithCsrf $true) 200 $null { param($j) $j.ok -eq $true } | Out-Null
Check "GET /api/me after logout -> 401" (Send -Method GET -Path "/admin-auth/api/me") 401 "AUTH_FAILED" | Out-Null

# ============================================================ F. recovery code
Section "F. recovery code login"
$login3 = Check "login -> SELECT_FACTOR" (Login "admin@corp.example" $script:pwd2) 200 $null { param($j) $j.next -eq "SELECT_FACTOR" }
Check "mfa recovery wrong code -> 401 AUTH_FAILED" (Send -Method POST -Path "/admin-auth/api/mfa/recovery" -Body @{ ticket = $login3.ticket; code = "AAAAA-AAAAA" }) 401 "AUTH_FAILED" | Out-Null
Check "mfa recovery correct -> OK" (Send -Method POST -Path "/admin-auth/api/mfa/recovery" -Body @{ ticket = $login3.ticket; code = $recoveryCodes[0] }) 200 $null { param($j) $j.next -eq "OK" } | Out-Null
Check "GET /api/me after recovery" (Send -Method GET -Path "/admin-auth/api/me") 200 $null { param($j) $j.mfaVerified -eq $true } | Out-Null
Check "recovery forces rebind -> factors empty" (Send -Method GET -Path "/admin-auth/api/security/mfa") 200 $null { param($j) $j.mfaState -eq 0 -and $j.factors.Count -eq 0 } | Out-Null

# ============================================================ G. re-bind after recovery
Section "G. rebind TOTP after recovery"
Check "logout" (Send -Method POST -Path "/admin-auth/api/logout" -Body @{} -WithCsrf $true) 200 | Out-Null
$login4 = Check "login -> BIND_TOTP" (Login "admin@corp.example" $script:pwd2) 200 $null { param($j) $j.next -eq "BIND_TOTP" }
$setup2 = Check "setup/init again" (Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/init" -Body @{ ticket = $login4.ticket }) 200 $null { param($j) $j.manualSecret.Length -ge 16 }
$secret2 = $setup2.manualSecret
$confirm2 = Check "confirm new TOTP -> OK" (Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{ ticket = $login4.ticket; code = (Get-Totp $secret2) }) 200 $null { param($j) $j.next -eq "OK" -and $j.recoveryCodes.Count -eq 10 }
$hello3 = Send -Method GET -Path "/admin/hello"
Record "GET /admin/hello after rebind -> 200" ($hello3.Status -eq 200) "status=$($hello3.Status)"

# ============================================================ H. admin policy last (kills own session)
Section "H. admin mfa require (last: invalidates own session)"
Check "require value=-1 -> 200 (session invalidated)" (Send -Method POST -Path "/admin-auth/api/admin/users/1/mfa/require" -Body @{ value = -1 } -WithCsrf $true) 200 $null { param($j) $j.ok -eq $true } | Out-Null
Check "session invalidated -> /api/me 401" (Send -Method GET -Path "/admin-auth/api/me") 401 "AUTH_FAILED" | Out-Null

# ============================================================ I. final login (leave a live session for data inspection)
Section "I. final login (leave session)"
$login5 = Check "login -> SELECT_FACTOR (policy restored)" (Login "admin@corp.example" $script:pwd2) 200 $null { param($j) $j.next -eq "SELECT_FACTOR" }
Sync-Step
Check "mfa verify -> OK" (Send -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{ ticket = $login5.ticket; factorType = "TOTP"; code = (Get-Totp $secret2 30) }) 200 $null { param($j) $j.next -eq "OK" } | Out-Null
Check "GET /api/me (final)" (Send -Method GET -Path "/admin-auth/api/me") 200 $null { param($j) $j.mfaVerified -eq $true } | Out-Null

# ============================================================ J. admin user lifecycle
Section "J. admin user lifecycle"
$userList = Check "GET /api/admin/users" (Send -Method GET -Path "/admin-auth/api/admin/users?page=0&size=10") 200 $null { param($j) $j.total -ge 1 -and $j.items.Count -ge 1 }
$created = Check "POST /api/admin/users" (Send -Method POST -Path "/admin-auth/api/admin/users" -Body @{
    displayName = "Viewer One"; role = "VIEWER"; email = "viewer@corp.example"
} -WithCsrf $true) 200 $null { param($j) $j.userId -gt 0 -and $j.temporaryPassword.Length -ge 12 -and $j.staffCode.Length -gt 0 }
$newUserId = $created.userId
Check "duplicate email -> 400 VALIDATION_FAILED" (Send -Method POST -Path "/admin-auth/api/admin/users" -Body @{
    displayName = "Duplicate"; role = "VIEWER"; email = "viewer@corp.example"
} -WithCsrf $true) 400 "VALIDATION_FAILED" | Out-Null
Check "GET users total=2" (Send -Method GET -Path "/admin-auth/api/admin/users?page=0&size=10") 200 $null { param($j) $j.total -eq 2 } | Out-Null
Check "POST unlock" (Send -Method POST -Path "/admin-auth/api/admin/users/$newUserId/unlock" -Body @{} -WithCsrf $true) 200 $null { param($j) $j.ok -eq $true } | Out-Null
Check "POST status disable" (Send -Method POST -Path "/admin-auth/api/admin/users/$newUserId/status" -Body @{ enabled = $false } -WithCsrf $true) 200 $null { param($j) $j.enabled -eq $false } | Out-Null
Check "POST status enable" (Send -Method POST -Path "/admin-auth/api/admin/users/$newUserId/status" -Body @{ enabled = $true } -WithCsrf $true) 200 $null { param($j) $j.enabled -eq $true } | Out-Null
Check "POST password reset" (Send -Method POST -Path "/admin-auth/api/admin/users/$newUserId/password/reset" -Body @{} -WithCsrf $true) 200 $null { param($j) $j.temporaryPassword.Length -ge 12 } | Out-Null
Check "POST mfa reset (no factors) -> 200" (Send -Method POST -Path "/admin-auth/api/admin/users/$newUserId/mfa/reset" -Body @{} -WithCsrf $true) 200 $null { param($j) $j.ok -eq $true } | Out-Null
Check "self disable -> 400" (Send -Method POST -Path "/admin-auth/api/admin/users/1/status" -Body @{ enabled = $false } -WithCsrf $true) 400 "VALIDATION_FAILED" | Out-Null

# ============================================================ summary
$failed = @($script:results | Where-Object { -not $_.OK })
Write-Host ""
Write-Host ("TOTAL={0} PASS={1} FAIL={2}" -f $script:results.Count, ($script:results.Count - $failed.Count), $failed.Count)
Write-Host ""
Write-Host "---- DEMO CREDENTIALS AFTER TEST (for UI/manual inspection) ----"
Write-Host ("account      : admin@corp.example")
Write-Host ("password     : {0}" -f $script:pwd2)
Write-Host ("totp secret  : {0}" -f $secret2)
Write-Host ("otpauth      : otpauth://totp/Admin%20Auth:admin@corp.example?secret={0}&issuer=Admin%20Auth&algorithm=SHA1&digits=6&period=30" -f $secret2)
Write-Host ("recovery     : {0}" -f (($confirm2.recoveryCodes) -join ", "))
if ($failed.Count -gt 0) {
    $failed | Format-Table -AutoSize | Out-String | Write-Host
    exit 1
}
exit 0
