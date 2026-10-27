# admin-auth demo: login as SUPER_ADMIN, then create a new admin (ASCII output)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/demo-create-admin.ps1
# Requires: a running sample instance on http://localhost:8080 (or set AA_BASE)
$ErrorActionPreference = "Stop"

$script:base = if ($env:AA_BASE) { $env:AA_BASE } else { "http://localhost:8080" }
$script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$INITIAL_PASSWORD = "Admin@123456"
$ADMIN_PASSWORD = "Sup3r-Admin!2026"
$NEW_ADMIN_EMAIL = "ops.admin@corp.example"
$NEW_ADMIN_NAME = "Ops Admin"

function Step([string]$text) {
    Write-Host ""
    Write-Host "=== $text ==="
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
    $status = [int]$response.StatusCode
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd()
    $reader.Close()
    $response.Close()
    if ($status -ne 200) {
        throw "$Method $Path -> $status $text"
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
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
Write-Host "XSRF token length: $($csrf.Length)"

# 1) SUPER_ADMIN login
Step "1. Login as bootstrap SUPER_ADMIN"
$login = Send -Method POST -Path "/admin-auth/api/login" -Body @{
    identityType = "EMAIL"; identifier = "admin@corp.example"; password = $INITIAL_PASSWORD
}
Write-Host "next=$($login.next)  user=$($login.user.displayName) / $($login.user.role)"

# 2) initial password change
Step "2. Change initial password (required)"
$change = Send -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{
    ticket = $login.ticket; oldPassword = $INITIAL_PASSWORD; newPassword = $ADMIN_PASSWORD
} -WithCsrf $true
Write-Host "next=$($change.next)"

# 3) bind TOTP (this also creates the authenticated session + step-up timestamp)
Step "3. Bind TOTP"
$setup = Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/init" -Body @{ ticket = $change.ticket }
Write-Host "otpauthUri=$($setup.otpauthUri)"
Write-Host "manualSecret=$($setup.manualSecret)"
$confirm = Send -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{
    ticket = $change.ticket; code = (Get-Totp $setup.manualSecret)
}
Write-Host "next=$($confirm.next)  recoveryCodes=$($confirm.recoveryCodes.Count)"

$me = Send -Method GET -Path "/admin-auth/api/me"
Write-Host "session: $($me.displayName) / $($me.role)  mfaVerified=$($me.mfaVerified)"

# 4) create a new admin (SUPER_ADMIN + step-up)
Step "4. Create a new admin via POST /api/admin/users"
$created = Send -Method POST -Path "/admin-auth/api/admin/users" -Body @{
    displayName = $NEW_ADMIN_NAME
    role        = "ADMIN"
    email       = $NEW_ADMIN_EMAIL
} -WithCsrf $true
Write-Host "userId=$($created.userId)"
Write-Host "email(mask)=$($created.emailMask)"
Write-Host "staffCode=$($created.staffCode)"
Write-Host "temporaryPassword=$($created.temporaryPassword)"

# 5) list users
Step "5. List admins via GET /api/admin/users"
$list = Send -Method GET -Path "/admin-auth/api/admin/users?page=0&size=20"
Write-Host ("total={0}" -f $list.total)
$list.items | ForEach-Object {
    $masks = ($_.identities | ForEach-Object { "$($_.type):$($_.mask)" }) -join ", "
    Write-Host ("- id={0} {1} role={2} status={3} mfaState={4} mustChange={5} [{6}]" -f `
        $_.id, $_.displayName, $_.role, $_.status, $_.mfaState, $_.mustChangePassword, $masks)
}

# 6) first login as the new admin (new cookie session)
Step "6. First login as the new admin"
$script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$newLogin = Send -Method POST -Path "/admin-auth/api/login" -Body @{
    identityType = "EMAIL"; identifier = $NEW_ADMIN_EMAIL; password = $created.temporaryPassword
}
Write-Host "next=$($newLogin.next)  user=$($newLogin.user.displayName) / $($newLogin.user.role)  mustChange=$($newLogin.user.mustChangePassword)"

Write-Host ""
Write-Host "---- DEMO SUMMARY ----"
Write-Host ("superadmin : admin@corp.example / {0}" -f $ADMIN_PASSWORD)
Write-Host ("new admin  : {0} / {1} (must change on first login)" -f $NEW_ADMIN_EMAIL, $created.temporaryPassword)
Write-Host ("staffCode  : {0}" -f $created.staffCode)
