# admin-auth acceptance script (ASCII only, PowerShell 5.1 compatible)
# Usage: powershell -ExecutionPolicy Bypass -File scripts/acceptance.ps1
$ErrorActionPreference = "Stop"

$script:base = "http://localhost:8080"
$script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:results = @()

function Record([string]$name, [bool]$ok, [string]$detail) {
    $script:results += [pscustomobject]@{ Step = $name; OK = $ok; Detail = $detail }
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

function Invoke-Api {
    param([string]$Method, [string]$Path, $Body = $null)
    $headers = @{ "Accept" = "application/json" }
    if ($Method -ne "GET") { $headers["X-XSRF-TOKEN"] = Get-CsrfToken }
    $params = @{
        Uri         = "$($script:base)$Path"
        Method      = $Method
        WebSession  = $script:session
        UseBasicParsing = $true
        Headers     = $headers
    }
    if ($null -ne $Body) {
        $params["ContentType"] = "application/json"
        $params["Body"] = ($Body | ConvertTo-Json -Compress)
    }
    return Invoke-WebRequest @params
}

function ConvertFrom-Base32([string]$text) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $clean = $text.Trim().TrimEnd('=').Replace(" ", "").ToUpperInvariant()
    $buffer = 0
    $bits = 0
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($ch in $clean.ToCharArray()) {
        $idx = $alphabet.IndexOf($ch)
        if ($idx -lt 0) { throw "Invalid Base32 character: $ch" }
        $buffer = ($buffer -shl 5) -bor $idx
        $bits += 5
        if ($bits -ge 8) {
            $bits -= 8
            $bytes.Add([byte](($buffer -shr $bits) -band 0xFF))
        }
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
    $code = $binary % [int][Math]::Pow(10, 6)
    return $code.ToString("000000")
}

# ---------- A. protected page redirects to login ----------
$redirectStatus = 0
$redirectLocation = ""
$webRequest = [System.Net.HttpWebRequest]::Create("$($script:base)/admin/hello")
$webRequest.AllowAutoRedirect = $false
$webRequest.Method = "GET"
try {
    $webResponse = $webRequest.GetResponse()
} catch [System.Net.WebException] {
    $webResponse = $_.Exception.Response
}
if ($null -ne $webResponse) {
    $redirectStatus = [int]$webResponse.StatusCode
    $redirectLocation = [string]$webResponse.Headers["Location"]
    $webResponse.Close()
}
Record "A.protected-redirect" ($redirectStatus -eq 302 -and $redirectLocation -like "*/admin-auth/login*") `
    "$redirectStatus -> $redirectLocation"

# ---------- B. login page ----------
$loginPage = Invoke-WebRequest -Uri "$($script:base)/admin-auth/login" -UseBasicParsing
Record "B.login-page" ($loginPage.StatusCode -eq 200 -and $loginPage.Content -match "aa-login-form") `
    "status=$($loginPage.StatusCode)"

# ---------- C. CSRF ----------
$csrfToken = Get-CsrfToken
Record "C.csrf" ($csrfToken.Length -gt 0) "tokenLength=$($csrfToken.Length)"

# ---------- D. initial login ----------
$login = (Invoke-Api -Method POST -Path "/admin-auth/api/login" -Body @{
    identityType = "EMAIL"; identifier = "admin@corp.example"; password = "Admin@123456"
}).Content | ConvertFrom-Json
Record "D.login" ($login.next -eq "CHANGE_PASSWORD") "next=$($login.next) ticket=$($login.ticket.Length) chars"

# ---------- E. initial password change ----------
$change = (Invoke-Api -Method POST -Path "/admin-auth/api/password/change-initial" -Body @{
    ticket = $login.ticket; oldPassword = "Admin@123456"; newPassword = "Str0ng-Passw0rd!2026"
}).Content | ConvertFrom-Json
Record "E.password-change" ($change.next -eq "BIND_TOTP") "next=$($change.next)"

# ---------- F. TOTP setup init ----------
$setup = (Invoke-Api -Method POST -Path "/admin-auth/api/mfa/totp/setup/init" -Body @{
    ticket = $change.ticket
}).Content | ConvertFrom-Json
$secret = $setup.manualSecret
Record "F.totp-setup-init" ($secret.Length -gt 0 -and $setup.qrSvg.StartsWith("<svg")) `
    "secretLength=$($secret.Length) uri=$($setup.otpauthUri.Substring(0, [Math]::Min(40, $setup.otpauthUri.Length)))"

# ---------- G. TOTP confirm (creates session) ----------
$confirmCode = Get-Totp $secret
$confirm = (Invoke-Api -Method POST -Path "/admin-auth/api/mfa/totp/setup/confirm" -Body @{
    ticket = $change.ticket; code = $confirmCode
}).Content | ConvertFrom-Json
Record "G.totp-confirm" ($confirm.next -eq "OK" -and $confirm.recoveryCodes.Count -eq 10) `
    "next=$($confirm.next) recoveryCodes=$($confirm.recoveryCodes.Count)"

# ---------- H. /api/me ----------
$me = (Invoke-Api -Method GET -Path "/admin-auth/api/me").Content | ConvertFrom-Json
Record "H.api-me" ($me.role -eq "SUPER_ADMIN" -and $me.mfaVerified -eq $true) `
    "role=$($me.role) mfaVerified=$($me.mfaVerified) version=$($me.version)"

# ---------- I. protected API 200 ----------
$hello = Invoke-WebRequest -Uri "$($script:base)/admin/hello" -WebSession $script:session -UseBasicParsing
Record "I.protected-200" ($hello.StatusCode -eq 200 -and $hello.Content -match "hello, admin") `
    "status=$($hello.StatusCode) body=$($hello.Content)"

# ---------- J. logout ----------
$logout = Invoke-Api -Method POST -Path "/admin-auth/api/logout" -Body @{}
Record "J.logout" ($logout.StatusCode -eq 200) "status=$($logout.StatusCode)"

# ---------- K. re-login requires MFA ----------
$login2 = (Invoke-Api -Method POST -Path "/admin-auth/api/login" -Body @{
    identityType = "EMAIL"; identifier = "admin@corp.example"; password = "Str0ng-Passw0rd!2026"
}).Content | ConvertFrom-Json
Record "K.relogin" ($login2.next -eq "SELECT_FACTOR") "next=$($login2.next) factors=$($login2.factors -join ',')"

# ---------- L. MFA verify (next time step to avoid replay) ----------
$verifyCode = Get-Totp $secret 30
$verified = (Invoke-Api -Method POST -Path "/admin-auth/api/mfa/verify" -Body @{
    ticket = $login2.ticket; factorType = "TOTP"; code = $verifyCode
}).Content | ConvertFrom-Json
Record "L.mfa-verify" ($verified.next -eq "OK") "next=$($verified.next)"

# ---------- M. protected API after re-login ----------
$hello2 = Invoke-WebRequest -Uri "$($script:base)/admin/hello" -WebSession $script:session -UseBasicParsing
Record "M.protected-after-relogin" ($hello2.StatusCode -eq 200) "status=$($hello2.StatusCode)"

# ---------- summary ----------
$failed = @($script:results | Where-Object { -not $_.OK })
Write-Host ""
Write-Host ("TOTAL={0} PASS={1} FAIL={2}" -f $script:results.Count, ($script:results.Count - $failed.Count), $failed.Count)
if ($failed.Count -gt 0) {
    $failed | Format-Table -AutoSize | Out-String | Write-Host
    exit 1
}
exit 0
