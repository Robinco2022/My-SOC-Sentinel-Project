$ErrorActionPreference = "Stop"

$script:Root = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$script:Listener = [System.Net.HttpListener]::new()
$script:Prefix = "http://127.0.0.1:8765/"
$script:MaxUploadBytes = 50MB
$script:AllowedExtensions = @(
    ".7z", ".bat", ".bin", ".c", ".cfg", ".conf", ".cc", ".cmd", ".cpp",
    ".cs", ".csv", ".dart", ".dll", ".doc", ".docx", ".exe", ".gif",
    ".go", ".gz", ".h", ".html", ".ini", ".jar", ".java", ".jpg",
    ".jpeg", ".js", ".json", ".jsx", ".kt", ".log", ".m", ".md", ".mm",
    ".pdf", ".pem", ".php", ".png", ".ps1", ".py", ".rb", ".rs", ".sh",
    ".sql", ".svg", ".swift", ".tf", ".toml", ".ts", ".tsx", ".txt",
    ".wav", ".webp", ".xml", ".yaml", ".yml", ".zip"
)

function Write-JsonResponse {
    param(
        [Parameter(Mandatory = $true)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory = $true)][int]$StatusCode,
        [Parameter(Mandatory = $true)]$Value
    )
    $json = ConvertTo-Json -InputObject $Value -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json; charset=utf-8"
    $Response.ContentLength64 = $bytes.Length
    $Response.Headers["Cache-Control"] = "no-store"
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.Close()
}

function Test-PrivateIpv4 {
    param([Parameter(Mandatory = $true)][string]$Address)
    if ($Address -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
        return $false
    }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        return $false
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    if ($parsed.ToString() -ne $Address) {
        return $false
    }
    $octets = $parsed.GetAddressBytes()
    if (($Address.Split(".") | Where-Object { [int]$_ -gt 255 -or [int]$_ -lt 0 }).Count -gt 0) {
        return $false
    }
    if ($octets[0] -eq 127 -or $octets[0] -eq 10) {
        return $true
    }
    if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) {
        return $true
    }
    return ($octets[0] -eq 192 -and $octets[1] -eq 168)
}

function Get-RequestJson {
    param(
        [Parameter(Mandatory = $true)][System.Net.HttpListenerRequest]$Request,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )
    if ($Request.ContentLength64 -gt $MaximumBytes) {
        throw [System.ArgumentException]::new("Request body is too large.")
    }
    $reader = [System.IO.StreamReader]::new(
        $Request.InputStream,
        $Request.ContentEncoding,
        $false,
        1024,
        $true
    )
    try {
        $builder = [System.Text.StringBuilder]::new()
        $buffer = New-Object char[] 4096
        $characterCount = 0
        while (($read = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $characterCount += $read
            if ($characterCount -gt $MaximumBytes) {
                throw [System.ArgumentException]::new("Request body is too large.")
            }
            [void]$builder.Append($buffer, 0, $read)
        }
        $body = $builder.ToString()
    }
    finally {
        $reader.Dispose()
    }
    if ([System.Text.Encoding]::UTF8.GetByteCount($body) -gt $MaximumBytes) {
        throw [System.ArgumentException]::new("Request body is too large.")
    }
    return ConvertFrom-Json -InputObject $body -ErrorAction Stop
}

function Get-DefenderExecutable {
    $basePath = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
    if (Test-Path -LiteralPath $basePath -PathType Leaf) {
        return $basePath
    }
    $platformRoot = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform"
    if (Test-Path -LiteralPath $platformRoot -PathType Container) {
        $candidates = Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending
        foreach ($candidate in $candidates) {
            $executable = Join-Path $candidate.FullName "MpCmdRun.exe"
            if (Test-Path -LiteralPath $executable -PathType Leaf) {
                return $executable
            }
        }
    }
    return $null
}

function Get-HostNeighbors {
    $command = Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue
    if (-not $command) {
        throw [System.InvalidOperationException]::new("IPv4 neighbor discovery is only available on Windows with the NetTCPIP module.")
    }
    $hosts = @(
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -and
                (Test-PrivateIpv4 -Address ([string]$_.IPAddress)) -and
                $_.LinkLayerAddress -notmatch '^(?:00(?:-00){5}|FF(?:-FF){5})$' -and
                [string]$_.State -in @("Reachable", "Stale", "Delay", "Probe", "Permanent")
            } |
            Group-Object -Property IPAddress |
            ForEach-Object {
                $neighbor = $_.Group | Select-Object -First 1
                [ordered]@{
                    ip = [string]$neighbor.IPAddress
                    mac = if ($neighbor.LinkLayerAddress -and $neighbor.LinkLayerAddress -notmatch "^00(-00){5}$") {
                        [string]$neighbor.LinkLayerAddress
                    }
                    else {
                        $null
                    }
                    state = [string]$neighbor.State
                }
            } |
            Sort-Object -Property ip
    )
    return @{ hosts = @($hosts); source = "Windows IPv4 neighbor cache" }
}

function Get-DefenderStatus {
    $statusCommand = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $statusCommand) {
        return @{
            available = $false
            realtimeProtection = $false
            signatureAgeDays = $null
            message = "Microsoft Defender status cmdlet is unavailable."
        }
    }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $age = $null
        if ($status.AntivirusSignatureLastUpdated) {
            $age = [Math]::Max(
                0,
                [Math]::Floor(((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalDays)
            )
        }
        return @{
            available = $true
            realtimeProtection = [bool]$status.RealTimeProtectionEnabled
            signatureAgeDays = $age
            message = "Microsoft Defender is available."
        }
    }
    catch {
        return @{
            available = $false
            realtimeProtection = $false
            signatureAgeDays = $null
            message = "Microsoft Defender status could not be read."
        }
    }
}

function Invoke-DefenderFileScan {
    param([Parameter(Mandatory = $true)][System.Net.HttpListenerContext]$Context)

    if ($Context.Request.ContentLength64 -gt $script:MaxUploadBytes) {
        Write-JsonResponse $Context.Response 413 @{ error = "File is larger than the 50 MB scan limit." }
        return
    }
    $executable = Get-DefenderExecutable
    if (-not $executable) {
        Write-JsonResponse $Context.Response 503 @{ error = "Microsoft Defender MpCmdRun.exe was not found on this computer." }
        return
    }

    $extension = [string]$Context.Request.Headers["X-File-Extension"]
    if ($extension -notmatch '^\.[a-zA-Z0-9]{1,8}$') {
        $extension = ".bin"
    }
    else {
        $extension = $extension.ToLowerInvariant()
        if ($extension -notin $script:AllowedExtensions) {
            $extension = ".bin"
        }
    }

    $temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-scan-" + [guid]::NewGuid().ToString("N"))
    $temporaryFile = Join-Path $temporaryDirectory ("sample" + $extension)
    $cleanupSucceeded = $false
    $process = $null
    try {
        [System.IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
        $fileStream = [System.IO.File]::Open(
            $temporaryFile,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $buffer = New-Object byte[] 81920
            $totalBytes = 0
            while (($read = $Context.Request.InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totalBytes += $read
                if ($totalBytes -gt $script:MaxUploadBytes) {
                    throw [System.ArgumentException]::new("File is larger than the 50 MB scan limit.")
                }
                $fileStream.Write($buffer, 0, $read)
            }
        }
        finally {
            $fileStream.Dispose()
        }
        if ($totalBytes -eq 0) {
            Write-JsonResponse $Context.Response 400 @{ error = "The selected file is empty." }
            return
        }

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $executable
        $startInfo.Arguments = '-Scan -ScanType 3 -File "{0}" -DisableRemediation' -f $temporaryFile
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw [System.InvalidOperationException]::new("Microsoft Defender could not be started.")
        }
        $finished = $process.WaitForExit(120000)
        if (-not $finished) {
            $process.Kill()
            $process.WaitForExit()
            Write-JsonResponse $Context.Response 504 @{ error = "The Defender scan exceeded the two-minute limit. Check Windows Security." }
            return
        }

        $detectionCount = 0
        $detectionCommand = Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($detectionCommand) {
            $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
            foreach ($detection in $detections) {
                foreach ($resource in @($detection.Resources)) {
                    if ([string]$resource -like "*$temporaryFile*") {
                        $detectionCount++
                    }
                }
            }
        }

        if ($detectionCount -gt 0) {
            $verdict = "detection"
            $message = "Defender reported a detection for this temporary scan file. Review Windows Security > Protection history."
        }
        elseif ($process.ExitCode -eq 0) {
            $verdict = "completed"
            $message = "Defender completed the scan without reporting a command error. Check Protection history; a completed scan is not a guarantee that the file is safe."
        }
        else {
            $verdict = "indeterminate"
            $message = "Defender returned exit code $($process.ExitCode). The result is inconclusive; check Windows Security > Protection history."
        }
        Write-JsonResponse $Context.Response 200 @{
            verdict = $verdict
            exitCode = $process.ExitCode
            detections = $detectionCount
            message = $message
        }
    }
    finally {
        if ($process) {
            $process.Dispose()
        }
        try {
            if (Test-Path -LiteralPath $temporaryFile) {
                Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $temporaryDirectory) {
                Remove-Item -LiteralPath $temporaryDirectory -Force -ErrorAction Stop
            }
            $cleanupSucceeded = $true
        }
        catch {
            Write-Warning "Sentinel could not remove a temporary antivirus scan file. Inspect the operating-system temporary directory."
        }
        if (-not $cleanupSucceeded) {
            Write-Warning "Manual cleanup may be required for a Sentinel antivirus temporary directory."
        }
    }
}

function New-WebCheck {
    param([Parameter(Mandatory = $true)][System.Net.HttpListenerRequest]$Request)
    if ($Request.ContentType -notlike "application/json*") {
        throw [System.ArgumentException]::new("Expected a JSON request.")
    }
    $body = Get-RequestJson -Request $Request -MaximumBytes 8192
    $uri = $null
    if (-not [uri]::TryCreate([string]$body.url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw [System.ArgumentException]::new("Enter a valid absolute private IPv4 URL.")
    }
    if ($uri.Scheme -notin @("http", "https") -or
        [string]$body.url -notmatch '^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/$' -or
        $uri.UserInfo -or
        $uri.AbsolutePath -ne "/" -or
        $uri.Query -or
        $uri.Fragment -or
        -not (Test-PrivateIpv4 -Address $uri.Host)) {
        throw [System.ArgumentException]::new("Only an HTTP or HTTPS root URL on an RFC1918/loopback IPv4 address is allowed.")
    }

    $webRequest = [System.Net.HttpWebRequest]::Create($uri)
    $webRequest.Proxy = $null
    $webRequest.AllowAutoRedirect = $false
    $webRequest.Method = "HEAD"
    $webRequest.Timeout = 8000
    $webRequest.ReadWriteTimeout = 8000
    $webRequest.KeepAlive = $false
    $response = $null
    try {
        $response = [System.Net.HttpWebResponse]$webRequest.GetResponse()
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response -is [System.Net.HttpWebResponse]) {
            $response = [System.Net.HttpWebResponse]$_.Exception.Response
        }
        else {
            throw [System.InvalidOperationException]::new("The private service could not be reached. Check its address and TLS certificate.")
        }
    }

    try {
        $headers = $response.Headers
        $checks = New-Object System.Collections.Generic.List[object]
        $checks.Add(@{
            severity = if ($uri.Scheme -eq "https") { "pass" } else { "warning" }
            title = "Transport encryption"
            detail = if ($uri.Scheme -eq "https") {
                "Connected with HTTPS; the certificate was validated by the local operating system."
            }
            else {
                "This service uses unencrypted HTTP. Prefer HTTPS when credentials or sensitive data are involved."
            }
        })
        if ($headers["Content-Security-Policy"]) {
            $checks.Add(@{ severity = "pass"; title = "Content Security Policy"; detail = "A Content-Security-Policy header is present." })
        }
        else {
            $checks.Add(@{ severity = "warning"; title = "Content Security Policy"; detail = "No Content-Security-Policy header was observed on this response." })
        }
        if ($uri.Scheme -eq "https") {
            if ($headers["Strict-Transport-Security"]) {
                $checks.Add(@{ severity = "pass"; title = "HSTS"; detail = "A Strict-Transport-Security header is present." })
            }
            else {
                $checks.Add(@{ severity = "warning"; title = "HSTS"; detail = "Consider Strict-Transport-Security for HTTPS services." })
            }
        }
        if ($headers["X-Content-Type-Options"] -match "(?i)\bnosniff\b") {
            $checks.Add(@{ severity = "pass"; title = "MIME sniffing protection"; detail = "X-Content-Type-Options: nosniff is present." })
        }
        else {
            $checks.Add(@{ severity = "warning"; title = "MIME sniffing protection"; detail = "Consider X-Content-Type-Options: nosniff." })
        }
        if ($headers["X-Frame-Options"] -or $headers["Content-Security-Policy"] -match "(?i)frame-ancestors") {
            $checks.Add(@{ severity = "pass"; title = "Clickjacking protection"; detail = "Frame protection is present." })
        }
        else {
            $checks.Add(@{ severity = "warning"; title = "Clickjacking protection"; detail = "No X-Frame-Options or CSP frame-ancestors directive was observed." })
        }
        if ($headers["Referrer-Policy"]) {
            $checks.Add(@{ severity = "pass"; title = "Referrer policy"; detail = "A Referrer-Policy header is present." })
        }
        else {
            $checks.Add(@{ severity = "info"; title = "Referrer policy"; detail = "Consider an explicit Referrer-Policy." })
        }
        $cookies = @($headers.GetValues("Set-Cookie"))
        if ($cookies.Count -gt 0) {
            $missingSecure = @($cookies | Where-Object { $_ -notmatch "(?i)(?:^|;)\s*Secure(?:;|$)" }).Count
            $missingHttpOnly = @($cookies | Where-Object { $_ -notmatch "(?i)(?:^|;)\s*HttpOnly(?:;|$)" }).Count
            $details = "$($cookies.Count) cookie(s) set. "
            if ($missingSecure -gt 0 -and $uri.Scheme -eq "https") {
                $details += "$missingSecure missing Secure. "
            }
            if ($missingHttpOnly -gt 0) {
                $details += "$missingHttpOnly missing HttpOnly. "
            }
            if ($missingSecure -eq 0 -and $missingHttpOnly -eq 0) {
                $checks.Add(@{ severity = "pass"; title = "Cookie flags"; detail = "Observed cookies set Secure/HttpOnly flags as applicable." })
            }
            else {
                $checks.Add(@{ severity = "warning"; title = "Cookie flags"; detail = $details.Trim() })
            }
        }
        else {
            $checks.Add(@{ severity = "info"; title = "Cookie flags"; detail = "No Set-Cookie header was observed on this response." })
        }
        if ($headers["Server"] -or $headers["X-Powered-By"]) {
            $checks.Add(@{ severity = "info"; title = "Server identification"; detail = "A server-identification header is present. Review whether version details should be minimized." })
        }
        return @{
            url = $uri.GetLeftPart([System.UriPartial]::Authority) + "/"
            statusCode = [int]$response.StatusCode
            statusText = [string]$response.StatusDescription
            checks = @($checks.ToArray())
            note = "One read-only HEAD request was made. This is not a penetration test."
        }
    }
    finally {
        $response.Close()
    }
}

function Test-ApiRequest {
    param([Parameter(Mandatory = $true)][System.Net.HttpListenerContext]$Context)
    if ($Context.Request.Url.Host -notmatch '^127\.0\.0\.1(?::8765)?$') {
        Write-JsonResponse $Context.Response 403 @{ error = "Sentinel accepts local-machine requests only." }
        return $false
    }
    $origin = $Context.Request.Headers["Origin"]
    if ($origin) {
        $expectedOrigin = "http://127.0.0.1:8765"
        if ($origin -ne $expectedOrigin) {
            Write-JsonResponse $Context.Response 403 @{ error = "Cross-origin requests are not allowed." }
            return $false
        }
    }
    return $true
}

function Invoke-Request {
    param([Parameter(Mandatory = $true)][System.Net.HttpListenerContext]$Context)
    $request = $Context.Request
    $response = $Context.Response
    $response.Headers["X-Content-Type-Options"] = "nosniff"
    $response.Headers["Referrer-Policy"] = "no-referrer"

    if ($request.Url.AbsolutePath.StartsWith("/api/")) {
        if (-not (Test-ApiRequest -Context $Context)) {
            return
        }
        switch ($request.Url.AbsolutePath) {
            "/api/hosts" {
                if ($request.HttpMethod -ne "GET") {
                    Write-JsonResponse $response 405 @{ error = "Method not allowed." }
                    return
                }
                try {
                    Write-JsonResponse $response 200 (Get-HostNeighbors)
                }
                catch {
                    Write-JsonResponse $response 503 @{ error = $_.Exception.Message }
                }
                return
            }
            "/api/defender/status" {
                if ($request.HttpMethod -ne "GET") {
                    Write-JsonResponse $response 405 @{ error = "Method not allowed." }
                    return
                }
                Write-JsonResponse $response 200 (Get-DefenderStatus)
                return
            }
            "/api/defender/scan" {
                if ($request.HttpMethod -ne "POST" -or $request.ContentType -notlike "application/octet-stream*") {
                    Write-JsonResponse $response 415 @{ error = "Expected a binary POST request." }
                    return
                }
                try {
                    Invoke-DefenderFileScan -Context $Context
                }
                catch [System.ArgumentException] {
                    Write-JsonResponse $response 400 @{ error = $_.Exception.Message }
                }
                catch {
                    Write-Warning "A local Defender file scan failed."
                    if (-not $response.OutputStream.CanWrite) {
                        return
                    }
                    Write-JsonResponse $response 500 @{ error = "The Defender file scan failed. Check the local Sentinel terminal and Windows Security." }
                }
                return
            }
            "/api/web-check" {
                if ($request.HttpMethod -ne "POST") {
                    Write-JsonResponse $response 405 @{ error = "Method not allowed." }
                    return
                }
                try {
                    $result = New-WebCheck -Request $request
                    Write-JsonResponse $response 200 $result
                }
                catch [System.ArgumentException] {
                    Write-JsonResponse $response 400 @{ error = $_.Exception.Message }
                }
                catch [System.InvalidOperationException] {
                    Write-JsonResponse $response 502 @{ error = $_.Exception.Message }
                }
                catch {
                    Write-Warning "A local private-service header check failed."
                    Write-JsonResponse $response 502 @{ error = "The private service could not be checked. Verify its address and certificate." }
                }
                return
            }
            default {
                Write-JsonResponse $response 404 @{ error = "Local API endpoint not found." }
                return
            }
        }
    }

    if ($request.HttpMethod -notin @("GET", "HEAD")) {
        $response.StatusCode = 405
        $response.Close()
        return
    }
    if ($request.Url.AbsolutePath -notin @("/", "/index.html", "/styles.css", "/app.js")) {
        $response.StatusCode = 404
        $response.Close()
        return
    }
    $fileName = if ($request.Url.AbsolutePath -eq "/") { "index.html" } else { $request.Url.AbsolutePath.TrimStart("/") }
    $filePath = Join-Path $script:Root $fileName
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        $response.StatusCode = 404
        $response.Close()
        return
    }
    $response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    $response.Headers["Cache-Control"] = "no-store"
    $response.ContentType = switch ([System.IO.Path]::GetExtension($filePath).ToLowerInvariant()) {
        ".html" { "text/html; charset=utf-8" }
        ".css" { "text/css; charset=utf-8" }
        ".js" { "text/javascript; charset=utf-8" }
    }
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    $response.ContentLength64 = $bytes.Length
    if ($request.HttpMethod -eq "GET") {
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
    }
    $response.Close()
}

try {
    $script:Listener.Prefixes.Add($script:Prefix)
    $script:Listener.Start()
}
catch {
    Write-Error "Could not start Sentinel at $script:Prefix. Stop the other Sentinel server or select a free port. $($_.Exception.Message)"
    exit 1
}

Write-Host "Sentinel is ready at $script:Prefix"
Write-Host "Host discovery is passive. Antivirus uses Windows Defender. Web checks accept RFC1918/loopback IPv4 only."
Write-Host "Press Ctrl+C to stop Sentinel."

try {
    while ($script:Listener.IsListening) {
        $context = $script:Listener.GetContext()
        try {
            Invoke-Request -Context $context
        }
        catch {
            Write-Warning "A local Sentinel request failed."
            try {
                if (-not $context.Response.OutputStream.CanWrite) {
                    continue
                }
                if ($context.Request.Url.AbsolutePath.StartsWith("/api/")) {
                    Write-JsonResponse $context.Response 500 @{ error = "The local request failed." }
                }
                else {
                    $context.Response.StatusCode = 500
                    $context.Response.Close()
                }
            }
            catch {
                Write-Warning "Could not complete a local HTTP response."
            }
        }
    }
}
finally {
    $script:Listener.Stop()
    $script:Listener.Close()
}
