[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,

    [ValidateRange(30, 3650)]
    [int]$ServerCertificateDays = 825,

    [string]$OutputDirectory = "",

    [switch]$Force
)

$ErrorActionPreference = "Stop"

$parsedIp = $null
if (-not [System.Net.IPAddress]::TryParse($ServerIp, [ref]$parsedIp) -or
    $parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "ServerIp must be the Docker host LAN IPv4 address."
}

$openssl = Get-Command openssl -ErrorAction Stop
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$certificateDirectory = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $repositoryRoot "certs"
}
else {
    [System.IO.Path]::GetFullPath($OutputDirectory)
}
New-Item -ItemType Directory -Path $certificateDirectory -Force | Out-Null

$caKey = Join-Path $certificateDirectory "ca.key"
$caCertificate = Join-Path $certificateDirectory "ca.crt"
$serverKey = Join-Path $certificateDirectory "server.key"
$serverCertificate = Join-Path $certificateDirectory "server.crt"
$cameraCertificate = Join-Path $certificateDirectory "cacert.pem"
$serverRequest = Join-Path $certificateDirectory "server.csr"
$serialFile = Join-Path $certificateDirectory "ca.srl"
$caConfig = Join-Path $certificateDirectory ".ca-openssl.cnf"
$serverConfig = Join-Path $certificateDirectory ".server-openssl.cnf"

$protectedOutputs = @(
    $caKey,
    $caCertificate,
    $serverKey,
    $serverCertificate,
    $cameraCertificate
)
$existingOutputs = @($protectedOutputs | Where-Object { Test-Path $_ })
if ($existingOutputs.Count -gt 0 -and -not $Force) {
    throw "Certificate files already exist. Refusing to overwrite them; use -Force only for an intentional certificate rotation."
}

if ($Force) {
    $protectedOutputs | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -LiteralPath $_ -Force
        }
    }
}

@"
[req]
prompt = no
distinguished_name = ca_dn
x509_extensions = v3_ca

[ca_dn]
CN = Sony FTP Local Root CA

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"@ | Set-Content -LiteralPath $caConfig -Encoding ascii

@"
[req]
prompt = no
distinguished_name = server_dn
req_extensions = v3_request

[server_dn]
CN = $ServerIp

[v3_request]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:$ServerIp

[v3_server]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:$ServerIp
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"@ | Set-Content -LiteralPath $serverConfig -Encoding ascii

function Invoke-OpenSsl {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & $openssl.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed with exit code $LASTEXITCODE."
    }
}

try {
    Invoke-OpenSsl @(
        "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256",
        "-days", "3650",
        "-keyout", $caKey,
        "-out", $caCertificate,
        "-config", $caConfig
    )

    Invoke-OpenSsl @(
        "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
        "-keyout", $serverKey,
        "-out", $serverRequest,
        "-config", $serverConfig
    )

    Invoke-OpenSsl @(
        "x509", "-req",
        "-in", $serverRequest,
        "-CA", $caCertificate,
        "-CAkey", $caKey,
        "-CAcreateserial",
        "-out", $serverCertificate,
        "-days", $ServerCertificateDays.ToString(),
        "-sha256",
        "-extfile", $serverConfig,
        "-extensions", "v3_server"
    )

    Copy-Item -LiteralPath $caCertificate -Destination $cameraCertificate -Force

    Invoke-OpenSsl @(
        "verify",
        "-CAfile", $caCertificate,
        $serverCertificate
    )
}
finally {
    @($caConfig, $serverConfig, $serverRequest, $serialFile) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -LiteralPath $_ -Force
        }
    }
}

Write-Host "FTPS certificates created in $certificateDirectory"
Write-Host "Copy $cameraCertificate to the memory-card root and import it for FTP Function."
Write-Host "Keep ca.key and server.key private; they are ignored by git."
