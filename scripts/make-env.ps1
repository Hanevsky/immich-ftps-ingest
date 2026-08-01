# Create a .env ready for docker compose / Portainer after certs exist.
# Usage:
#   .\scripts\generate-ftps-cert.ps1 -ServerIp 192.168.1.10
#   .\scripts\make-env.ps1 -ServerIp 192.168.1.10 -FtpUsers "camera_a7c2:Secret!!" -ImmichApiKey "..."

param(
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [string]$FtpUsers = "camera_a7c2:CHANGE_ME_TO_16_PLUS_RANDOM_CHARS",
    [string]$ImmichApiKey = "CHANGE_ME_IMMICH_API_KEY"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$cert = Join-Path $root "certs\server.crt"
$key = Join-Path $root "certs\server.key"
if (-not (Test-Path $cert) -or -not (Test-Path $key)) {
    throw "Missing certs\server.crt or certs\server.key — run generate-ftps-cert.ps1 first."
}

function Escape-DotEnv([string]$text) {
    ($text -replace '\\', '\\' -replace '"', '\"' -replace "`r`n", '\n' -replace "`n", '\n' -replace "`r", '\n')
}

$certPem = Escape-DotEnv (Get-Content -Raw $cert)
$keyPem = Escape-DotEnv (Get-Content -Raw $key)

@(
    "FTP_USERS=$FtpUsers"
    "FTP_MASQUERADE_ADDRESS=$ServerIp"
    "IMMICH_API_KEY=$ImmichApiKey"
    "FTP_CERT_PEM=`"$certPem`""
    "FTP_KEY_PEM=`"$keyPem`""
) | Set-Content -Path (Join-Path $root ".env") -Encoding utf8

Write-Host "Wrote .env — edit FTP_USERS and IMMICH_API_KEY if placeholders remain."
Write-Host "Import certs\cacert.pem into the camera, then: docker compose up -d"
