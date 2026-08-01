# Immich FTPS Ingest

Add-only **FTPES** ingest for cameras into [Immich](https://immich.app).

```text
Camera ──FTPS (upload only)──► staging volume ──► immich-cli ──► Immich API
```

No Immich library/DB mounts. Compromised FTP credentials can only upload allowed
media into staging (not list/delete/overwrite). Restrict the camera IP on the firewall.

## Quick start

**Required:** Docker Compose v2, running Immich (`immich_default` network), OpenSSL.

```bash
# 1) Certs for your Docker host LAN IP
./scripts/generate-ftps-cert.sh 192.168.1.10          # Windows: .\scripts\generate-ftps-cert.ps1

# 2) .env with credentials + PEM certs
./scripts/make-env.sh 192.168.1.10 'camera_a7c2:LongRandomSecret!!' 'your-immich-api-key'
# Windows: .\scripts\make-env.ps1 -ServerIp 192.168.1.10 -FtpUsers '...' -ImmichApiKey '...'

# 3) Start (Immich must already be up)
docker compose up -d
```

Import `certs/cacert.pem` on the camera. FTP: host = LAN IP, port `2121`, FTPES On, Passive On.

### Portainer

Stacks → Add stack → paste [`docker-compose.yml`](docker-compose.yml) → set env:

| Variable | Example |
|----------|---------|
| `FTP_USERS` | `camera_a7c2:LongRandomSecret!!` |
| `FTP_MASQUERADE_ADDRESS` | `192.168.1.10` |
| `IMMICH_API_KEY` | Immich key with `asset.upload` |
| `FTP_CERT_PEM` | full `certs/server.crt` |
| `FTP_KEY_PEM` | full `certs/server.key` |

Defaults (usually leave alone): `IMMICH_HOST=http://immich-server:2283`,
`IMMICH_DOCKER_NETWORK=immich_default`, `IMMICH_ALLOW_HTTP=true`.

### Add next to Immich compose

Copy the `sony-ftp` / `immich-importer` services from `docker-compose.yml` into your
[Immich compose](https://github.com/immich-app/immich/releases/latest/download/docker-compose.yml).
Set `IMMICH_HOST=http://immich-server:2283` and drop the external `immich` network
(use the default project network).

## Camera (Sony FTPES)

| Setting | Value |
|---------|-------|
| Host | `FTP_MASQUERADE_ADDRESS` |
| Port | `2121` |
| Secure Protocol | On |
| Root Certificate Error | Does Not Connect |
| User / Password | from `FTP_USERS` |
| Passive Mode | On |

## Operations

```bash
docker compose logs -f
docker compose down          # keeps volumes
# docker compose down -v   # deletes staging — avoid
```

Local image build (developers):  
`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`

## Security (short)

- FTPS required; destructive FTP commands blocked; collisions get `_1`, `_2`, …
- Staging is never auto-deleted after import
- New uploads rejected with `452` when free space is low (~1 GB default)

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Cert rejected | Import `cacert.pem`; IP in cert SAN |
| Login rejected | Secure Protocol = On |
| Passive hang | Ports `30000–30009`, masquerade IP, firewall |
| Importer unhealthy | Immich network / `IMMICH_HOST` |

Immich CLI: https://docs.immich.app/features/command-line-interface/
