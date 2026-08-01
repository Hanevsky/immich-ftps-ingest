# Immich FTPS Ingest (Sony / Camera)

Add-only **FTPES** ingest for cameras (Sony a7C II and similar) into [Immich](https://immich.app).

The camera uploads to an isolated staging volume. A separate importer pushes finished files into Immich via the official CLI. Neither service mounts Immich storage or PostgreSQL.

```text
Camera ──FTPS (upload only)──► staging volume
                                    │
                                    └──► immich-cli (read-only) ──► Immich API
```

## Why this exists

| Goal | Behavior |
|------|----------|
| Protect Immich library | No direct library/DB mounts; importer is read-only on staging |
| No overwrite / delete via FTP | Destructive FTP commands blocked; collisions get `_1`, `_2`, … |
| Safe for incomplete transfers | Hidden `.upload-*.part` until atomic publish |
| Simple deploy | A few env vars — same idea as companion Immich sidecars |

Compromised FTP credentials can only **upload** allowed media into staging (and fill disk). They cannot list, download, rename, or delete existing files. Restrict camera IP on the firewall.

> This is **not** a backup of Immich. Host admins can always read Docker volumes and container env.

## Requirements

- Docker Engine + Compose v2
- Running Immich (importer joins its Docker network, default `immich_default`)
- OpenSSL (FTPS certificate)
- Stable LAN IPs for the Docker host and camera

## Deploy options

### Publish images to GitHub (GHCR) — recommended

Build once in CI, pull on every host (no local `docker compose build`):

1. Push this repo to GitHub.
2. Actions → **Publish images** runs on `main`/`master` (or tag `v1.0.0`).
3. Images appear at:
   - `ghcr.io/<your-user>/immich-ftps-server`
   - `ghcr.io/<your-user>/immich-ftps-importer`
4. If the package is private: Package settings → link the repo / grant pull, or make it public.
5. Set in `.env`:

```dotenv
GHCR_OWNER=your-github-user
IMAGE_TAG=latest
```

```bash
docker compose pull
docker compose up -d
```

Local build without GHCR (development):

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

### A) Sidecar next to an existing Immich stack (default)

Use the root [`docker-compose.yml`](docker-compose.yml). The importer joins Immich’s
Docker network (`immich_default` by default):

```bash
cp .env.example .env
# set GHCR_OWNER, FTP_USERS, FTP_MASQUERADE_ADDRESS, IMMICH_HOST, IMMICH_API_KEY, …
docker compose pull
docker compose up -d
```

### B) Same Compose project as Immich

See [`examples/docker-compose.with-immich.yml`](examples/docker-compose.with-immich.yml)
for a full Immich + FTPS example (same pattern as adding `immich-sftp` beside
`immich-server`).

Prefer merging only the `sony-ftp` / `immich-importer` service blocks into the
[official Immich release compose](https://github.com/immich-app/immich/releases/latest/download/docker-compose.yml).
When co-located, set:

```dotenv
IMMICH_HOST=http://immich-server:2283
```

No `IMMICH_DOCKER_NETWORK` is required — importer shares Immich’s default network.
Compose resolves `../certs` and `../immich-certs` relative to the example file
(back to the repo root), so plain `-f` works:

```bash
docker compose -f examples/docker-compose.with-immich.yml --env-file .env pull
docker compose -f examples/docker-compose.with-immich.yml --env-file .env up -d
```

## Quick start (3 steps)

Works for most users — Immich on the same Docker host, no extra config.

1. Two credential files (ignored by git):

```powershell
# Windows PowerShell
New-Item ftp_users.txt -Value "camera_a7c2:LongRandomSecret!!"
New-Item immich_api_key.txt -Value "your-immich-api-key"
```

```bash
# Linux/macOS
printf 'camera_a7c2:LongRandomSecret!!' > ftp_users.txt
printf 'your-immich-api-key' > immich_api_key.txt
```

2. FTPS certs for your Docker host LAN IP:

```powershell
.\scripts\generate-ftps-cert.ps1 -ServerIp 192.168.1.10
```

```bash
./scripts/generate-ftps-cert.sh 192.168.1.10
```

3. `.env` with only your LAN IP, then start:

```dotenv
FTP_MASQUERADE_ADDRESS=192.168.1.10
```

```bash
docker compose up -d
```

Camera: user/password from `ftp_users.txt`, port `2121`, FTPES On, import `certs/cacert.pem`.

### Non-default setups (optional)

Edit `.env` only when you need to override:

| Variable | Default | When to change |
|----------|---------|----------------|
| `IMMICH_HOST` | `http://immich-server:2283` | Immich on another host/network |
| `IMMICH_DOCKER_NETWORK` | `immich_default` | Immich Compose project has another name |
| `IMMICH_ALLOW_HTTP` | `true` | Set `false` to refuse plain HTTP Immich |
| `GHCR_OWNER` / `IMAGE_TAG` | `hanevsky` / `latest` | Pin a release or use your own fork images |
| `TZ` | `UTC` | Local timezone |
| `FTP_USERS_FILE` / `IMMICH_API_KEY_FILE` | `./ftp_users.txt` / `./immich_api_key.txt` | Custom secret file paths |

## Immich API key

Create a key for the user who should own new assets.

Grant: `asset.upload`  
Optionally: `asset.read` (duplicate checks on some Immich/CLI versions)

Do **not** grant: `asset.update`, `asset.delete`, library admin, or “All permissions”.

## FTPS certificate

Generate a local CA + server cert for the host LAN IP:

```powershell
.\scripts\generate-ftps-cert.ps1 -ServerIp 192.168.1.10
```

| File | Use |
|------|-----|
| `certs/server.crt`, `certs/server.key` | Mounted into the FTP container only |
| `certs/cacert.pem` | Import on the camera |
| `certs/ca.key` | Keep offline — never put on the camera or card |

Sony (example):

```text
MENU → Network → Network Option → Import Root Certificate → FTP Function → OK
```

Re-issue the cert if the host LAN IP changes. Official guides: [FTP registration](https://helpguide.sony.net/di/ftp_2360/v1/en/contents/FTP_server_registration.html) · [Root certificate](https://helpguide.sony.net/di/ftp_2360/v1/en/contents/root_certificate.html)

## Firewall

1. Reserve DHCP leases for host and camera  
2. Do **not** port-forward FTP on the router  
3. Allow TCP `2121` and `30000–30009` **only** from the camera IP  

```powershell
New-NetFirewallRule `
  -DisplayName "Camera FTPS ingest" `
  -Direction Inbound -Action Allow -Protocol TCP `
  -LocalAddress 192.168.1.10 `
  -LocalPort 2121,30000-30009 `
  -RemoteAddress 192.168.1.50
```

## Camera settings (Sony FTPES)

| Setting | Value |
|---------|-------|
| Host Name | `FTP_MASQUERADE_ADDRESS` |
| Port | `2121` |
| Secure Protocol | On (FTPES) |
| Root Certificate Error | Does Not Connect |
| User / Password | from `FTP_USERS` |
| Passive Mode | On |
| Destination Directory | empty or `/` |

## Verify

1. Upload a test JPG → log shows `FTP upload committed`  
2. Upload the same name again → `*_1` created, original unchanged  
3. Within ~60s importer uploads both into Immich  
4. Existing Immich library size does not shrink  

Live policy check (password prompted; creates two throwaway assets):

```powershell
python scripts\verify-ftps-policy.py `
  --host 192.168.1.10 `
  --user <ftp-username> `
  --ca certs\ca.crt `
  --file C:\Temp\ftp-test.jpg
```

Unit / contract tests:

```bash
python -m venv .venv
.venv/bin/pip install -r ftp-server/requirements.txt   # Windows: .venv\Scripts\pip
.venv/bin/python -m unittest discover -s tests -v
```

## Security model (short)

- FTPS required by default (no plaintext login)
- Allowed FTP: upload + minimal session commands; no `RETR` / `DELE` / `RNFR` / `APPE` / …
- Atomic publish; disk guard rejects new `STOR` with `452` when free space is low (default 1024 MB via `FTP_MIN_FREE_MB`)
- FTP container on an internal Docker network; importer on the Immich network only
- Non-root (`10001`), `read_only`, `cap_drop: ALL`, `no-new-privileges`
- Staging copies are **never** auto-deleted after import

## Operations

```bash
docker compose logs -f sony-ftp
docker compose logs -f immich-importer
docker compose down          # keeps volumes
# docker compose down -v   # DANGER: deletes staging + importer state
```

| Topic | Notes |
|-------|--------|
| Staging growth | Monitor disk; set `FTP_MIN_FREE_MB` if needed |
| Partial uploads | Leftover `.upload-*.part` is ignored — do not rename blindly |
| Retry | Failed Immich batches are retried; Immich hashing avoids duplicates |
| Stop grace | FTP 15s / importer 60s so an in-flight `immich upload` can finish |

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Camera rejects cert | Import `cacert.pem`; IP in cert SAN; “Does Not Connect” |
| Login rejected | Secure Protocol = On |
| LIST ok, STOR fails | Extension/name rules; leading `-` rejected; logs for `452` |
| Passive hang | Ports `30000–30009`, `FTP_MASQUERADE_ADDRESS`, firewall |
| Importer unhealthy | Immich network exists; `IMMICH_HOST` resolves (`http://immich-server:2283`) |
| Same file retries forever | `importer_state` permissions; CLI exit code in logs |

## License / scope

Built for home Immich + camera FTPES ingest. Review firewall and API-key scope before exposing anything beyond your LAN.

Immich CLI docs: https://docs.immich.app/features/command-line-interface/
