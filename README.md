# Immich FTPS Ingest

Add-only **FTPES** ingest for cameras into [Immich](https://immich.app).

```text
Camera ──FTPS (upload only)──► staging volume ──► immich-cli ──► Immich API
```

## Quick start (Portainer / Compose)

**Required:** Docker + running Immich (`immich_default` network).

### Environment (only 3 required)

| Variable | Example |
|----------|---------|
| `FTP_USERS` | `camera_a7c2:LongRandomSecret!!` |
| `FTP_MASQUERADE_ADDRESS` | `192.168.1.10` (Docker host LAN IP) |
| `IMMICH_API_KEY` | Immich key with `asset.upload` |

FTPS certificates are **created automatically** on first start (stored in volume
`ftp_certs`, SAN = masquerade IP, optional DNS via `FTP_CERT_DNS`).

To rotate certificates once: set `FTP_REGENERATE_CERT=true`, recreate `sony_ftp`,
export/import `cacert.pem`, then set `FTP_REGENERATE_CERT=false`.

1. Portainer → Stacks → Add → paste [`docker-compose.yml`](docker-compose.yml)
2. Set the three variables above → **Deploy**
3. Export the camera trust root:

```bash
docker exec sony_ftp cat /run/ftp-certs/cacert.pem > cacert.pem
```

4. Import `cacert.pem` on the camera. FTP: host = LAN IP, port `2121`, FTPES On, Passive On.

Optional overrides: `IMMICH_HOST`, `IMMICH_DOCKER_NETWORK`, `FTP_CERT_PEM` /
`FTP_KEY_PEM` (skip auto-gen), `FTP_AUTO_GENERATE_CERT=false`.

Importer tunables (defaults are for camera bursts on a Docker LAN):

| Variable | Default | Meaning |
|----------|---------|---------|
| `IMPORT_INTERVAL_SEC` | `30` | Idle poll interval |
| `IMPORT_BATCH_SIZE` | `200` | Max files per Immich CLI call |
| `IMPORT_CONCURRENCY` | `2` | Parallel uploads |
| `IMPORT_SKIP_HASH` | `true` | Skip local hash (Immich still dedupes) |
| `IMPORT_DELETE_AFTER_UPLOAD` | `true` | Delete staging file after success/duplicate |

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
docker compose down
# docker compose down -v   # deletes staging + auto-generated certs — avoid
```

If you delete the `ftp_certs` volume, a **new** CA is generated and the camera
must import the new `cacert.pem`.

Local image build:  
`docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`

## Security (short)

- FTPS required; destructive FTP commands blocked; collisions get `_1`, `_2`, …
- Staging files are deleted after a successful Immich upload (or server duplicate)
- New uploads rejected with `452` when free space is low (~1 GB default)

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Cert rejected | Re-import `cacert.pem` from the container; IP must match masquerade |
| Login rejected | Secure Protocol = On |
| Passive hang | Ports `30000–30009`, masquerade IP, firewall |
| Importer unhealthy | Immich network / `IMMICH_HOST` |

Immich CLI: https://docs.immich.app/features/command-line-interface/
