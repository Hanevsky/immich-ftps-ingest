from __future__ import annotations

import argparse
import ftplib
import getpass
import io
import secrets
import ssl
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path


def expect_denied(label: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except ftplib.error_perm:
        print(f"PASS: {label} denied")
        return
    raise RuntimeError(f"SECURITY FAILURE: {label} was unexpectedly allowed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Upload two disposable test photos over verified FTPS and assert "
            "that read/update/delete/traversal operations are blocked."
        )
    )
    parser.add_argument("--host", required=True, help="Docker host LAN IPv4")
    parser.add_argument("--port", type=int, default=2121)
    parser.add_argument("--user", required=True, help="FTP username")
    parser.add_argument(
        "--ca",
        type=Path,
        default=Path("certs/ca.crt"),
        help="FTPS root CA certificate",
    )
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="A small valid JPG/ARW/MP4 test asset; it will be imported to Immich",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.ca.is_file():
        raise SystemExit(f"CA certificate not found: {args.ca}")
    if not args.file.is_file():
        raise SystemExit(f"Test asset not found: {args.file}")
    if args.file.stat().st_size == 0:
        raise SystemExit("Test asset must not be empty")

    password = getpass.getpass("FTP password: ")
    context = ssl.create_default_context(cafile=str(args.ca))
    payload = args.file.read_bytes()
    suffix = args.file.suffix.upper()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    token = secrets.token_hex(3).upper()
    remote_name = f"SECURITY_TEST_{stamp}_{token}{suffix}"
    collision_name = f"{Path(remote_name).stem}_1{suffix}"

    client = ftplib.FTP_TLS(context=context)
    client.connect(args.host, args.port, timeout=15)
    try:
        client.login(args.user, password)
        client.prot_p()
        client.storbinary(f"STOR {remote_name}", io.BytesIO(payload))
        client.storbinary(f"STOR {remote_name}", io.BytesIO(payload))

        listing = set(client.nlst())
        if remote_name not in listing or collision_name not in listing:
            raise RuntimeError(
                "SECURITY FAILURE: collision-safe files were not both published"
            )
        print(f"PASS: collision stored as {remote_name} and {collision_name}")

        expect_denied("DELE", lambda: client.delete(remote_name))
        expect_denied(
            "RNFR/RNTO",
            lambda: client.rename(remote_name, f"RENAMED_{remote_name}"),
        )
        expect_denied(
            "RETR",
            lambda: client.retrbinary(f"RETR {remote_name}", lambda _: None),
        )
        expect_denied(
            "APPE",
            lambda: client.storbinary(f"APPE {remote_name}", io.BytesIO(b"x")),
        )
        expect_denied(
            "path traversal",
            lambda: client.storbinary(
                f"STOR ../{remote_name}",
                io.BytesIO(payload),
            ),
        )
    finally:
        try:
            client.quit()
        except (OSError, EOFError, ftplib.Error):
            client.close()

    print("FTPS add-only policy verified.")
    print("Wait for the importer and confirm both disposable assets in Immich.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
