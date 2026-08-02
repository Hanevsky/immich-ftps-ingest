from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import shutil
import stat
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Self

from OpenSSL import SSL
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.log import config_logging
from pyftpdlib.servers import FTPServer

LOGGER = logging.getLogger("sony_ftp")

SAFE_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _+,.()\[\]-]*$")
SAFE_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,12}$")

BLOCKED_COMMANDS = frozenset(
    {
        "APPE",
        "DELE",
        "MFMT",
        "MKD",
        "REST",
        "RETR",
        "RMD",
        "RNFR",
        "RNTO",
        "SITE",
        "STOU",
        "XMKD",
        "XRMD",
    }
)

# Read-only metadata and upload commands required by common FTPES clients.
# Active-mode commands (PORT/EPRT) and every destructive command are omitted.
ALLOWED_COMMANDS = frozenset(
    {
        "ABOR",
        "ALLO",
        "AUTH",
        "CDUP",
        "CWD",
        "EPSV",
        "FEAT",
        "LIST",
        "MDTM",
        "MLSD",
        "MLST",
        "MODE",
        "NLST",
        "NOOP",
        "OPTS",
        "PASS",
        "PASV",
        "PBSZ",
        "PROT",
        "PWD",
        "QUIT",
        "SIZE",
        "STOR",
        "STRU",
        "SYST",
        "TYPE",
        "USER",
        "XCUP",
        "XCWD",
        "XPWD",
    }
)

PLACEHOLDER_SECRETS = frozenset(
    {
        "changeme",
        "change-me",
        "password",
        "replace_me",
        "replace-me",
        "sony",
        "sony-password",
    }
)


class SecurityDefaults:
    """Centralized security constants for auditability."""

    MAX_LOGIN_ATTEMPTS = 3
    AUTH_FAILED_TIMEOUT = 3
    COMMIT_RETRIES = 10
    RESERVE_MAX_ATTEMPTS = 100_000
    MAX_TRACKED_IPS = 10_000
    BANNER = "FTP service ready."
    MIN_FREE_MB_DEFAULT = 1024
    MIN_FREE_MB_MINIMUM = 64
    MIN_FREE_MB_MAXIMUM = 102_400
    TLS_CIPHER_LIST = b"HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES"


class ConfigError(ValueError):
    """Raised when startup configuration is unsafe or invalid."""


class UploadPolicyError(ValueError):
    """Raised when an FTP upload violates the add-only policy."""


def parse_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false")


def parse_int(
    name: str,
    value: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def parse_extensions(value: str) -> frozenset[str]:
    extensions = frozenset(
        part.strip().lower().lstrip(".")
        for part in value.split(",")
        if part.strip()
    )
    if not extensions:
        raise ConfigError("FTP_ALLOWED_EXTENSIONS must not be empty")
    invalid = sorted(ext for ext in extensions if not SAFE_EXTENSION_RE.fullmatch(ext))
    if invalid:
        raise ConfigError(
            "FTP_ALLOWED_EXTENSIONS contains invalid values: " + ", ".join(invalid)
        )
    return extensions


def _read_secret_file(env_name: str) -> str | None:
    """Read a Docker secret file (e.g. /run/secrets/ftp_users) if present."""
    path_value = os.environ.get(env_name, "").strip()
    if not path_value:
        return None
    path = Path(path_value)
    if not path.is_file():
        raise ConfigError(f"{env_name} points to a missing file: {path}")
    return path.read_text(encoding="utf-8").strip()


def _normalize_pem(value: str) -> str:
    """Accept real newlines or dotenv-style escaped \\n sequences."""
    text = value.strip().strip('"').strip("'")
    if "\\n" in text and "\n" not in text:
        text = text.replace("\\n", "\n")
    return text.strip()


def _ftp_cert_dns_names() -> list[str]:
    raw = os.environ.get("FTP_CERT_DNS", "").strip()
    if not raw:
        return []
    return [part.strip().rstrip(".") for part in raw.split(",") if part.strip()]


def generate_self_signed_ftps_certs(
    cert_dir: Path,
    *,
    server_ip: str,
    dns_names: list[str] | None = None,
    validity_days: int = 825,
) -> tuple[Path, Path, Path]:
    """Create a Sony-friendly local CA + server certificate (persisted on volume)."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key_path = cert_dir / "ca.key"
    ca_cert_path = cert_dir / "cacert.pem"
    server_key_path = cert_dir / "server.key"
    server_cert_path = cert_dir / "server.crt"
    dns_names = list(dns_names or [])

    now = datetime.now(timezone.utc)
    # 3072-bit CA matches scripts/generate-ftps-cert.*; 4096 can fail on some cameras.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sony FTP Local Root CA")])
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    ca_cert = ca_builder.sign(ca_key, hashes.SHA256())

    try:
        server_ip_obj = ipaddress.ip_address(server_ip)
    except ValueError as error:
        raise ConfigError(
            "FTP_MASQUERADE_ADDRESS must be a valid IPv4 for automatic certificate generation"
        ) from error
    if server_ip_obj.version != 4:
        raise ConfigError(
            "FTP_MASQUERADE_ADDRESS must be IPv4 for passive-mode camera access"
        )

    san_entries: list[x509.GeneralName] = [x509.IPAddress(server_ip_obj)]
    for dns_name in dns_names:
        san_entries.append(x509.DNSName(dns_name))

    common_name = dns_names[0] if dns_names else server_ip
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_path.write_bytes(ca_pem)
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    # Chain = leaf + CA so TLS clients that expect a chain still verify.
    server_cert_path.write_bytes(server_pem + ca_pem)

    if os.name == "posix":
        os.chmod(ca_key_path, 0o600)
        os.chmod(server_key_path, 0o600)
        os.chmod(ca_cert_path, 0o644)
        os.chmod(server_cert_path, 0o644)

    LOGGER.warning(
        "Generated self-signed FTPS certificates in %s for IP=%s dns=%s. "
        "Import ONLY cacert.pem into the camera: "
        "docker exec sony_ftp cat /run/ftp-certs/cacert.pem",
        cert_dir,
        server_ip,
        ",".join(dns_names) if dns_names else "(none)",
    )
    return server_cert_path, server_key_path, ca_cert_path


def _clear_generated_ftps_material(cert_dir: Path) -> None:
    for name in ("ca.key", "cacert.pem", "server.key", "server.crt", "ca.crt", "ca.srl"):
        path = cert_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def ensure_ftps_certificate_files(
    *,
    cert_path: Path,
    key_path: Path,
    masquerade_address: str | None,
    allow_plaintext: bool,
) -> tuple[Path | None, Path | None]:
    """Resolve cert material from PEM env, existing files, or one-time auto-generation."""
    cert_pem = _normalize_pem(os.environ.get("FTP_CERT_PEM", ""))
    key_pem = _normalize_pem(os.environ.get("FTP_KEY_PEM", ""))
    if cert_pem or key_pem:
        if not (cert_pem and key_pem):
            raise ConfigError("FTP_CERT_PEM and FTP_KEY_PEM must both be set")
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(cert_pem + "\n", encoding="utf-8")
        key_path.write_text(key_pem + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(cert_path, 0o600)
            os.chmod(key_path, 0o600)

    regenerate = parse_bool(
        "FTP_REGENERATE_CERT",
        os.environ.get("FTP_REGENERATE_CERT", "false"),
    )
    if regenerate and not (cert_pem or key_pem):
        LOGGER.warning(
            "FTP_REGENERATE_CERT=true — wiping generated certs in %s "
            "(set back to false after the camera re-imports cacert.pem)",
            cert_path.parent,
        )
        _clear_generated_ftps_material(cert_path.parent)

    cert_exists = cert_path.is_file()
    key_exists = key_path.is_file()
    if cert_exists != key_exists:
        raise ConfigError(
            "FTP_CERT_FILE and FTP_KEY_FILE must either both exist or both be absent"
        )

    if not cert_exists:
        auto_generate = parse_bool(
            "FTP_AUTO_GENERATE_CERT",
            os.environ.get("FTP_AUTO_GENERATE_CERT", "true"),
        )
        if allow_plaintext:
            return None, None
        if not auto_generate:
            raise ConfigError(
                "FTPS is required: set FTP_CERT_PEM/FTP_KEY_PEM, mount certificates, "
                "or keep FTP_AUTO_GENERATE_CERT=true"
            )
        if not masquerade_address:
            raise ConfigError(
                "FTP_MASQUERADE_ADDRESS is required to auto-generate an FTPS certificate"
            )
        generate_self_signed_ftps_certs(
            cert_path.parent,
            server_ip=masquerade_address,
            dns_names=_ftp_cert_dns_names(),
        )

    return cert_path, key_path


def resolve_ftp_credentials() -> tuple[str, str]:
    """Accept FTP_USERS=user:password (or FTP_USERS_FILE with the same content)."""
    users = _read_secret_file("FTP_USERS_FILE") or os.environ.get(
        "FTP_USERS", ""
    ).strip()
    if not users:
        raise ConfigError("Set FTP_USERS=user:password")
    if ":" not in users:
        raise ConfigError("FTP_USERS must be in user:password form")
    username, password = users.split(":", 1)
    username = username.strip()
    if not username or password == "":
        raise ConfigError("FTP_USERS must be in user:password form")
    return username, password


def _open_flags(*names: str) -> int:
    flags = 0
    for name in names:
        flags |= getattr(os, name, 0)
    return flags


def _path_contains_symlink(path: Path) -> bool:
    current = Path("/") if path.is_absolute() else Path(".")
    for part in path.parts:
        if part in {"/", "\\"}:
            continue
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


@dataclass(frozen=True)
class ServerConfig:
    listen_address: str
    port: int
    username: str
    password: str
    root: Path
    allow_plaintext: bool
    cert_file: Path | None
    key_file: Path | None
    masquerade_address: str | None
    passive_min_port: int
    passive_max_port: int
    allowed_extensions: frozenset[str]
    max_filename_bytes: int
    timeout_seconds: int
    data_timeout_seconds: int
    max_connections: int
    max_connections_per_ip: int
    global_failure_limit: int
    failure_window_seconds: int
    ban_seconds: int
    min_free_bytes: int

    @property
    def tls_enabled(self) -> bool:
        return self.cert_file is not None and self.key_file is not None

    @classmethod
    def from_env(cls) -> ServerConfig:
        username, password = resolve_ftp_credentials()
        allow_plaintext = parse_bool(
            "FTP_ALLOW_PLAINTEXT",
            os.environ.get("FTP_ALLOW_PLAINTEXT", "false"),
        )

        cert_path = Path(
            os.environ.get("FTP_CERT_FILE", "/run/ftp-certs/server.crt")
        )
        key_path = Path(os.environ.get("FTP_KEY_FILE", "/run/ftp-certs/server.key"))
        masquerade_address = (
            os.environ.get("FTP_MASQUERADE_ADDRESS", "").strip() or None
        )
        cert_path, key_path = ensure_ftps_certificate_files(
            cert_path=cert_path,
            key_path=key_path,
            masquerade_address=masquerade_address,
            allow_plaintext=allow_plaintext,
        )

        min_free_mb = parse_int(
            "FTP_MIN_FREE_MB",
            os.environ.get(
                "FTP_MIN_FREE_MB",
                str(SecurityDefaults.MIN_FREE_MB_DEFAULT),
            ),
            minimum=SecurityDefaults.MIN_FREE_MB_MINIMUM,
            maximum=SecurityDefaults.MIN_FREE_MB_MAXIMUM,
        )

        config = cls(
            listen_address=os.environ.get("FTP_LISTEN_ADDRESS", "0.0.0.0").strip(),
            port=parse_int(
                "FTP_PORT",
                os.environ.get("FTP_PORT", "2121"),
                minimum=1024,
                maximum=65535,
            ),
            username=username,
            password=password,
            root=Path(os.environ.get("FTP_ROOT", "/srv/ftp/sony")).resolve(),
            allow_plaintext=allow_plaintext,
            cert_file=cert_path,
            key_file=key_path,
            masquerade_address=masquerade_address,
            passive_min_port=parse_int(
                "FTP_PASSIVE_MIN_PORT",
                os.environ.get("FTP_PASSIVE_MIN_PORT", "30000"),
                minimum=1024,
                maximum=65535,
            ),
            passive_max_port=parse_int(
                "FTP_PASSIVE_MAX_PORT",
                os.environ.get("FTP_PASSIVE_MAX_PORT", "30009"),
                minimum=1024,
                maximum=65535,
            ),
            allowed_extensions=parse_extensions(
                os.environ.get(
                    "FTP_ALLOWED_EXTENSIONS",
                    "jpg,jpeg,arw,heif,hif,dng,mp4,mov,mts,xmp",
                )
            ),
            max_filename_bytes=parse_int(
                "FTP_MAX_FILENAME_BYTES",
                os.environ.get("FTP_MAX_FILENAME_BYTES", "200"),
                minimum=32,
                maximum=240,
            ),
            timeout_seconds=parse_int(
                "FTP_TIMEOUT_SECONDS",
                os.environ.get("FTP_TIMEOUT_SECONDS", "300"),
                minimum=30,
                maximum=3600,
            ),
            data_timeout_seconds=parse_int(
                "FTP_DATA_TIMEOUT_SECONDS",
                os.environ.get("FTP_DATA_TIMEOUT_SECONDS", "300"),
                minimum=30,
                maximum=3600,
            ),
            max_connections=parse_int(
                "FTP_MAX_CONNECTIONS",
                os.environ.get("FTP_MAX_CONNECTIONS", "32"),
                minimum=1,
                maximum=50,
            ),
            max_connections_per_ip=parse_int(
                "FTP_MAX_CONNECTIONS_PER_IP",
                os.environ.get("FTP_MAX_CONNECTIONS_PER_IP", "8"),
                minimum=1,
                maximum=10,
            ),
            global_failure_limit=parse_int(
                "FTP_GLOBAL_FAILURE_LIMIT",
                os.environ.get("FTP_GLOBAL_FAILURE_LIMIT", "6"),
                minimum=3,
                maximum=100,
            ),
            failure_window_seconds=parse_int(
                "FTP_FAILURE_WINDOW_SECONDS",
                os.environ.get("FTP_FAILURE_WINDOW_SECONDS", "300"),
                minimum=30,
                maximum=86400,
            ),
            ban_seconds=parse_int(
                "FTP_BAN_SECONDS",
                os.environ.get("FTP_BAN_SECONDS", "900"),
                minimum=30,
                maximum=86400,
            ),
            min_free_bytes=min_free_mb * 1024 * 1024,
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not SAFE_USERNAME_RE.fullmatch(self.username):
            raise ConfigError(
                "FTP username must be 3-64 characters and contain only letters, "
                "numbers, underscore, dot, or dash"
            )
        if self.username.lower() in {"anonymous", "ftp", "sony", "admin"}:
            raise ConfigError("FTP username is too predictable; choose a unique username")
        if not 16 <= len(self.password) <= 64:
            raise ConfigError("FTP password must contain 16-64 characters")
        normalized_password = self.password.strip().lower()
        placeholder_markers = (
            "changeme",
            "change_me",
            "change-me",
            "replace_me",
            "replace-me",
            "replace-with",
        )
        if normalized_password in PLACEHOLDER_SECRETS or any(
            marker in normalized_password for marker in placeholder_markers
        ):
            raise ConfigError("FTP password is a known placeholder")
        if normalized_password == self.username.lower() or len(set(self.password)) < 6:
            raise ConfigError("FTP password is too predictable")
        if any(
            ord(character) < 32 or ord(character) == 127
            for character in self.password
        ):
            raise ConfigError("FTP password must not contain control characters")
        if self.passive_min_port > self.passive_max_port:
            raise ConfigError(
                "FTP_PASSIVE_MIN_PORT must not exceed FTP_PASSIVE_MAX_PORT"
            )
        if self.passive_max_port - self.passive_min_port > 99:
            raise ConfigError("The passive FTP range must contain at most 100 ports")
        if self.max_connections_per_ip > self.max_connections:
            raise ConfigError(
                "FTP_MAX_CONNECTIONS_PER_IP must not exceed FTP_MAX_CONNECTIONS"
            )
        if self.min_free_bytes < SecurityDefaults.MIN_FREE_MB_MINIMUM * 1024 * 1024:
            raise ConfigError("FTP_MIN_FREE_MB is below the supported minimum")
        try:
            ipaddress.ip_address(self.listen_address)
        except ValueError as error:
            raise ConfigError("FTP_LISTEN_ADDRESS must be an IP address") from error
        if self.masquerade_address:
            try:
                address = ipaddress.ip_address(self.masquerade_address)
            except ValueError as error:
                raise ConfigError(
                    "FTP_MASQUERADE_ADDRESS must be an IP address"
                ) from error
            if address.version != 4:
                raise ConfigError(
                    "FTP_MASQUERADE_ADDRESS must be IPv4 for passive-mode camera access"
                )


def normalize_requested_filename(
    raw_name: str,
    allowed_extensions: frozenset[str],
    max_filename_bytes: int,
) -> str:
    """Validate a root-level upload name and return its canonical form."""

    name = raw_name.removeprefix("/")
    if not name or name in {".", ".."}:
        raise UploadPolicyError("empty or reserved filename")
    if name != name.strip():
        raise UploadPolicyError("leading or trailing whitespace is not allowed")
    if name.startswith("-"):
        raise UploadPolicyError("leading dash is not allowed")
    if "/" in name or "\\" in name or ".." in name or "\x00" in name:
        raise UploadPolicyError("path components are not allowed")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise UploadPolicyError("control characters are not allowed")
    if not SAFE_FILENAME_RE.fullmatch(name):
        raise UploadPolicyError("filename contains unsupported characters")
    if len(name.encode("utf-8")) > max_filename_bytes:
        raise UploadPolicyError("filename is too long")

    suffix = Path(name).suffix
    if not suffix:
        raise UploadPolicyError("file extension is required")
    extension = suffix[1:].lower()
    if extension not in allowed_extensions:
        raise UploadPolicyError(f"extension .{extension} is not allowed")
    return name


@dataclass
class PendingUpload:
    requested_name: str
    final_path: Path
    reservation_path: Path
    temporary_path: Path


def _candidate_name(original_name: str, index: int) -> str:
    if index == 0:
        return original_name
    path = Path(original_name)
    return f"{path.stem}_{index}{path.suffix}"


def _reservation_name(candidate_name: str) -> str:
    digest = hashlib.sha256(candidate_name.encode("utf-8")).hexdigest()
    return f".reserve-{digest}.lock"


class SafeStagingStore:
    """Directory-scoped staging operations with symlink-resistant I/O."""

    def __init__(self, root: Path) -> None:
        if root.is_symlink():
            raise ConfigError("FTP_ROOT must not be a symbolic link")
        root.mkdir(parents=True, exist_ok=True)
        resolved = root.resolve(strict=True)
        if _path_contains_symlink(resolved):
            raise ConfigError("FTP_ROOT path must not contain symbolic links")
        if not resolved.is_dir():
            raise ConfigError("FTP_ROOT is not a directory")
        if not os.access(resolved, os.W_OK):
            raise ConfigError("FTP_ROOT is not writable by the service user")

        # Unix permission bits are the security boundary in the Docker image.
        # Windows ACL semantics differ, so skip this check outside POSIX.
        if os.name == "posix":
            mode = resolved.stat().st_mode
            if mode & stat.S_IWOTH:
                raise ConfigError("FTP_ROOT must not be world-writable")
            if not os.access(resolved, os.X_OK):
                raise ConfigError("FTP_ROOT is not executable/traversable")

        self.root = resolved
        directory_flags = _open_flags("O_RDONLY", "O_DIRECTORY")
        if directory_flags == os.O_RDONLY:
            # Windows and some platforms lack O_DIRECTORY; keep a path-only mode.
            self._dir_fd: int | None = None
            self._use_dir_fd = False
        else:
            self._dir_fd = os.open(str(resolved), directory_flags)
            self._use_dir_fd = True

        self._nofollow = hasattr(os, "O_NOFOLLOW")
        self._link_supports_dir_fd = self._use_dir_fd and self._supports_link_dir_fd()

    def close(self) -> None:
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @staticmethod
    def _supports_link_dir_fd() -> bool:
        # Presence of src_dir_fd in the signature varies by platform.
        import inspect

        try:
            signature = inspect.signature(os.link)
        except (TypeError, ValueError, AttributeError):
            return False
        return "src_dir_fd" in signature.parameters

    def free_bytes(self) -> int:
        return shutil.disk_usage(self.root).free

    def has_min_free_space(self, minimum_bytes: int) -> bool:
        return self.free_bytes() >= minimum_bytes

    def path_for(self, name: str) -> Path:
        return self.root / name

    def _open_exclusive(self, name: str, mode: int = 0o600) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if self._nofollow:
            flags |= os.O_NOFOLLOW
        if self._use_dir_fd and self._dir_fd is not None:
            return os.open(name, flags, mode, dir_fd=self._dir_fd)
        return os.open(self.root / name, flags, mode)

    def _unlink(self, name: str) -> None:
        if self._use_dir_fd and self._dir_fd is not None:
            os.unlink(name, dir_fd=self._dir_fd)
            return
        (self.root / name).unlink()

    def _exists(self, name: str) -> bool:
        if self._use_dir_fd and self._dir_fd is not None:
            try:
                os.stat(name, dir_fd=self._dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError:
                # Symlink loops / permission errors are treated as occupied.
                return True
            return True
        path = self.root / name
        return path.exists() or path.is_symlink()

    def _fsync_directory(self) -> None:
        if self._dir_fd is not None:
            os.fsync(self._dir_fd)

    def release(self, reservation_path: Path) -> None:
        try:
            self._unlink(reservation_path.name)
            self._fsync_directory()
        except FileNotFoundError:
            return
        except OSError:
            LOGGER.exception(
                "Could not remove upload reservation %s",
                reservation_path.name,
            )

    def discard(self, path: Path) -> None:
        try:
            self._unlink(path.name)
            self._fsync_directory()
        except FileNotFoundError:
            return
        except OSError:
            LOGGER.exception("Could not discard temporary upload %s", path.name)

    def reserve(
        self,
        requested_name: str,
        *,
        start_index: int = 0,
        max_attempts: int = SecurityDefaults.RESERVE_MAX_ATTEMPTS,
    ) -> tuple[Path, Path]:
        """Atomically reserve a unique destination without touching existing files."""

        for index in range(start_index, start_index + max_attempts):
            candidate_name = _candidate_name(requested_name, index)
            if self._exists(candidate_name):
                continue

            reservation_name = _reservation_name(candidate_name)
            try:
                descriptor = self._open_exclusive(reservation_name, 0o600)
            except FileExistsError:
                continue

            try:
                os.write(descriptor, f"{candidate_name}\n".encode())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

            if self._exists(candidate_name):
                self.release(self.path_for(reservation_name))
                continue
            return self.path_for(candidate_name), self.path_for(reservation_name)

        raise UploadPolicyError("could not allocate a unique destination filename")

    def commit(self, pending: PendingUpload) -> Path:
        """Publish a completed hidden upload using a no-replace hard link."""

        for _ in range(SecurityDefaults.COMMIT_RETRIES):
            try:
                if self._link_supports_dir_fd and self._dir_fd is not None:
                    os.link(
                        pending.temporary_path.name,
                        pending.final_path.name,
                        src_dir_fd=self._dir_fd,
                        dst_dir_fd=self._dir_fd,
                        follow_symlinks=False,
                    )
                else:
                    os.link(
                        pending.temporary_path,
                        pending.final_path,
                        follow_symlinks=False,
                    )
            except FileExistsError:
                self.release(pending.reservation_path)
                final_path, reservation_path = self.reserve(
                    pending.requested_name,
                    start_index=1,
                )
                pending.final_path = final_path
                pending.reservation_path = reservation_path
                continue
            except OSError as error:
                # Symlink targets or cross-device errors must never overwrite.
                raise UploadPolicyError(
                    f"could not publish upload safely: {error}"
                ) from error

            self._fsync_directory()
            self.discard(pending.temporary_path)
            self.release(pending.reservation_path)
            return pending.final_path

        raise UploadPolicyError("destination changed repeatedly while committing upload")


# Compatibility wrappers used by unit tests and older call sites.
def reserve_destination(
    root: Path,
    requested_name: str,
    *,
    start_index: int = 0,
    max_attempts: int = SecurityDefaults.RESERVE_MAX_ATTEMPTS,
) -> tuple[Path, Path]:
    store = SafeStagingStore(root)
    try:
        return store.reserve(
            requested_name,
            start_index=start_index,
            max_attempts=max_attempts,
        )
    finally:
        store.close()


def release_reservation(path: Path) -> None:
    store = SafeStagingStore(path.parent)
    try:
        store.release(path)
    finally:
        store.close()


def commit_pending_upload(pending: PendingUpload) -> Path:
    store = SafeStagingStore(pending.final_path.parent)
    try:
        return store.commit(pending)
    finally:
        store.close()


class LoginRateLimiter:
    """Cross-connection failure window and temporary IP ban."""

    def __init__(
        self,
        *,
        failure_limit: int,
        window_seconds: int,
        ban_seconds: int,
        max_tracked_ips: int = SecurityDefaults.MAX_TRACKED_IPS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_limit = failure_limit
        self.window_seconds = window_seconds
        self.ban_seconds = ban_seconds
        self.max_tracked_ips = max_tracked_ips
        self.clock = clock
        self._failures: defaultdict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._lock = Lock()
        self._eviction_logged = False

    def _prune(self, address: str, now: float) -> deque[float]:
        failures = self._failures[address]
        cutoff = now - self.window_seconds
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            self._failures.pop(address, None)
            return deque()
        return failures

    def _evict_if_needed(self, now: float) -> None:
        # Drop expired bans first.
        expired = [
            address
            for address, blocked_until in self._blocked_until.items()
            if blocked_until <= now
        ]
        for address in expired:
            self._blocked_until.pop(address, None)

        tracked = set(self._failures) | set(self._blocked_until)
        overflow = len(tracked) - self.max_tracked_ips
        if overflow <= 0:
            return

        candidates: list[tuple[float, str]] = []
        for address in tracked:
            blocked_until = self._blocked_until.get(address, 0.0)
            failures = self._failures.get(address)
            last_failure = failures[-1] if failures else 0.0
            # Prefer evicting the oldest, non-banned activity first.
            score = last_failure if blocked_until <= now else blocked_until
            candidates.append((score, address))
        candidates.sort()
        for _, address in candidates[:overflow]:
            self._failures.pop(address, None)
            self._blocked_until.pop(address, None)
        if not self._eviction_logged:
            LOGGER.warning(
                "LoginRateLimiter evicted %s tracked IP entries after reaching cap=%s",
                overflow,
                self.max_tracked_ips,
            )
            self._eviction_logged = True

    def is_blocked(self, address: str) -> bool:
        now = self.clock()
        with self._lock:
            blocked_until = self._blocked_until.get(address, 0)
            if blocked_until > now:
                return True
            self._blocked_until.pop(address, None)
            self._prune(address, now)
            self._evict_if_needed(now)
            return False

    def record_failure(self, address: str) -> bool:
        now = self.clock()
        with self._lock:
            failures = self._prune(address, now)
            if not failures:
                failures = self._failures[address]
            failures.append(now)
            self._evict_if_needed(now)
            if len(failures) >= self.failure_limit:
                self._blocked_until[address] = now + self.ban_seconds
                self._failures.pop(address, None)
                return True
            return False

    def record_success(self, address: str) -> None:
        with self._lock:
            self._failures.pop(address, None)
            self._blocked_until.pop(address, None)


class HardenedTLSContextMixin:
    _context_config: ServerConfig | None = None

    @classmethod
    def get_ssl_context(cls):
        config = getattr(cls, "_context_config", None)
        if config is None:
            raise ConfigError("TLS handler was built without a bound ServerConfig")
        # Rebuild when a different configuration is attached to the class.
        if cls.ssl_context is not None and getattr(cls, "_bound_config_id", None) == id(
            config
        ):
            return cls.ssl_context

        context = SSL.Context(SSL.SSLv23_METHOD)
        if hasattr(context, "set_min_proto_version"):
            context.set_min_proto_version(SSL.TLS1_2_VERSION)
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        if hasattr(SSL, "OP_NO_COMPRESSION"):
            context.set_options(SSL.OP_NO_COMPRESSION)
        if config.cert_file is None:
            raise ConfigError("TLS certificate path is missing")
        context.use_certificate_chain_file(str(config.cert_file))
        key_file = config.key_file or config.cert_file
        context.use_privatekey_file(str(key_file))
        context.set_cipher_list(SecurityDefaults.TLS_CIPHER_LIST)
        cls.ssl_context = context
        cls._bound_config_id = id(config)
        return context


class UploadOnlyHandlerMixin:
    config: ServerConfig
    login_limiter: LoginRateLimiter
    staging_store: SafeStagingStore

    def __init__(self, *args, **kwargs) -> None:
        self._pending_uploads: dict[str, PendingUpload] = {}
        super().__init__(*args, **kwargs)

    def on_connect(self) -> None:
        if self.login_limiter.is_blocked(self.remote_ip):
            LOGGER.warning("Rejected temporarily blocked FTP client ip=%s", self.remote_ip)
            self.respond("421 Too many authentication failures; try again later.")
            self.close_when_done()

    def on_login(self, username: str) -> None:
        self.login_limiter.record_success(self.remote_ip)
        LOGGER.info("FTP login succeeded ip=%s user=%s", self.remote_ip, username)

    def on_login_failed(self, username: str, password: str) -> None:
        del password
        blocked = self.login_limiter.record_failure(self.remote_ip)
        LOGGER.warning(
            "FTP login failed ip=%s user=%r temporary_ban=%s",
            self.remote_ip,
            username,
            blocked,
        )

    def pre_process_command(self, line: str, cmd: str, arg: str) -> None:
        normalized_command = cmd.upper()
        if normalized_command in BLOCKED_COMMANDS:
            LOGGER.warning(
                "Blocked FTP command ip=%s command=%s",
                self.remote_ip,
                normalized_command,
            )
            self.respond("550 Command disabled by upload-only policy.")
            return

        if normalized_command == "STOR":
            try:
                safe_name = normalize_requested_filename(
                    arg,
                    self.config.allowed_extensions,
                    self.config.max_filename_bytes,
                )
            except UploadPolicyError as error:
                LOGGER.warning(
                    "Rejected FTP upload name ip=%s name=%r reason=%s",
                    self.remote_ip,
                    arg,
                    error,
                )
                self.respond(f"553 File name not allowed: {error}.")
                return
            arg = safe_name
            line = f"STOR {safe_name}"

        super().pre_process_command(line, normalized_command, arg)

    def ftp_STOR(self, file: str, mode: str = "w"):
        if mode != "w" or self._restart_position:
            self.respond("550 Resuming or appending uploads is disabled.")
            return None

        root = Path(self.fs.root).resolve()
        if root != self.staging_store.root:
            self.respond("550 Uploads are restricted to the FTP root.")
            return None

        requested_path = Path(file)
        if requested_path.parent.resolve() != root:
            self.respond("550 Uploads are restricted to the FTP root.")
            return None

        if not self.staging_store.has_min_free_space(self.config.min_free_bytes):
            LOGGER.warning(
                "Rejected FTP upload due to low free space ip=%s free=%s required=%s",
                self.remote_ip,
                self.staging_store.free_bytes(),
                self.config.min_free_bytes,
            )
            self.respond("452 Insufficient storage space on server.")
            return None

        requested_name = normalize_requested_filename(
            requested_path.name,
            self.config.allowed_extensions,
            self.config.max_filename_bytes,
        )
        try:
            final_path, reservation_path = self.staging_store.reserve(requested_name)
        except (OSError, UploadPolicyError) as error:
            LOGGER.error(
                "Could not reserve FTP destination ip=%s name=%s error=%s",
                self.remote_ip,
                requested_name,
                error,
            )
            self.respond("451 Could not reserve a safe destination.")
            return None

        temporary_path = self.staging_store.path_for(
            f".upload-{uuid.uuid4().hex}.part"
        )
        pending = PendingUpload(
            requested_name=requested_name,
            final_path=final_path,
            reservation_path=reservation_path,
            temporary_path=temporary_path,
        )
        self._pending_uploads[str(temporary_path)] = pending

        try:
            result = super().ftp_STOR(str(temporary_path), mode="x")
        except Exception:
            self._pending_uploads.pop(str(temporary_path), None)
            self.staging_store.discard(temporary_path)
            self.staging_store.release(reservation_path)
            raise
        if result is None:
            self._pending_uploads.pop(str(temporary_path), None)
            self.staging_store.discard(temporary_path)
            self.staging_store.release(reservation_path)
        return result

    def on_file_received(self, file: str) -> None:
        pending = self._pending_uploads.pop(file, None)
        if pending is None:
            LOGGER.error("Completed upload has no reservation file=%s", Path(file).name)
            return
        try:
            final_path = self.staging_store.commit(pending)
        except Exception:
            # Preserve the complete hidden temporary file and its reservation.
            # An operator can recover it without any loss of received bytes.
            LOGGER.exception(
                "Could not publish completed upload; retained temporary file=%s",
                pending.temporary_path.name,
            )
            return
        LOGGER.info(
            "FTP upload committed ip=%s requested=%s stored=%s",
            self.remote_ip,
            pending.requested_name,
            final_path.name,
        )

    def on_incomplete_file_received(self, file: str) -> None:
        pending = self._pending_uploads.pop(file, None)
        if pending is None:
            return
        self.staging_store.discard(pending.temporary_path)
        self.staging_store.release(pending.reservation_path)
        LOGGER.warning(
            "Incomplete FTP upload discarded ip=%s requested=%s",
            self.remote_ip,
            pending.requested_name,
        )


def build_handler(config: ServerConfig, staging_store: SafeStagingStore | None = None):
    authorizer = DummyAuthorizer()
    # e=change directory, l=list, w=store. No read/delete/append/rename/mkdir.
    authorizer.add_user(
        config.username,
        config.password,
        str(config.root),
        perm="elw",
        msg_login="Authentication successful.",
    )

    store = staging_store or SafeStagingStore(config.root)

    if config.tls_enabled:
        base_handler = TLS_FTPHandler

        class ConfiguredUploadHandler(
            UploadOnlyHandlerMixin,
            HardenedTLSContextMixin,
            TLS_FTPHandler,
        ):
            pass

    else:
        base_handler = FTPHandler

        class ConfiguredUploadHandler(UploadOnlyHandlerMixin, FTPHandler):
            pass

    ConfiguredUploadHandler.__name__ = "ConfiguredUploadHandler"
    ConfiguredUploadHandler.authorizer = authorizer
    ConfiguredUploadHandler.config = config
    ConfiguredUploadHandler.staging_store = store
    ConfiguredUploadHandler.login_limiter = LoginRateLimiter(
        failure_limit=config.global_failure_limit,
        window_seconds=config.failure_window_seconds,
        ban_seconds=config.ban_seconds,
    )
    ConfiguredUploadHandler.proto_cmds = {
        command: metadata.copy()
        for command, metadata in base_handler.proto_cmds.items()
        if command in ALLOWED_COMMANDS
    }
    ConfiguredUploadHandler.timeout = config.timeout_seconds
    ConfiguredUploadHandler.max_login_attempts = SecurityDefaults.MAX_LOGIN_ATTEMPTS
    ConfiguredUploadHandler.auth_failed_timeout = SecurityDefaults.AUTH_FAILED_TIMEOUT
    ConfiguredUploadHandler.banner = SecurityDefaults.BANNER
    ConfiguredUploadHandler.passive_ports = range(
        config.passive_min_port,
        config.passive_max_port + 1,
    )
    ConfiguredUploadHandler.masquerade_address = config.masquerade_address
    ConfiguredUploadHandler.permit_foreign_addresses = False
    ConfiguredUploadHandler.permit_privileged_ports = False
    ConfiguredUploadHandler.use_sendfile = False

    ConfiguredDTPHandler = type(
        "ConfiguredDTPHandler",
        (base_handler.dtp_handler,),
        {"timeout": config.data_timeout_seconds},
    )
    ConfiguredUploadHandler.dtp_handler = ConfiguredDTPHandler

    if config.tls_enabled:
        ConfiguredUploadHandler.certfile = str(config.cert_file)
        ConfiguredUploadHandler.keyfile = str(config.key_file)
        ConfiguredUploadHandler.tls_control_required = not config.allow_plaintext
        ConfiguredUploadHandler.tls_data_required = not config.allow_plaintext
        ConfiguredUploadHandler.ssl_context = None
        ConfiguredUploadHandler._context_config = config
        ConfiguredUploadHandler._bound_config_id = None

    return ConfiguredUploadHandler


def build_server(config: ServerConfig) -> FTPServer:
    staging_store = SafeStagingStore(config.root)
    # Keep ServerConfig.root aligned with the validated realpath.
    object.__setattr__(config, "root", staging_store.root)
    handler = build_handler(config, staging_store=staging_store)
    server = FTPServer((config.listen_address, config.port), handler)
    server.max_cons = config.max_connections
    server.max_cons_per_ip = config.max_connections_per_ip
    return server


def main() -> int:
    os.umask(0o027)
    config_logging(level=logging.INFO)
    try:
        config = ServerConfig.from_env()
        server = build_server(config)
    except (ConfigError, OSError, ValueError) as error:
        LOGGER.critical("FTP server refused to start: %s", error)
        return 2

    security_mode = (
        "FTPS required"
        if config.tls_enabled and not config.allow_plaintext
        else "FTPS optional; plaintext explicitly enabled"
        if config.tls_enabled
        else "plaintext explicitly enabled"
    )
    LOGGER.info(
        "Starting add-only FTP service address=%s port=%d passive=%d-%d "
        "mode=%s root=%s min_free_bytes=%s",
        config.listen_address,
        config.port,
        config.passive_min_port,
        config.passive_max_port,
        security_mode,
        config.root,
        config.min_free_bytes,
    )
    try:
        server.serve_forever(timeout=1, blocking=True, handle_exit=True)
    except KeyboardInterrupt:
        LOGGER.info("FTP server interrupted")
    finally:
        server.close_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
