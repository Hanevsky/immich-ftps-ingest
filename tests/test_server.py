from __future__ import annotations

import ftplib
import io
import ipaddress
import os
import ssl
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "ftp-server"))

import server as ftp_server


def make_config(root: Path) -> ftp_server.ServerConfig:
    return ftp_server.ServerConfig(
        listen_address="127.0.0.1",
        port=2121,
        username="camera_test_7x",
        password="correct-horse-battery-staple",
        root=root,
        allow_plaintext=True,
        cert_file=None,
        key_file=None,
        masquerade_address=None,
        passive_min_port=30000,
        passive_max_port=30009,
        allowed_extensions=frozenset({"jpg", "arw", "mp4"}),
        max_filename_bytes=200,
        timeout_seconds=30,
        data_timeout_seconds=30,
        max_connections=5,
        max_connections_per_ip=2,
        global_failure_limit=6,
        failure_window_seconds=300,
        ban_seconds=900,
        min_free_bytes=1024 * 1024,
    )


class ConfigValidationTests(unittest.TestCase):
    def test_rejects_placeholder_and_low_variety_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            for password in (
                "CHANGE_ME_WITH_RANDOM_PASSWORD",
                "aaaaaaaaaaaaaaaa",
            ):
                with self.subTest(password=password), self.assertRaises(
                    ftp_server.ConfigError
                ):
                    replace(config, password=password).validate()

    def test_ftp_users_env_parses_user_password(self) -> None:
        previous = {
            key: os.environ.get(key)
            for key in ("FTP_USERS", "FTP_USER", "FTP_PASS", "FTP_ALLOW_PLAINTEXT")
        }
        try:
            os.environ.pop("FTP_USER", None)
            os.environ.pop("FTP_PASS", None)
            os.environ["FTP_USERS"] = "camera_test_7x:Str0ng-P@ssw0rd!!99"
            os.environ["FTP_ALLOW_PLAINTEXT"] = "true"
            with tempfile.TemporaryDirectory() as directory:
                os.environ["FTP_ROOT"] = directory
                os.environ["FTP_MASQUERADE_ADDRESS"] = "192.0.2.10"
                config = ftp_server.ServerConfig.from_env()
                self.assertEqual(config.username, "camera_test_7x")
                self.assertEqual(config.password, "Str0ng-P@ssw0rd!!99")
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            os.environ.pop("FTP_ROOT", None)
            os.environ.pop("FTP_MASQUERADE_ADDRESS", None)


class FilenamePolicyTests(unittest.TestCase):
    def test_accepts_sony_names_case_insensitively(self) -> None:
        allowed = frozenset({"jpg", "arw"})
        self.assertEqual(
            ftp_server.normalize_requested_filename("/DSC01234.JPG", allowed, 200),
            "DSC01234.JPG",
        )
        self.assertEqual(
            ftp_server.normalize_requested_filename("DSC01235.ARW", allowed, 200),
            "DSC01235.ARW",
        )

    def test_rejects_traversal_controls_hidden_and_executables(self) -> None:
        invalid_names = (
            "../outside.jpg",
            "..\\outside.jpg",
            "folder/photo.jpg",
            ".hidden.jpg",
            "photo..jpg",
            "photo\n.jpg",
            "payload.exe",
            "payload.php",
            "-evil.jpg",
        )
        for name in invalid_names:
            with self.subTest(name=name), self.assertRaises(
                ftp_server.UploadPolicyError
            ):
                ftp_server.normalize_requested_filename(
                    name,
                    frozenset({"jpg", "arw"}),
                    200,
                )

    def test_rejects_overlong_name(self) -> None:
        with self.assertRaises(ftp_server.UploadPolicyError):
            ftp_server.normalize_requested_filename(
                f"{'A' * 200}.JPG",
                frozenset({"jpg"}),
                100,
            )


class ReservationTests(unittest.TestCase):
    def test_collision_commit_never_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "DSC00001.JPG"
            original.write_bytes(b"existing")

            final_path, reservation_path = ftp_server.reserve_destination(
                root,
                original.name,
            )
            self.assertEqual(final_path.name, "DSC00001_1.JPG")
            self.assertTrue(reservation_path.exists())

            temporary_path = root / ".upload-test.part"
            temporary_path.write_bytes(b"new")
            pending = ftp_server.PendingUpload(
                requested_name=original.name,
                final_path=final_path,
                reservation_path=reservation_path,
                temporary_path=temporary_path,
            )

            committed = ftp_server.commit_pending_upload(pending)
            self.assertEqual(original.read_bytes(), b"existing")
            self.assertEqual(committed.read_bytes(), b"new")
            self.assertFalse(temporary_path.exists())
            self.assertFalse(reservation_path.exists())

    def test_safe_store_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaises(ftp_server.ConfigError):
                ftp_server.SafeStagingStore(link)

    def test_safe_store_treats_symlink_name_as_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.JPG"
            target.write_bytes(b"target")
            symlink = root / "DSC00001.JPG"
            try:
                symlink.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            store = ftp_server.SafeStagingStore(root)
            try:
                final_path, reservation_path = store.reserve("DSC00001.JPG")
                self.assertEqual(final_path.name, "DSC00001_1.JPG")
                self.assertTrue(reservation_path.exists())
                store.release(reservation_path)
            finally:
                store.close()


class LoginRateLimiterTests(unittest.TestCase):
    def test_blocks_and_expires_cross_connection_failures(self) -> None:
        now = [100.0]
        limiter = ftp_server.LoginRateLimiter(
            failure_limit=3,
            window_seconds=60,
            ban_seconds=120,
            clock=lambda: now[0],
        )

        self.assertFalse(limiter.record_failure("192.0.2.10"))
        self.assertFalse(limiter.record_failure("192.0.2.10"))
        self.assertTrue(limiter.record_failure("192.0.2.10"))
        self.assertTrue(limiter.is_blocked("192.0.2.10"))

        now[0] += 121
        self.assertFalse(limiter.is_blocked("192.0.2.10"))

    def test_prunes_empty_entries_and_evicts_at_cap(self) -> None:
        now = [1.0]
        limiter = ftp_server.LoginRateLimiter(
            failure_limit=10,
            window_seconds=10,
            ban_seconds=30,
            max_tracked_ips=3,
            clock=lambda: now[0],
        )
        limiter.record_failure("192.0.2.1")
        now[0] = 2.0
        limiter.record_failure("192.0.2.2")
        now[0] = 3.0
        limiter.record_failure("192.0.2.3")
        now[0] = 4.0
        limiter.record_failure("192.0.2.4")
        self.assertLessEqual(
            len(limiter._failures) + len(limiter._blocked_until),
            3,
        )

        now[0] = 100.0
        limiter.is_blocked("192.0.2.4")
        self.assertNotIn("192.0.2.1", limiter._failures)


class DiskGuardTests(unittest.TestCase):
    def test_rejects_upload_when_free_space_is_too_low(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = replace(make_config(root), min_free_bytes=10 * 1024 * 1024)
            store = ftp_server.SafeStagingStore(root)
            handler_cls = ftp_server.build_handler(config, staging_store=store)
            handler = object.__new__(handler_cls)
            handler.config = config
            handler.staging_store = store
            handler.remote_ip = "127.0.0.1"
            handler._restart_position = 0
            handler._pending_uploads = {}
            handler.fs = type("FS", (), {"root": str(root)})()
            responses: list[str] = []
            handler.respond = responses.append  # type: ignore[method-assign]

            original = ftp_server.SafeStagingStore.has_min_free_space

            def fake_has_space(_self, minimum_bytes: int) -> bool:
                del minimum_bytes
                return False

            ftp_server.SafeStagingStore.has_min_free_space = fake_has_space  # type: ignore[method-assign]
            try:
                result = handler.ftp_STOR(str(root / "DSC00001.JPG"), mode="w")
            finally:
                ftp_server.SafeStagingStore.has_min_free_space = original  # type: ignore[method-assign]
                store.close()

            self.assertIsNone(result)
            self.assertTrue(
                any(message.startswith("452 ") for message in responses),
                responses,
            )


class BannerAndSslContextTests(unittest.TestCase):
    def test_banner_is_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            handler = ftp_server.build_handler(make_config(Path(directory)))
            self.assertEqual(handler.banner, ftp_server.SecurityDefaults.BANNER)
            self.assertNotIn("Sony", handler.banner)

    def test_tls_context_is_rebuilt_for_different_configs(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        def write_cert(directory: Path) -> tuple[Path, Path]:
            certificate_path = directory / "server.crt"
            key_path = directory / "server.key"
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
            )
            now = datetime.now(timezone.utc)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                    ),
                    critical=False,
                )
                .sign(private_key, hashes.SHA256())
            )
            certificate_path.write_bytes(
                certificate.public_bytes(serialization.Encoding.PEM)
            )
            key_path.write_bytes(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            return certificate_path, key_path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_dir = root / "a"
            second_dir = root / "b"
            first_dir.mkdir()
            second_dir.mkdir()
            cert_a, key_a = write_cert(first_dir)
            cert_b, key_b = write_cert(second_dir)

            handler_a = ftp_server.build_handler(
                replace(
                    make_config(first_dir),
                    allow_plaintext=False,
                    cert_file=cert_a,
                    key_file=key_a,
                )
            )
            context_a = handler_a.get_ssl_context()
            handler_b = ftp_server.build_handler(
                replace(
                    make_config(second_dir),
                    allow_plaintext=False,
                    cert_file=cert_b,
                    key_file=key_b,
                )
            )
            context_b = handler_b.get_ssl_context()
            self.assertIsNot(context_a, context_b)


class HandlerPolicyTests(unittest.TestCase):
    def test_only_safe_protocol_commands_are_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            handler = ftp_server.build_handler(make_config(Path(directory)))
            for command in ftp_server.BLOCKED_COMMANDS:
                self.assertNotIn(command, handler.proto_cmds)
            self.assertNotIn("PORT", handler.proto_cmds)
            self.assertNotIn("EPRT", handler.proto_cmds)
            self.assertIn("STOR", handler.proto_cmds)
            self.assertNotIn("RETR", handler.proto_cmds)


class PlainFtpIntegrationTests(unittest.TestCase):
    """Plaintext is used only to test policy without certificate fixtures."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        config = make_config(self.root)
        handler = ftp_server.build_handler(config)
        handler.passive_ports = None
        self.server = ftp_server.FTPServer(("127.0.0.1", 0), handler)
        self.server.max_cons = config.max_connections
        self.server.max_cons_per_ip = config.max_connections_per_ip
        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"timeout": 0.05, "blocking": True, "handle_exit": False},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.close_all()
        self.thread.join(timeout=2)
        self.temporary_directory.cleanup()

    def connect(self) -> ftplib.FTP:
        client = ftplib.FTP()
        client.connect("127.0.0.1", self.port, timeout=3)
        client.login("camera_test_7x", "correct-horse-battery-staple")
        return client

    def wait_for(self, path: Path) -> None:
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(path.exists(), f"{path} was not committed")

    def test_upload_collision_and_destructive_commands(self) -> None:
        client = self.connect()
        try:
            client.storbinary("STOR DSC00001.JPG", io.BytesIO(b"first"))
            self.wait_for(self.root / "DSC00001.JPG")
            client.storbinary("STOR DSC00001.JPG", io.BytesIO(b"second"))
            self.wait_for(self.root / "DSC00001_1.JPG")

            self.assertEqual((self.root / "DSC00001.JPG").read_bytes(), b"first")
            self.assertEqual((self.root / "DSC00001_1.JPG").read_bytes(), b"second")

            with self.assertRaises(ftplib.error_perm):
                client.delete("DSC00001.JPG")
            with self.assertRaises(ftplib.error_perm):
                client.rename("DSC00001.JPG", "renamed.JPG")
            with self.assertRaises(ftplib.error_perm):
                client.retrbinary("RETR DSC00001.JPG", lambda _: None)
            with self.assertRaises(ftplib.error_perm):
                client.storbinary("APPE DSC00001.JPG", io.BytesIO(b"append"))

            self.assertEqual((self.root / "DSC00001.JPG").read_bytes(), b"first")
        finally:
            client.close()

    def test_rejects_traversal_and_unapproved_extension(self) -> None:
        client = self.connect()
        try:
            with self.assertRaises(ftplib.error_perm):
                client.storbinary("STOR ../outside.jpg", io.BytesIO(b"bad"))
            with self.assertRaises(ftplib.error_perm):
                client.storbinary("STOR payload.exe", io.BytesIO(b"bad"))
        finally:
            client.close()

        self.assertFalse((self.root.parent / "outside.jpg").exists())
        self.assertFalse((self.root / "payload.exe").exists())


class FtpsIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        certificate_path = self.root / "server.crt"
        key_path = self.root / "server.key"

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        config = replace(
            make_config(self.root),
            allow_plaintext=False,
            cert_file=certificate_path,
            key_file=key_path,
        )
        handler = ftp_server.build_handler(config)
        handler.passive_ports = None
        self.server = ftp_server.FTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.socket.getsockname()[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"timeout": 0.05, "blocking": True, "handle_exit": False},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.close_all()
        self.thread.join(timeout=2)
        self.temporary_directory.cleanup()

    def test_requires_tls_for_credentials_and_file_data(self) -> None:
        plaintext_client = ftplib.FTP()
        plaintext_client.connect("127.0.0.1", self.port, timeout=3)
        try:
            with self.assertRaises(ftplib.error_perm):
                plaintext_client.login(
                    "camera_test_7x",
                    "correct-horse-battery-staple",
                )
        finally:
            plaintext_client.close()

        tls_client = ftplib.FTP_TLS(context=ssl._create_unverified_context())
        tls_client.connect("127.0.0.1", self.port, timeout=3)
        try:
            tls_client.login(
                "camera_test_7x",
                "correct-horse-battery-staple",
            )
            tls_client.prot_p()
            tls_client.storbinary("STOR DSC09999.JPG", io.BytesIO(b"encrypted"))
        finally:
            tls_client.close()

        destination = self.root / "DSC09999.JPG"
        deadline = time.monotonic() + 2
        while not destination.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(destination.read_bytes(), b"encrypted")


if __name__ == "__main__":
    unittest.main()
