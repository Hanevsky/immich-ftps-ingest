from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SecurityContractTests(unittest.TestCase):
    def test_compose_keeps_staging_read_only_for_importer(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("sony_staging:/data:ro", compose)
        self.assertIn("internal: true", compose)
        self.assertGreaterEqual(compose.count("no-new-privileges:true"), 2)
        self.assertGreaterEqual(compose.count("cap_drop:"), 2)
        self.assertGreaterEqual(compose.count("read_only: true"), 2)
        self.assertGreaterEqual(compose.count('user: "10001:10001"'), 2)
        self.assertIn("FTP_USERS", compose)
        self.assertIn("IMMICH_HOST", compose)
        self.assertIn("stop_grace_period: 15s", compose)
        self.assertIn("stop_grace_period: 60s", compose)
        self.assertIn("/state/last-cycle", compose)
        self.assertIn("immich_default", compose)
        self.assertIn("immich-ftps-server", compose)
        self.assertIn("immich-ftps-importer", compose)
        self.assertIn("GHCR_OWNER", compose)
        self.assertIn("FTP_USERS_FILE", compose)
        self.assertIn("IMMICH_API_KEY_FILE", compose)

    def test_ftp_service_cannot_read_ca_private_key_or_immich_credentials(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        ftp_service = compose.split("  immich-importer:", maxsplit=1)[0]
        self.assertIn("./certs/server.crt:/run/ftp-certs/server.crt:ro", ftp_service)
        self.assertIn("./certs/server.key:/run/ftp-certs/server.key:ro", ftp_service)
        self.assertNotIn("./certs:/run/ftp-certs", ftp_service)
        self.assertNotIn("ca.key", ftp_service)
        self.assertNotIn("IMMICH_", ftp_service)

    def test_compose_does_not_mount_or_configure_immich_database(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8").lower()
        forbidden = ("postgres", "database_url", "db_password", "/var/lib/postgresql")
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, compose)

    def test_importer_has_no_local_delete_flags(self) -> None:
        importer = (ROOT / "importer" / "import-loop.sh").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?m)^\s*(rm|unlink)\b", importer))
        self.assertNotIn("--delete", importer)
        self.assertNotIn("--delete-duplicates", importer)
        self.assertRegex(importer, r"''\|\.\*\|-\*\)")
        self.assertRegex(importer, r"conv=fsync|sync \"\$MANIFEST_FILE\"")
        self.assertIn("IMMICH_ALLOW_HTTP", importer)
        importer_dockerfile = (ROOT / "importer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(r"sed -i 's/\r$//'", importer_dockerfile)
        self.assertIn("--ignore-scripts", importer_dockerfile)
        self.assertIn("IMMICH_HOST", importer)

    def test_containers_run_as_non_root(self) -> None:
        for dockerfile in (
            ROOT / "ftp-server" / "Dockerfile",
            ROOT / "importer" / "Dockerfile",
        ):
            with self.subTest(dockerfile=dockerfile):
                contents = dockerfile.read_text(encoding="utf-8")
                self.assertRegex(contents, r"(?m)^USER 10001:10001$")

    def test_direct_dependencies_are_pinned(self) -> None:
        requirements = (
            ROOT / "ftp-server" / "requirements.txt"
        ).read_text(encoding="utf-8")
        for line in requirements.splitlines():
            if line.strip() and not line.startswith("#"):
                self.assertIn("==", line)

    def test_secrets_and_certificates_are_gitignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertRegex(gitignore, r"(?m)^\.env$")
        self.assertRegex(gitignore, r"(?m)^certs/\*$")
        self.assertRegex(gitignore, r"(?m)^immich-certs/\*$")
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertRegex(attributes, r"(?m)^\*\.sh text eol=lf$")


if __name__ == "__main__":
    unittest.main()
