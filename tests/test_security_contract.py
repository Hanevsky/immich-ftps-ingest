from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SecurityContractTests(unittest.TestCase):
    def test_compose_is_self_contained_for_portainer(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("sony_staging:/data:ro", compose)
        self.assertIn("internal: true", compose)
        self.assertGreaterEqual(compose.count("no-new-privileges:true"), 2)
        # Importer stays capability-dropped; FTP keeps defaults for volume mounts.
        self.assertGreaterEqual(compose.count("\n    cap_drop:"), 1)
        self.assertGreaterEqual(compose.count("read_only: true"), 2)
        self.assertIn("FTP_USERS", compose)
        self.assertIn("FTP_AUTO_GENERATE_CERT", compose)
        self.assertIn("IMMICH_API_KEY", compose)
        self.assertIn("IMMICH_HOST", compose)
        self.assertIn("immich_default", compose)
        self.assertIn("immich-ftps-server", compose)
        self.assertIn("immich-ftps-importer", compose)
        self.assertNotIn("./certs/", compose)
        self.assertNotIn("secrets:", compose)
        self.assertNotIn("FTP_USERS_FILE", compose)
        self.assertNotIn("./ftp_users.txt", compose)

    def test_ftp_service_cannot_read_immich_credentials(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        ftp_service = compose.split("  immich-importer:", maxsplit=1)[0]
        # Ignore file header comments; assert the FTP service env block.
        ftp_env = ftp_service.split("environment:", maxsplit=1)[1]
        self.assertNotIn("IMMICH_", ftp_env)
        self.assertNotIn("ca.key", ftp_service)

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
        self.assertRegex(importer, r"sync \"\$MANIFEST_FILE\"")
        self.assertIn("IMMICH_ALLOW_HTTP", importer)
        self.assertIn("IMMICH_HOST", importer)
        self.assertIn("IMMICH_CA_CERT_PEM", importer)
        self.assertIn("export IMMICH_INSTANCE_URL", importer)
        self.assertIn('--url "$IMMICH_INSTANCE_URL"', importer)
        self.assertIn('--key "$IMMICH_API_KEY"', importer)
        self.assertNotIn("FTP_USERS", importer)
        importer_dockerfile = (ROOT / "importer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(r"sed -i 's/\r$//'", importer_dockerfile)
        self.assertIn("--ignore-scripts", importer_dockerfile)

    def test_containers_run_as_non_root_in_images(self) -> None:
        ftp_dockerfile = (ROOT / "ftp-server" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("runuser -u app", (ROOT / "ftp-server" / "entrypoint.sh").read_text(encoding="utf-8"))
        self.assertIn("entrypoint.sh", ftp_dockerfile)
        importer_dockerfile = (ROOT / "importer" / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(importer_dockerfile, r"(?m)^USER 10001:10001$")

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
