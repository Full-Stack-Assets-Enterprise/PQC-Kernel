from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pqc_evidence.canonical import sha256_file
from pqc_evidence.elf_detector import detect_elf
from pqc_evidence.rules import load_rules


@unittest.skipUnless(shutil.which("cc") and shutil.which("readelf"), "cc/readelf required")
class ElfDetectorTests(unittest.TestCase):
    def test_dynamic_import_is_detected_without_external_crypto_library(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider_source = root / "provider.c"
            app_source = root / "app.c"
            provider_source.write_text("int RSA_sign(void) { return 0; }\n", encoding="utf-8")
            app_source.write_text(
                "extern int RSA_sign(void); int main(void) { return RSA_sign(); }\n",
                encoding="utf-8",
            )
            library = root / "libfixturecrypto.so"
            app = root / "fixture-app"
            subprocess.run(
                ["cc", "-fPIC", "-shared", str(provider_source), "-o", str(library)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "cc",
                    str(app_source),
                    "-L",
                    str(root),
                    "-lfixturecrypto",
                    "-Wl,-rpath,$ORIGIN",
                    "-o",
                    str(app),
                ],
                check=True,
                capture_output=True,
            )
            result = detect_elf(
                file_path=app,
                artifact_digest=sha256_file(app),
                artifact_path="fixture-app",
                scan_id="scan-elf-test",
                ruleset=load_rules(),
                observed_at="2026-08-29T00:00:00Z",
            )
            self.assertIn(result.coverage.status, {"FULL", "PARTIAL"})
            self.assertEqual(
                ["RSA_sign"],
                [item.normalized_claim["symbol"] for item in result.observations],
            )
            self.assertEqual(
                "LINKED_REFERENCE", result.observations[0].normalized_claim["usage_state"]
            )


if __name__ == "__main__":
    unittest.main()
