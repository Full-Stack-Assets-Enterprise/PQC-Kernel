from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pqc_evidence.rules import load_policy, load_rules
from pqc_evidence.scanner import ScanOptions, create_scan_bundle
from pqc_evidence.verify import verify_bundle

FIXTURES = Path(__file__).parent / "fixtures" / "source"


class BundleTests(unittest.TestCase):
    def _create(self, destination: Path):
        return create_scan_bundle(
            target=FIXTURES,
            output=destination,
            ruleset=load_rules(),
            policy=load_policy(),
            options=ScanOptions(include_binaries=False, target_label="Golden source fixture"),
            scan_id="scan-golden-001",
        )

    def test_bundle_is_complete_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            result = self._create(bundle)
            self.assertEqual("PASS", result.manifest["status"])
            self.assertEqual(6, result.manifest["record_counts"]["observations"])
            self.assertEqual(
                {
                    "coverage.jsonl",
                    "detector_rules.json",
                    "dossier.md",
                    "integrity.json",
                    "observations.jsonl",
                    "policy_profile.json",
                    "policy_evaluations.jsonl",
                    "scan_manifest.json",
                },
                {path.name for path in bundle.iterdir()},
            )
            verification = verify_bundle(
                bundle, expected_receipt=result.integrity_receipt
            )
            self.assertTrue(verification.ok, verification.issues)
            self.assertEqual(7, verification.verified_files)
            self.assertEqual(14, verification.verified_records)
            self.assertEqual(result.integrity_receipt, verification.integrity_receipt)
            dossier = (bundle / "dossier.md").read_text(encoding="utf-8")
            self.assertIn("An absent finding is not proof", dossier)
            self.assertIn("applicability not established", dossier)

    def test_external_receipt_detects_substituted_integrity_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            self._create(bundle)
            verification = verify_bundle(bundle, expected_receipt="sha256:" + "0" * 64)
            self.assertFalse(verification.ok)
            self.assertIn("integrity receipt mismatch", verification.issues)

    def test_existing_bundle_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            self._create(bundle)
            with self.assertRaises(FileExistsError):
                self._create(bundle)

    def test_tampering_breaks_integrity_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            self._create(bundle)
            dossier = bundle / "dossier.md"
            dossier.write_text(dossier.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
            verification = verify_bundle(bundle)
            self.assertFalse(verification.ok)
            self.assertIn("digest mismatch: dossier.md", verification.issues)

    def test_unsupported_single_file_never_receives_pass_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "notes.txt"
            target.write_text("not source and not ELF\n", encoding="utf-8")
            result = create_scan_bundle(
                target=target,
                output=root / "bundle",
                ruleset=load_rules(),
                policy=load_policy(),
                options=ScanOptions(),
                scan_id="scan-unsupported-001",
            )
            self.assertEqual("NO_SUPPORTED_ARTIFACTS", result.manifest["status"])
            self.assertEqual(0, result.manifest["record_counts"]["coverage"])

    def test_symlink_scan_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "linked-target"
            link.symlink_to(FIXTURES, target_is_directory=True)
            with self.assertRaises(ValueError):
                create_scan_bundle(
                    target=link,
                    output=root / "bundle",
                    ruleset=load_rules(),
                    policy=load_policy(),
                    options=ScanOptions(include_binaries=False),
                    scan_id="scan-symlink-001",
                )


if __name__ == "__main__":
    unittest.main()
