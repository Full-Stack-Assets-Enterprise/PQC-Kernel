from __future__ import annotations

import unittest
from pathlib import Path

from pqc_evidence.canonical import sha256_bytes
from pqc_evidence.rules import load_policy, load_rules
from pqc_evidence.policy import evaluate_observation
from pqc_evidence.source_detector import detect_source

FIXTURES = Path(__file__).parent / "fixtures" / "source"


class SourceDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = load_rules()

    def _scan(self, name: str):
        content = (FIXTURES / name).read_bytes()
        return detect_source(
            content_bytes=content,
            artifact_digest=sha256_bytes(content),
            artifact_path=name,
            scan_id="scan-test",
            ruleset=self.rules,
            observed_at="2026-08-29T00:00:00Z",
            include_snippets=False,
        )

    def test_positive_fixture_resolves_exact_and_argument_bound_algorithms(self) -> None:
        result = self._scan("positive.c")
        algorithms = [item.normalized_claim["algorithm"] for item in result.observations]
        symbols = [item.normalized_claim["symbol"] for item in result.observations]
        self.assertEqual(result.coverage.status, "FULL")
        self.assertCountEqual(
            symbols,
            [
                "RSA_sign",
                "EVP_PKEY_CTX_new_id",
                "EVP_PKEY_CTX_new_from_name",
                "EVP_PKEY_derive",
                "ECDSA_do_sign",
                "C_GenerateKeyPair",
            ],
        )
        self.assertIn("RSA", algorithms)
        self.assertIn("ML-KEM", algorithms)
        self.assertIn("ECDSA", algorithms)
        self.assertIn("UNKNOWN_HSM_PUBLIC_KEY", algorithms)
        self.assertIn("UNKNOWN_KEY_ESTABLISHMENT", algorithms)
        self.assertEqual(30, len(self.rules.rules))

    def test_comments_literals_declarations_and_macro_definitions_do_not_match(self) -> None:
        result = self._scan("negative.c")
        self.assertEqual([], result.observations)

    def test_policy_never_labels_pqc_reference_compliant(self) -> None:
        result = self._scan("positive.c")
        policy = load_policy()
        ml_kem = next(
            item for item in result.observations if item.normalized_claim["algorithm"] == "ML-KEM"
        )
        evaluation = evaluate_observation(ml_kem, policy, "2026-08-29T00:00:00Z")
        self.assertEqual("PQC_CANDIDATE_DETECTED", evaluation.status)
        self.assertNotIn("COMPLIANT", evaluation.status)
        self.assertTrue(evaluation.applicability_required)


if __name__ == "__main__":
    unittest.main()
