from __future__ import annotations

import unittest

from pqc_evidence.models import Observation, expected_record_id


class ObservationModelTests(unittest.TestCase):
    def _observation(self, scan_id: str, timestamp: str) -> Observation:
        return Observation.build(
            scan_id=scan_id,
            detector_id="openssl.rsa_sign",
            detector_version="0.1.0",
            artifact_digest="sha256:" + "a" * 64,
            artifact_path="src/main.c",
            location={"kind": "SOURCE", "line": 4, "column": 5},
            method="SOURCE_LEXICAL_CALL",
            normalized_claim={
                "algorithm": "RSA",
                "primitive_family": "DIGITAL_SIGNATURE",
                "operation": "SIGN",
                "provider": "OPENSSL",
                "symbol": "RSA_sign",
                "usage_state": "UNRESOLVED",
                "assurance": "API_REFERENCE_ONLY",
            },
            confidence_score=0.98,
            confidence_basis="test",
            evidence={"matched_symbol": "RSA_sign", "call_token_digest": "sha256:" + "b" * 64},
            observed_at=timestamp,
        )

    def test_observation_id_is_stable_across_scan_sessions(self) -> None:
        first = self._observation("scan-a", "2026-08-29T00:00:00Z")
        second = self._observation("scan-b", "2026-08-30T00:00:00Z")
        self.assertEqual(first.observation_id, second.observation_id)

    def test_expected_record_id_detects_semantic_tampering(self) -> None:
        record = self._observation("scan-a", "2026-08-29T00:00:00Z").to_dict()
        self.assertEqual(record["observation_id"], expected_record_id(record))
        record["normalized_claim"]["algorithm"] = "ECDSA"
        self.assertNotEqual(record["observation_id"], expected_record_id(record))

    def test_invalid_digest_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Observation.build(
                scan_id="scan",
                detector_id="detector",
                detector_version="0.1.0",
                artifact_digest="not-a-digest",
                artifact_path="main.c",
                location={"kind": "SOURCE", "line": 1, "column": 1},
                method="TEST",
                normalized_claim={},
                confidence_score=0.5,
                confidence_basis="test",
                evidence={},
                observed_at="2026-08-29T00:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()

