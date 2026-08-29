"""Evidence bundle integrity and semantic-ID verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_json, iter_jsonl, sha256_bytes, sha256_file, stable_id
from .models import expected_record_id

RECORD_FILES = {
    "observations.jsonl": ("observation_id", "observations"),
    "coverage.jsonl": ("coverage_id", "coverage"),
    "policy_evaluations.jsonl": ("policy_evaluation_id", "policy_evaluations"),
}


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    issues: list[str]
    verified_files: int
    verified_records: int
    integrity_receipt: str | None


def verify_bundle(
    bundle_path: Path, expected_receipt: str | None = None
) -> VerificationResult:
    bundle_path = bundle_path.resolve()
    issues: list[str] = []
    verified_files = 0
    verified_records = 0
    integrity_path = bundle_path / "integrity.json"
    manifest_path = bundle_path / "scan_manifest.json"
    if not bundle_path.is_dir():
        return VerificationResult(False, ["bundle path is not a directory"], 0, 0, None)
    try:
        integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return VerificationResult(False, [f"bundle metadata unreadable: {exc}"], 0, 0, None)

    actual_receipt = sha256_file(integrity_path)
    if expected_receipt is not None and actual_receipt != expected_receipt:
        issues.append("integrity receipt mismatch")

    integrity_files = integrity.get("files")
    if not isinstance(integrity_files, dict):
        return VerificationResult(
            False,
            ["integrity files field must be an object"],
            0,
            0,
            actual_receipt,
        )
    expected_names = set(integrity_files) | {"integrity.json"}
    actual_names = {path.name for path in bundle_path.iterdir()}
    unexpected = actual_names - expected_names
    missing = expected_names - actual_names
    if unexpected:
        issues.append(f"unexpected bundle file(s): {sorted(unexpected)}")
    if missing:
        issues.append(f"missing bundle file(s): {sorted(missing)}")

    for name, expected in integrity_files.items():
        if Path(name).name != name:
            issues.append(f"unsafe integrity path: {name!r}")
            continue
        path = bundle_path / name
        if not path.is_file():
            continue
        if not isinstance(expected, dict):
            issues.append(f"invalid integrity entry: {name}")
            continue
        actual_digest = sha256_file(path)
        actual_size = path.stat().st_size
        if actual_digest != expected.get("digest"):
            issues.append(f"digest mismatch: {name}")
        elif actual_size != expected.get("size"):
            issues.append(f"size mismatch: {name}")
        else:
            verified_files += 1

    if integrity.get("bundle_id") != manifest.get("bundle_id"):
        issues.append("bundle_id mismatch between integrity and scan manifest")

    for snapshot_name, manifest_field in (
        ("detector_rules.json", "ruleset"),
        ("policy_profile.json", "policy"),
    ):
        try:
            snapshot = json.loads((bundle_path / snapshot_name).read_text(encoding="utf-8"))
            snapshot_digest = sha256_bytes(canonical_json(snapshot).encode("utf-8"))
            if snapshot_digest != manifest[manifest_field]["digest"]:
                issues.append(f"{snapshot_name}: canonical digest does not match manifest")
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            issues.append(f"{snapshot_name}: snapshot verification failed: {exc}")

    scan_id = manifest.get("scan_id")
    expected_counts = manifest.get("record_counts", {})
    observation_ids: set[str] = set()
    coverage_ids: set[str] = set()
    policy_observation_ids: list[str] = []
    for filename, (id_field, count_field) in RECORD_FILES.items():
        path = bundle_path / filename
        if not path.is_file():
            continue
        count = 0
        ids_in_file: set[str] = set()
        try:
            for record in iter_jsonl(path):
                count += 1
                expected_type = {
                    "observations.jsonl": "observation",
                    "coverage.jsonl": "coverage",
                    "policy_evaluations.jsonl": "policy_evaluation",
                }[filename]
                if record.get("record_type") != expected_type:
                    issues.append(f"{filename}:{count}: record_type mismatch")
                if record.get("scan_id") != scan_id:
                    issues.append(f"{filename}:{count}: scan_id mismatch")
                try:
                    expected_id = expected_record_id(record)
                except (KeyError, TypeError, ValueError) as exc:
                    issues.append(f"{filename}:{count}: invalid record: {exc}")
                    continue
                if record.get(id_field) != expected_id:
                    issues.append(f"{filename}:{count}: deterministic ID mismatch")
                else:
                    verified_records += 1
                record_id = record.get(id_field)
                if record_id in ids_in_file:
                    issues.append(f"{filename}:{count}: duplicate record ID")
                elif isinstance(record_id, str):
                    ids_in_file.add(record_id)
                if filename == "observations.jsonl" and isinstance(record_id, str):
                    observation_ids.add(record_id)
                if filename == "coverage.jsonl" and isinstance(record_id, str):
                    coverage_ids.add(record_id)
                if filename == "policy_evaluations.jsonl":
                    policy_observation_ids.append(str(record.get("observation_id", "")))
        except (OSError, ValueError) as exc:
            issues.append(str(exc))
            continue
        if count != expected_counts.get(count_field):
            issues.append(
                f"{filename}: record count {count} != manifest {expected_counts.get(count_field)!r}"
            )
    missing_policy_targets = sorted(set(policy_observation_ids) - observation_ids)
    if missing_policy_targets:
        issues.append(f"policy evaluations reference missing observations: {missing_policy_targets}")
    if sorted(policy_observation_ids) != sorted(observation_ids):
        issues.append("policy evaluation coverage is not one-to-one with observations")
    try:
        expected_bundle_id = stable_id(
            "bundle",
            {
                "scan_id": scan_id,
                "ruleset_digest": manifest["ruleset"]["digest"],
                "policy_digest": manifest["policy"]["digest"],
                "observation_ids": sorted(observation_ids),
                "coverage_ids": sorted(coverage_ids),
            },
        )
        if manifest.get("bundle_id") != expected_bundle_id:
            issues.append("bundle_id does not match the verified evidence identity set")
    except (KeyError, TypeError) as exc:
        issues.append(f"bundle identity could not be verified: {exc}")
    return VerificationResult(
        not issues,
        issues,
        verified_files,
        verified_records,
        actual_receipt,
    )
