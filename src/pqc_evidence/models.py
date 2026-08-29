"""Strict v0.1 evidence record models.

The internal representation is deliberately small and dependency-free. Stable
identifiers are derived from semantic identity fields, never timestamps or scan
session identifiers, so the same fact can be reconciled across scans.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .canonical import stable_id

SCHEMA_VERSION = "0.1.0"


def _validate_digest(value: str | None) -> None:
    if value is None:
        return
    prefix, separator, digest = value.partition(":")
    if prefix != "sha256" or separator != ":" or len(digest) != 64:
        raise ValueError("artifact_digest must be a sha256:<64 hex characters> value")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise ValueError("artifact_digest contains non-hexadecimal characters") from exc


def observation_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": record["schema_version"],
        "detector_id": record["detector_id"],
        "detector_version": record["detector_version"],
        "artifact_digest": record["artifact_digest"],
        "artifact_path": record["artifact_path"],
        "location": record["location"],
        "method": record["method"],
        "normalized_claim": record["normalized_claim"],
        "evidence": record["evidence"],
    }


def coverage_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": record["schema_version"],
        "detector_id": record["detector_id"],
        "detector_version": record["detector_version"],
        "artifact_digest": record.get("artifact_digest"),
        "artifact_path": record["artifact_path"],
        "status": record["status"],
        "reason_code": record["reason_code"],
        "bytes_analyzed": record["bytes_analyzed"],
        "lost_symbols": record["lost_symbols"],
        "notes": record["notes"],
    }


def policy_evaluation_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": record["schema_version"],
        "observation_id": record["observation_id"],
        "policy_profile_id": record["policy_profile_id"],
        "policy_version": record["policy_version"],
        "status": record["status"],
        "priority": record["priority"],
        "rationale": record["rationale"],
        "source_ids": record["source_ids"],
    }


def expected_record_id(record: Mapping[str, Any]) -> str:
    record_type = record.get("record_type")
    if record_type == "observation":
        return stable_id("obs", observation_identity(record))
    if record_type == "coverage":
        return stable_id("cov", coverage_identity(record))
    if record_type == "policy_evaluation":
        return stable_id("pol", policy_evaluation_identity(record))
    raise ValueError(f"unsupported record_type: {record_type!r}")


@dataclass(frozen=True)
class Observation:
    schema_version: str
    record_type: str
    observation_id: str
    scan_id: str
    detector_id: str
    detector_version: str
    artifact_digest: str
    artifact_path: str
    location: dict[str, Any]
    method: str
    normalized_claim: dict[str, Any]
    confidence: dict[str, Any]
    evidence: dict[str, Any]
    observed_at: str

    @classmethod
    def build(
        cls,
        *,
        scan_id: str,
        detector_id: str,
        detector_version: str,
        artifact_digest: str,
        artifact_path: str,
        location: dict[str, Any],
        method: str,
        normalized_claim: dict[str, Any],
        confidence_score: float,
        confidence_basis: str,
        evidence: dict[str, Any],
        observed_at: str,
    ) -> "Observation":
        _validate_digest(artifact_digest)
        if not 0.0 <= confidence_score <= 1.0:
            raise ValueError("confidence_score must be between 0 and 1")
        draft: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "observation",
            "scan_id": scan_id,
            "detector_id": detector_id,
            "detector_version": detector_version,
            "artifact_digest": artifact_digest,
            "artifact_path": artifact_path,
            "location": location,
            "method": method,
            "normalized_claim": normalized_claim,
            "confidence": {
                "score": round(confidence_score, 4),
                "basis": confidence_basis,
            },
            "evidence": evidence,
            "observed_at": observed_at,
        }
        draft["observation_id"] = stable_id("obs", observation_identity(draft))
        return cls(**draft)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageRecord:
    schema_version: str
    record_type: str
    coverage_id: str
    scan_id: str
    detector_id: str
    detector_version: str
    artifact_digest: str | None
    artifact_path: str
    status: str
    reason_code: str
    bytes_analyzed: int
    lost_symbols: bool
    notes: list[str]
    recorded_at: str

    @classmethod
    def build(
        cls,
        *,
        scan_id: str,
        detector_id: str,
        detector_version: str,
        artifact_digest: str | None,
        artifact_path: str,
        status: str,
        reason_code: str,
        bytes_analyzed: int,
        lost_symbols: bool,
        notes: list[str],
        recorded_at: str,
    ) -> "CoverageRecord":
        _validate_digest(artifact_digest)
        if status not in {"FULL", "PARTIAL", "FAILED", "SKIPPED"}:
            raise ValueError(f"unsupported coverage status: {status}")
        if bytes_analyzed < 0:
            raise ValueError("bytes_analyzed cannot be negative")
        draft: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "coverage",
            "scan_id": scan_id,
            "detector_id": detector_id,
            "detector_version": detector_version,
            "artifact_digest": artifact_digest,
            "artifact_path": artifact_path,
            "status": status,
            "reason_code": reason_code,
            "bytes_analyzed": bytes_analyzed,
            "lost_symbols": lost_symbols,
            "notes": notes,
            "recorded_at": recorded_at,
        }
        draft["coverage_id"] = stable_id("cov", coverage_identity(draft))
        return cls(**draft)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyEvaluation:
    schema_version: str
    record_type: str
    policy_evaluation_id: str
    scan_id: str
    observation_id: str
    policy_profile_id: str
    policy_version: str
    status: str
    priority: str
    rationale: str
    source_ids: list[str]
    applicability_required: bool
    evaluated_at: str

    @classmethod
    def build(
        cls,
        *,
        scan_id: str,
        observation_id: str,
        policy_profile_id: str,
        policy_version: str,
        status: str,
        priority: str,
        rationale: str,
        source_ids: list[str],
        evaluated_at: str,
    ) -> "PolicyEvaluation":
        draft: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "policy_evaluation",
            "scan_id": scan_id,
            "observation_id": observation_id,
            "policy_profile_id": policy_profile_id,
            "policy_version": policy_version,
            "status": status,
            "priority": priority,
            "rationale": rationale,
            "source_ids": source_ids,
            "applicability_required": True,
            "evaluated_at": evaluated_at,
        }
        draft["policy_evaluation_id"] = stable_id(
            "pol", policy_evaluation_identity(draft)
        )
        return cls(**draft)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

