"""Scan orchestration and write-once evidence bundle creation."""

from __future__ import annotations

import os
import platform
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import __version__
from .canonical import sha256_bytes, sha256_file, stable_id, write_json, write_jsonl
from .dossier import generate_dossier
from .elf_detector import DETECTOR_ID as ELF_DETECTOR_ID
from .elf_detector import detect_elf, is_elf
from .models import CoverageRecord, Observation, PolicyEvaluation
from .policy import evaluate_observation
from .rules import PolicyProfile, RuleSet
from .source_detector import DETECTOR_ID as SOURCE_DETECTOR_ID
from .source_detector import detect_source

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx"}
SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_scan_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"scan-{timestamp}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class ScanOptions:
    include_headers: bool = False
    include_binaries: bool = True
    include_snippets: bool = False
    max_file_bytes: int = 100 * 1024 * 1024
    target_label: str | None = None


@dataclass(frozen=True)
class ScanResult:
    bundle_path: Path
    manifest: dict[str, object]
    integrity_receipt: str


def _relative_label(path: Path, target: Path) -> str:
    if target.is_file():
        return target.name
    return path.relative_to(target).as_posix()


def _candidate_paths(target: Path) -> Iterable[Path]:
    if target.is_file() or target.is_symlink():
        yield target
        return
    for path in sorted(target.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if path.is_file() or path.is_symlink():
            yield path


def _binary_candidate(path: Path, target: Path) -> bool:
    if target.is_file():
        return True
    name = path.name.lower()
    return os.access(path, os.X_OK) or ".so" in name or name.endswith((".elf", ".bin"))


def _skipped_coverage(
    *,
    scan_id: str,
    detector_id: str,
    detector_version: str,
    artifact_path: str,
    reason_code: str,
    note: str,
    recorded_at: str,
    size: int = 0,
) -> CoverageRecord:
    return CoverageRecord.build(
        scan_id=scan_id,
        detector_id=detector_id,
        detector_version=detector_version,
        artifact_digest=None,
        artifact_path=artifact_path,
        status="SKIPPED",
        reason_code=reason_code,
        bytes_analyzed=0,
        lost_symbols=False,
        notes=[note, f"Candidate size: {size} byte(s)."],
        recorded_at=recorded_at,
    )


def _failed_read_coverage(
    *,
    scan_id: str,
    detector_id: str,
    detector_version: str,
    artifact_path: str,
    recorded_at: str,
    error: OSError,
) -> CoverageRecord:
    return CoverageRecord.build(
        scan_id=scan_id,
        detector_id=detector_id,
        detector_version=detector_version,
        artifact_digest=None,
        artifact_path=artifact_path,
        status="FAILED",
        reason_code="READ_ERROR",
        bytes_analyzed=0,
        lost_symbols=False,
        notes=[f"Artifact could not be read: {type(error).__name__}: {error}"],
        recorded_at=recorded_at,
    )


def create_scan_bundle(
    *,
    target: Path,
    output: Path,
    ruleset: RuleSet,
    policy: PolicyProfile,
    options: ScanOptions,
    scan_id: str | None = None,
) -> ScanResult:
    target = target.expanduser().absolute()
    if target.is_symlink():
        raise ValueError("the scan target cannot be a symlink")
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    if not target.is_file() and not target.is_dir():
        raise ValueError("scan target must be a regular file or directory")
    selected_scan_id = scan_id or new_scan_id()
    if not SCAN_ID_PATTERN.fullmatch(selected_scan_id):
        raise ValueError("scan_id may contain only letters, digits, period, underscore, and hyphen")
    if options.max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive")

    started_at = utc_now()
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []
    candidate_count = 0

    for path in _candidate_paths(target):
        artifact_path = _relative_label(path, target)
        suffix = path.suffix.lower()
        is_source = suffix in SOURCE_EXTENSIONS
        is_header = suffix in HEADER_EXTENSIONS
        may_be_binary = options.include_binaries and _binary_candidate(path, target)
        if not (is_source or is_header or may_be_binary):
            continue
        try:
            size = path.lstat().st_size
        except OSError:
            size = 0
        if path.is_symlink():
            candidate_count += 1
            detector_id = SOURCE_DETECTOR_ID if is_source or is_header else ELF_DETECTOR_ID
            coverage.append(
                _skipped_coverage(
                    scan_id=selected_scan_id,
                    detector_id=detector_id,
                    detector_version=ruleset.version,
                    artifact_path=artifact_path,
                    reason_code="SYMLINK_EXCLUDED",
                    note="Symlinks are excluded to prevent traversal outside the approved target root.",
                    recorded_at=started_at,
                    size=size,
                )
            )
            continue
        if is_header and not options.include_headers:
            candidate_count += 1
            coverage.append(
                _skipped_coverage(
                    scan_id=selected_scan_id,
                    detector_id=SOURCE_DETECTOR_ID,
                    detector_version=ruleset.version,
                    artifact_path=artifact_path,
                    reason_code="HEADER_EXCLUDED",
                    note="Header scanning was not enabled; declarations otherwise inflate lexical findings.",
                    recorded_at=started_at,
                    size=size,
                )
            )
            continue
        binary_is_elf = may_be_binary and not (is_source or is_header) and is_elf(path)
        if not (is_source or is_header or binary_is_elf):
            continue
        candidate_count += 1
        if size > options.max_file_bytes:
            detector_id = SOURCE_DETECTOR_ID if is_source or is_header else ELF_DETECTOR_ID
            coverage.append(
                _skipped_coverage(
                    scan_id=selected_scan_id,
                    detector_id=detector_id,
                    detector_version=ruleset.version,
                    artifact_path=artifact_path,
                    reason_code="SIZE_LIMIT",
                    note=f"Artifact exceeded the configured {options.max_file_bytes}-byte safety limit.",
                    recorded_at=started_at,
                    size=size,
                )
            )
            continue

        if is_source or is_header:
            try:
                content_bytes = path.read_bytes()
            except OSError as exc:
                coverage.append(
                    _failed_read_coverage(
                        scan_id=selected_scan_id,
                        detector_id=SOURCE_DETECTOR_ID,
                        detector_version=ruleset.version,
                        artifact_path=artifact_path,
                        recorded_at=started_at,
                        error=exc,
                    )
                )
                continue
            artifact_digest = sha256_bytes(content_bytes)
            result = detect_source(
                content_bytes=content_bytes,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                scan_id=selected_scan_id,
                ruleset=ruleset,
                observed_at=started_at,
                include_snippets=options.include_snippets,
            )
            observations.extend(result.observations)
            coverage.append(result.coverage)
            continue

        if binary_is_elf:
            try:
                artifact_digest = sha256_file(path)
            except OSError as exc:
                coverage.append(
                    _failed_read_coverage(
                        scan_id=selected_scan_id,
                        detector_id=ELF_DETECTOR_ID,
                        detector_version=ruleset.version,
                        artifact_path=artifact_path,
                        recorded_at=started_at,
                        error=exc,
                    )
                )
                continue
            result = detect_elf(
                file_path=path,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                scan_id=selected_scan_id,
                ruleset=ruleset,
                observed_at=started_at,
            )
            observations.extend(result.observations)
            coverage.append(result.coverage)

    observations.sort(
        key=lambda item: (
            item.artifact_path,
            str(item.location),
            item.detector_id,
            item.observation_id,
        )
    )
    coverage.sort(key=lambda item: (item.artifact_path, item.detector_id, item.coverage_id))
    evaluations: list[PolicyEvaluation] = [
        evaluate_observation(observation, policy, started_at)
        for observation in observations
    ]
    completed_at = utc_now()
    has_gaps = any(record.status != "FULL" for record in coverage)
    if not coverage:
        status = "NO_SUPPORTED_ARTIFACTS"
    else:
        status = "COMPLETED_WITH_GAPS" if has_gaps else "PASS"
    manifest: dict[str, object] = {
        "schema_version": "0.1.0",
        "scan_id": selected_scan_id,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "engine": {"name": "pqc-evidence-kernel", "version": __version__},
        "ruleset": {"id": ruleset.id, "version": ruleset.version, "digest": ruleset.digest},
        "policy": {"id": policy.id, "version": policy.version, "digest": policy.digest},
        "target": {
            "label": options.target_label or target.name,
            "kind": "file" if target.is_file() else "directory",
            "candidate_count": candidate_count,
        },
        "scope": {
            "source_extensions": sorted(SOURCE_EXTENSIONS),
            "header_extensions": sorted(HEADER_EXTENSIONS) if options.include_headers else [],
            "include_binaries": options.include_binaries,
            "include_snippets": options.include_snippets,
            "max_file_bytes": options.max_file_bytes,
        },
        "record_counts": {
            "observations": len(observations),
            "coverage": len(coverage),
            "policy_evaluations": len(evaluations),
        },
        "environment": {
            "os": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "interpretation_boundary": (
            "Evidence records supported API references and detector coverage only; "
            "runtime use, cryptographic absence, regulatory applicability, and compliance are not inferred."
        ),
    }
    manifest["bundle_id"] = stable_id(
        "bundle",
        {
            "scan_id": selected_scan_id,
            "ruleset_digest": ruleset.digest,
            "policy_digest": policy.digest,
            "observation_ids": sorted(item.observation_id for item in observations),
            "coverage_ids": sorted(item.coverage_id for item in coverage),
        },
    )
    dossier = generate_dossier(
        manifest=manifest,
        observations=observations,
        coverage=coverage,
        evaluations=evaluations,
        policy=policy,
    )

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "scan_manifest.json", manifest)
    write_json(output / "detector_rules.json", ruleset.raw)
    write_json(output / "policy_profile.json", policy.raw)
    write_jsonl(output / "observations.jsonl", (item.to_dict() for item in observations))
    write_jsonl(output / "coverage.jsonl", (item.to_dict() for item in coverage))
    write_jsonl(
        output / "policy_evaluations.jsonl", (item.to_dict() for item in evaluations)
    )
    with (output / "dossier.md").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(dossier)

    integrity_files = {}
    for name in (
        "scan_manifest.json",
        "detector_rules.json",
        "policy_profile.json",
        "observations.jsonl",
        "coverage.jsonl",
        "policy_evaluations.jsonl",
        "dossier.md",
    ):
        path = output / name
        integrity_files[name] = {"digest": sha256_file(path), "size": path.stat().st_size}
    integrity = {
        "schema_version": "0.1.0",
        "bundle_id": manifest["bundle_id"],
        "algorithm": "SHA-256",
        "files": integrity_files,
        "created_at": completed_at,
    }
    write_json(output / "integrity.json", integrity)
    integrity_receipt = sha256_file(output / "integrity.json")
    return ScanResult(
        bundle_path=output,
        manifest=manifest,
        integrity_receipt=integrity_receipt,
    )
