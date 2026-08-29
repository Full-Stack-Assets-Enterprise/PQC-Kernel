"""ELF dynamic-import detector backed by the system readelf utility."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_bytes
from .models import CoverageRecord, Observation
from .rules import RuleSet

DETECTOR_ID = "elf.dynamic-import"


@dataclass(frozen=True)
class ElfDetectionResult:
    observations: list[Observation]
    coverage: CoverageRecord


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _failed_coverage(
    *,
    scan_id: str,
    ruleset: RuleSet,
    artifact_digest: str,
    artifact_path: str,
    observed_at: str,
    reason_code: str,
    note: str,
) -> ElfDetectionResult:
    return ElfDetectionResult(
        observations=[],
        coverage=CoverageRecord.build(
            scan_id=scan_id,
            detector_id=DETECTOR_ID,
            detector_version=ruleset.version,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            status="FAILED",
            reason_code=reason_code,
            bytes_analyzed=0,
            lost_symbols=False,
            notes=[note],
            recorded_at=observed_at,
        ),
    )


def detect_elf(
    *,
    file_path: Path,
    artifact_digest: str,
    artifact_path: str,
    scan_id: str,
    ruleset: RuleSet,
    observed_at: str,
    timeout_seconds: int = 30,
) -> ElfDetectionResult:
    readelf = shutil.which("readelf")
    artifact_size = file_path.stat().st_size
    if not readelf:
        return _failed_coverage(
            scan_id=scan_id,
            ruleset=ruleset,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            observed_at=observed_at,
            reason_code="TOOL_UNAVAILABLE",
            note="readelf was not available in PATH; no binary inference was made.",
        )

    try:
        header = subprocess.run(
            [readelf, "--wide", "--file-header", str(file_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return _failed_coverage(
            scan_id=scan_id,
            ruleset=ruleset,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            observed_at=observed_at,
            reason_code="TOOL_TIMEOUT",
            note=f"readelf exceeded the {timeout_seconds}-second analysis limit.",
        )

    if header.returncode != 0:
        detail = (header.stderr or "readelf failed").strip().replace(
            str(file_path), artifact_path
        )
        return _failed_coverage(
            scan_id=scan_id,
            ruleset=ruleset,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            observed_at=observed_at,
            reason_code="TOOL_ERROR",
            note=f"readelf did not complete: {detail[:240]}",
        )

    class_match = re.search(r"^\s*Class:\s*(?P<value>\S+)", header.stdout, re.MULTILINE)
    machine_match = re.search(
        r"^\s*Machine:\s*(?P<value>.+?)\s*$", header.stdout, re.MULTILINE
    )
    elf_class = class_match.group("value") if class_match else "UNKNOWN"
    machine = machine_match.group("value") if machine_match else "UNKNOWN"
    if elf_class != "ELF64" or "X86-64" not in machine.upper():
        return ElfDetectionResult(
            observations=[],
            coverage=CoverageRecord.build(
                scan_id=scan_id,
                detector_id=DETECTOR_ID,
                detector_version=ruleset.version,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                status="SKIPPED",
                reason_code="UNSUPPORTED_ELF_ARCHITECTURE",
                bytes_analyzed=artifact_size,
                lost_symbols=False,
                notes=[
                    f"Detected {elf_class} / {machine}; v0.1 is bounded to ELF64 x86-64."
                ],
                recorded_at=observed_at,
            ),
        )

    try:
        symbols = subprocess.run(
            [readelf, "--wide", "--dyn-syms", str(file_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        sections = subprocess.run(
            [readelf, "--wide", "--sections", str(file_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return _failed_coverage(
            scan_id=scan_id,
            ruleset=ruleset,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            observed_at=observed_at,
            reason_code="TOOL_TIMEOUT",
            note=f"readelf exceeded the {timeout_seconds}-second analysis limit.",
        )

    if symbols.returncode != 0 or sections.returncode != 0:
        detail = (symbols.stderr or sections.stderr or "readelf failed").strip()
        detail = detail.replace(str(file_path), artifact_path)
        return _failed_coverage(
            scan_id=scan_id,
            ruleset=ruleset,
            artifact_digest=artifact_digest,
            artifact_path=artifact_path,
            observed_at=observed_at,
            reason_code="TOOL_ERROR",
            note=f"readelf did not complete: {detail[:240]}",
        )

    has_dynsym = ".dynsym" in sections.stdout
    has_symtab = ".symtab" in sections.stdout
    symbol_map = ruleset.by_symbol
    observations: list[Observation] = []
    symbol_line = re.compile(
        r"^\s*(?P<index>\d+):\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+\S+\s+\S+\s+UND\s+(?P<name>\S+)"
    )
    seen: set[tuple[str, str]] = set()
    for raw_line in symbols.stdout.splitlines():
        match = symbol_line.match(raw_line)
        if not match:
            continue
        versioned_name = match.group("name")
        symbol = versioned_name.split("@", 1)[0]
        if symbol not in symbol_map:
            continue
        dedupe_key = (match.group("index"), symbol)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        rule = symbol_map[symbol]
        claim = {
            "algorithm": rule.algorithm,
            "primitive_family": rule.primitive_family,
            "operation": rule.operation,
            "provider": rule.provider,
            "symbol": rule.symbol,
            "usage_state": "LINKED_REFERENCE",
            "assurance": "DYNAMIC_IMPORT_ONLY",
        }
        observations.append(
            Observation.build(
                scan_id=scan_id,
                detector_id=rule.id,
                detector_version=ruleset.version,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                location={
                    "kind": "ELF_DYNAMIC_SYMBOL",
                    "symbol_index": int(match.group("index")),
                    "symbol": versioned_name,
                },
                method="ELF_UNDEFINED_DYNAMIC_SYMBOL",
                normalized_claim=claim,
                confidence_score=min(rule.confidence, 0.94),
                confidence_basis=(
                    "Exact supported symbol appeared as an undefined dynamic symbol. "
                    "This proves a link-time reference, not runtime execution or algorithm configuration."
                ),
                evidence={
                    "matched_symbol": symbol,
                    "versioned_symbol": versioned_name,
                    "symbol_table": ".dynsym",
                    "symbol_line_digest": sha256_bytes(raw_line.encode("utf-8")),
                },
                observed_at=observed_at,
            )
        )

    if not has_dynsym:
        status = "PARTIAL"
        reason_code = "NO_DYNAMIC_SYMBOL_TABLE"
        notes = [
            "No .dynsym section was available. Static linkage and implementation fingerprinting are out of scope."
        ]
    elif not has_symtab:
        status = "PARTIAL"
        reason_code = "SYMBOL_TABLE_STRIPPED"
        notes = [
            "Dynamic imports were inspected, but the regular symbol table is unavailable; static and internal crypto cannot be excluded."
        ]
    else:
        status = "FULL"
        reason_code = "ANALYSIS_COMPLETE"
        notes = [
            "Undefined dynamic symbols were inspected. Static linkage, dlopen/dlsym, inlining, and constant fingerprints remain out of scope."
        ]
    coverage = CoverageRecord.build(
        scan_id=scan_id,
        detector_id=DETECTOR_ID,
        detector_version=ruleset.version,
        artifact_digest=artifact_digest,
        artifact_path=artifact_path,
        status=status,
        reason_code=reason_code,
        bytes_analyzed=artifact_size,
        lost_symbols=not has_symtab,
        notes=notes,
        recorded_at=observed_at,
    )
    return ElfDetectionResult(observations=observations, coverage=coverage)
