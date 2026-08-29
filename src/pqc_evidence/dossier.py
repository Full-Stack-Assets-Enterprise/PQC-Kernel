"""Human-readable projection of a completed evidence scan."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from .models import CoverageRecord, Observation, PolicyEvaluation
from .rules import PolicyProfile


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: Iterable[Iterable[object]]) -> list[str]:
    output = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    output.extend(
        "| " + " | ".join(_escape(value) for value in row) + " |" for row in rows
    )
    return output


def generate_dossier(
    *,
    manifest: dict[str, Any],
    observations: list[Observation],
    coverage: list[CoverageRecord],
    evaluations: list[PolicyEvaluation],
    policy: PolicyProfile,
) -> str:
    evaluation_by_observation = {
        evaluation.observation_id: evaluation for evaluation in evaluations
    }
    status_counts = Counter(evaluation.status for evaluation in evaluations)
    coverage_counts = Counter(record.status for record in coverage)
    algorithm_counts = Counter(
        observation.normalized_claim["algorithm"] for observation in observations
    )
    findings_by_priority: dict[str, list[tuple[Observation, PolicyEvaluation]]] = defaultdict(list)
    for observation in observations:
        evaluation = evaluation_by_observation[observation.observation_id]
        findings_by_priority[evaluation.priority].append((observation, evaluation))

    lines: list[str] = [
        "# Cryptographic Discovery Evidence Dossier",
        "",
        "**Customer Confidential — Assessment Draft**",
        "",
        f"- Scan ID: `{manifest['scan_id']}`",
        f"- Engine: `{manifest['engine']['name']} {manifest['engine']['version']}`",
        f"- Rules: `{manifest['ruleset']['id']} {manifest['ruleset']['version']}`",
        f"- Policy projection: `{manifest['policy']['id']} {manifest['policy']['version']}`",
        f"- Target label: `{manifest['target']['label']}`",
        f"- Completed: `{manifest['completed_at']}`",
        f"- Gate status: **{manifest['status']}**",
        "",
        "## Executive Summary",
        "",
        (
            f"The assessment produced **{len(observations)} atomic observation(s)** "
            f"across **{len(coverage)} coverage record(s)**. "
            f"{coverage_counts.get('FULL', 0)} artifact-detector result(s) completed "
            f"at full v0.1 scope, {coverage_counts.get('PARTIAL', 0)} were partial, "
            f"{coverage_counts.get('FAILED', 0)} failed, and "
            f"{coverage_counts.get('SKIPPED', 0)} were explicitly excluded."
        ),
        "",
        (
            "This dossier distinguishes detector evidence from policy interpretation. "
            "A detected API or dynamic import is not proof of runtime execution. A "
            "PQC reference is not proof of correct implementation, FIPS validation, or "
            "compliance. An absent finding is not proof that cryptography is absent."
        ),
        "",
        "### Policy disposition",
        "",
    ]
    if status_counts:
        lines.extend(
            _table(
                ["Disposition", "Count"],
                sorted(status_counts.items(), key=lambda item: item[0]),
            )
        )
    else:
        lines.append("No observations were available for policy evaluation.")

    lines.extend(["", "### Algorithm evidence", ""])
    if algorithm_counts:
        lines.extend(
            _table(
                ["Normalized algorithm or context", "Observations"],
                sorted(algorithm_counts.items(), key=lambda item: (-item[1], item[0])),
            )
        )
    else:
        lines.append("No supported API or ELF-import observations were detected.")

    lines.extend(["", "## Prioritized Findings", ""])
    priority_order = ["HIGH", "REVIEW", "MEDIUM", "LOW"]
    ordered_priorities = priority_order + sorted(
        set(findings_by_priority) - set(priority_order)
    )
    finding_number = 0
    for priority in ordered_priorities:
        group = findings_by_priority.get(priority, [])
        if not group:
            continue
        lines.extend([f"### {priority}", ""])
        rows = []
        for observation, evaluation in group:
            finding_number += 1
            location = observation.location
            if location["kind"] == "SOURCE":
                location_text = f"{observation.artifact_path}:{location['line']}:{location['column']}"
            else:
                location_text = f"{observation.artifact_path} / {location.get('symbol', 'symbol')}"
            rows.append(
                (
                    finding_number,
                    observation.normalized_claim["algorithm"],
                    observation.normalized_claim["operation"],
                    location_text,
                    evaluation.status,
                    f"{observation.confidence['score']:.2f}",
                    observation.observation_id,
                )
            )
        lines.extend(
            _table(
                ["#", "Algorithm", "Operation", "Evidence location", "Disposition", "Confidence", "Observation ID"],
                rows,
            )
        )
        lines.append("")

    lines.extend(["## Coverage and Evidence Gaps", ""])
    if coverage:
        coverage_rows = []
        for record in coverage:
            coverage_rows.append(
                (
                    record.artifact_path,
                    record.detector_id,
                    record.status,
                    record.reason_code,
                    record.bytes_analyzed,
                    "Yes" if record.lost_symbols else "No",
                    "; ".join(record.notes),
                )
            )
        lines.extend(
            _table(
                ["Artifact", "Detector", "Status", "Reason", "Bytes", "Lost symbols", "Boundary note"],
                coverage_rows,
            )
        )
    else:
        lines.append("No supported candidate artifacts were found in the supplied target.")

    lines.extend(
        [
            "",
            "## Interpretation Boundary",
            "",
            "The following limitations are release-defining, not footnotes:",
            "",
            "- Source detection is token-aware lexical matching, not Clang AST or CFG analysis.",
            "- Macro expansion, aliases, templates, function pointers, dead-code reachability, and build-conditional resolution are not implemented.",
            "- ELF analysis is limited to undefined dynamic symbols exposed to `readelf`.",
            "- Static linkage, `dlopen()`/`dlsym()`, inlining, stripped implementation fingerprints, and NTT constant detection are not implemented.",
            "- No runtime execution, key material, protocol negotiation, or effective cryptographic configuration is established.",
            "- Customer system classification and contract coverage are required before applying any regulatory milestone.",
            "",
            "## Policy Sources and Conditional Milestones",
            "",
            policy.raw["disclaimer"],
            "",
        ]
    )
    lines.extend(
        _table(
            ["Source", "Status/date", "Use in this dossier"],
            (
                (
                    f"[{source['title']}]({source['url']})",
                    source["effective_date"],
                    source["notes"],
                )
                for source in policy.raw.get("sources", [])
            ),
        )
    )
    lines.extend(["", "### Reference milestones (applicability not established)", ""])
    lines.extend(
        _table(
            ["Milestone", "Date", "Conditional applicability", "Source"],
            (
                (
                    milestone["id"],
                    milestone["date"],
                    milestone["applicability"],
                    milestone["source_id"],
                )
                for milestone in policy.raw.get("reference_milestones", [])
            ),
        )
    )

    lines.extend(
        [
            "",
            "## Recommended Analyst Workflow",
            "",
            "1. Resolve every `FAILED`, `PARTIAL`, and material `SKIPPED` coverage record before making an estate-level statement.",
            "2. Confirm whether each referenced symbol is reachable in the shipped build and exercised in the relevant deployment path.",
            "3. Resolve unknown EVP and PKCS#11 mechanisms from keys, provider configuration, HSM policy, or approved runtime evidence.",
            "4. Establish system classification and contractual scope before attaching a transition deadline.",
            "5. Build a migration dependency sequence only after provider, protocol, certificate, HSM, and downstream compatibility constraints are evidenced.",
            "",
            "## Reproducibility and Integrity",
            "",
            "The evidence bundle binds each observation to an artifact digest, detector version, ruleset digest, and stable observation ID. `integrity.json` binds every dossier input and projection. Retain the scan command's integrity receipt outside the bundle and run `pqc-evidence verify BUNDLE_DIRECTORY --expected-receipt RECEIPT` before analysis or delivery. Without that external receipt or a signature, verification establishes internal consistency rather than origin authenticity.",
            "",
        ]
    )
    return "\n".join(lines)
