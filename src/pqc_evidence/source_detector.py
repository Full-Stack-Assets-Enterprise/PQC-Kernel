"""Token-aware lexical source detector for the bounded v0.1 scope."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import sha256_bytes
from .models import CoverageRecord, Observation
from .rules import DetectorRule, RuleSet

DETECTOR_ID = "source.lexical-call"
DECLARATION_KEYWORDS = {
    "auto",
    "bool",
    "char",
    "const",
    "double",
    "enum",
    "extern",
    "float",
    "inline",
    "int",
    "long",
    "short",
    "signed",
    "static",
    "struct",
    "unsigned",
    "void",
    "volatile",
}
CONTROL_KEYWORDS = {"case", "if", "return", "sizeof", "switch", "while"}


@dataclass(frozen=True)
class SourceDetectionResult:
    observations: list[Observation]
    coverage: CoverageRecord


def _mask_noncode(content: str) -> str:
    """Mask comments and literals without moving line/column offsets."""

    output: list[str] = []
    state = "code"
    index = 0
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "line_comment"
                continue
            if char == "/" and next_char == "*":
                output.extend((" ", " "))
                index += 2
                state = "block_comment"
                continue
            if char == '"':
                output.append(" ")
                index += 1
                state = "string"
                continue
            if char == "'":
                output.append(" ")
                index += 1
                state = "char"
                continue
            output.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                output.append("\n")
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and next_char:
                output.extend((" ", "\n" if next_char == "\n" else " "))
                index += 2
                continue
            if char == quote:
                output.append(" ")
                index += 1
                state = "code"
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

    return "".join(output)


def _looks_like_declaration(masked: str, symbol_start: int) -> bool:
    line_start = masked.rfind("\n", 0, symbol_start) + 1
    prefix = masked[line_start:symbol_start]
    stripped = prefix.strip()
    if stripped.startswith("#"):
        return True
    if not stripped:
        return False
    words = set(re.findall(r"[A-Za-z_]\w*", stripped))
    if words & CONTROL_KEYWORDS:
        return False
    if any(token in prefix for token in ("=", ";", "{", "}", ",", ".", "->")):
        return False
    declaration_shape = re.fullmatch(r"[\w\s:*<>,\[\]&]+", stripped) is not None
    return declaration_shape and bool(words & DECLARATION_KEYWORDS or "*" in stripped)


def _call_slice(content: str, open_paren: int, limit: int = 4096) -> str:
    """Return a bounded, balanced call excerpt starting at the open parenthesis."""

    end_limit = min(len(content), open_paren + limit)
    depth = 0
    state = "code"
    index = open_paren
    while index < end_limit:
        char = content[index]
        next_char = content[index + 1] if index + 1 < end_limit else ""
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "/" and next_char == "*":
                state = "block_comment"
                index += 1
            elif char == "/" and next_char == "/":
                state = "line_comment"
                index += 1
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return content[open_paren : index + 1]
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and next_char:
                index += 1
            elif char == quote:
                state = "code"
        elif state == "block_comment" and char == "*" and next_char == "/":
            state = "code"
            index += 1
        elif state == "line_comment" and char == "\n":
            state = "code"
        index += 1
    return content[open_paren:end_limit]


def _resolved_claim(rule: DetectorRule, call_text: str) -> tuple[dict[str, str], float, str | None]:
    algorithm = rule.algorithm
    family = rule.primitive_family
    confidence = rule.confidence
    matched_marker: str | None = None
    for marker, override in rule.argument_markers.items():
        if re.search(rf"\b{re.escape(marker)}\b", call_text):
            algorithm = str(override.get("algorithm", algorithm))
            family = str(override.get("primitive_family", family))
            confidence = float(override.get("confidence", confidence))
            matched_marker = marker
            break
    claim = {
        "algorithm": algorithm,
        "primitive_family": family,
        "operation": rule.operation,
        "provider": rule.provider,
        "symbol": rule.symbol,
        "usage_state": "UNRESOLVED",
        "assurance": "API_REFERENCE_ONLY",
    }
    return claim, confidence, matched_marker


def detect_source(
    *,
    content_bytes: bytes,
    artifact_digest: str,
    artifact_path: str,
    scan_id: str,
    ruleset: RuleSet,
    observed_at: str,
    include_snippets: bool,
) -> SourceDetectionResult:
    content = content_bytes.decode("utf-8", errors="replace")
    replacements = content.count("\ufffd")
    masked = _mask_noncode(content)
    symbol_map = ruleset.by_symbol
    symbol_pattern = "|".join(
        re.escape(symbol) for symbol in sorted(symbol_map, key=len, reverse=True)
    )
    pattern = re.compile(rf"\b(?P<symbol>{symbol_pattern})\s*(?P<open>\()")
    observations: list[Observation] = []

    for match in pattern.finditer(masked):
        if _looks_like_declaration(masked, match.start("symbol")):
            continue
        rule = symbol_map[match.group("symbol")]
        call_text = _call_slice(content, match.start("open"))
        claim, confidence, matched_marker = _resolved_claim(rule, call_text)
        line = masked.count("\n", 0, match.start("symbol")) + 1
        line_start = masked.rfind("\n", 0, match.start("symbol")) + 1
        column = match.start("symbol") - line_start + 1
        evidence = {
            "matched_symbol": rule.symbol,
            "call_token_digest": sha256_bytes(call_text.encode("utf-8")),
            "argument_marker": matched_marker,
        }
        if include_snippets:
            evidence["excerpt"] = re.sub(r"\s+", " ", call_text).strip()[:240]
        basis = (
            "Exact supported API token followed by a call parenthesis; comments and "
            "literals excluded from token matching; semantic reachability unresolved."
        )
        if matched_marker:
            basis += f" Algorithm refined by argument marker {matched_marker}."
        observations.append(
            Observation.build(
                scan_id=scan_id,
                detector_id=rule.id,
                detector_version=ruleset.version,
                artifact_digest=artifact_digest,
                artifact_path=artifact_path,
                location={"kind": "SOURCE", "line": line, "column": column},
                method="SOURCE_LEXICAL_CALL",
                normalized_claim=claim,
                confidence_score=confidence,
                confidence_basis=basis,
                evidence=evidence,
                observed_at=observed_at,
            )
        )

    status = "PARTIAL" if replacements else "FULL"
    reason_code = "DECODE_REPLACEMENT" if replacements else "ANALYSIS_COMPLETE"
    notes = [
        "Token-aware lexical analysis completed; macro expansion, aliases, function pointers, and reachability are out of scope."
    ]
    if replacements:
        notes.append(f"UTF-8 decoding replaced {replacements} invalid byte sequence(s).")
    coverage = CoverageRecord.build(
        scan_id=scan_id,
        detector_id=DETECTOR_ID,
        detector_version=ruleset.version,
        artifact_digest=artifact_digest,
        artifact_path=artifact_path,
        status=status,
        reason_code=reason_code,
        bytes_analyzed=len(content_bytes),
        lost_symbols=False,
        notes=notes,
        recorded_at=observed_at,
    )
    return SourceDetectionResult(observations=observations, coverage=coverage)
