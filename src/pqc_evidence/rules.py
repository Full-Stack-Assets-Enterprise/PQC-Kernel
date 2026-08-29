"""Bundled detector and policy profile loading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_bytes


@dataclass(frozen=True)
class DetectorRule:
    id: str
    symbol: str
    provider: str
    algorithm: str
    primitive_family: str
    operation: str
    confidence: float
    argument_markers: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleSet:
    id: str
    version: str
    digest: str
    rules: tuple[DetectorRule, ...]
    raw: dict[str, Any]

    @property
    def by_symbol(self) -> dict[str, DetectorRule]:
        return {rule.symbol: rule for rule in self.rules}


@dataclass(frozen=True)
class PolicyProfile:
    id: str
    version: str
    digest: str
    raw: dict[str, Any]


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def default_rules_path() -> Path:
    return Path(
        str(files("pqc_evidence").joinpath("data/rules/openssl-pkcs11-v0.1.0.json"))
    )


def default_policy_path() -> Path:
    return Path(
        str(files("pqc_evidence").joinpath("data/policies/us-federal-pqc-v0.1.0.json"))
    )


def load_rules(path: Path | None = None) -> RuleSet:
    raw = _read_json(path or default_rules_path())
    rules = tuple(
        DetectorRule(
            id=item["id"],
            symbol=item["symbol"],
            provider=item["provider"],
            algorithm=item["algorithm"],
            primitive_family=item["primitive_family"],
            operation=item["operation"],
            confidence=float(item["confidence"]),
            argument_markers=dict(item.get("argument_markers", {})),
        )
        for item in raw["rules"]
    )
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("detector rule IDs must be unique")
    if len({rule.symbol for rule in rules}) != len(rules):
        raise ValueError("detector symbols must be unique in v0.1")
    return RuleSet(
        id=raw["ruleset_id"],
        version=raw["version"],
        digest=sha256_bytes(canonical_json(raw).encode("utf-8")),
        rules=rules,
        raw=raw,
    )


def load_policy(path: Path | None = None) -> PolicyProfile:
    raw = _read_json(path or default_policy_path())
    source_ids = {source["id"] for source in raw.get("sources", [])}
    for rule in raw.get("rules", []):
        unknown = set(rule.get("source_ids", [])) - source_ids
        if unknown:
            raise ValueError(f"policy rule references unknown sources: {sorted(unknown)}")
    return PolicyProfile(
        id=raw["profile_id"],
        version=raw["version"],
        digest=sha256_bytes(canonical_json(raw).encode("utf-8")),
        raw=raw,
    )
