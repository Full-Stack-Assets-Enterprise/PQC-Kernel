"""Versioned policy projection over immutable observations."""

from __future__ import annotations

from .models import Observation, PolicyEvaluation
from .rules import PolicyProfile


def evaluate_observation(
    observation: Observation,
    profile: PolicyProfile,
    evaluated_at: str,
) -> PolicyEvaluation:
    algorithm = observation.normalized_claim["algorithm"]
    matched: dict[str, object] | None = None
    for rule in profile.raw.get("rules", []):
        algorithms = rule.get("algorithms", [])
        prefix = rule.get("algorithm_prefix")
        if algorithm in algorithms or (prefix and algorithm.startswith(str(prefix))):
            matched = rule
            break
    if matched is None:
        matched = {
            "status": "MANUAL_POLICY_REVIEW",
            "priority": "REVIEW",
            "rationale": (
                "No built-in policy rule maps this normalized claim. Preserve the "
                "observation and obtain an analyst interpretation."
            ),
            "source_ids": [],
        }
    return PolicyEvaluation.build(
        scan_id=observation.scan_id,
        observation_id=observation.observation_id,
        policy_profile_id=profile.id,
        policy_version=profile.version,
        status=str(matched["status"]),
        priority=str(matched["priority"]),
        rationale=str(matched["rationale"]),
        source_ids=[str(value) for value in matched.get("source_ids", [])],
        evaluated_at=evaluated_at,
    )
