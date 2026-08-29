"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rules import load_policy, load_rules
from .scanner import ScanOptions, create_scan_bundle, new_scan_id
from .verify import verify_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-evidence",
        description="Offline evidence-first cryptographic discovery for Linux C/C++ and ELF.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Create a new write-once, integrity-verifiable evidence bundle")
    scan.add_argument("target", type=Path)
    scan.add_argument("--output", type=Path, help="New bundle directory (must not exist)")
    scan.add_argument("--scan-id", help="Caller-controlled scan identity")
    scan.add_argument("--target-label", help="Non-sensitive label used in the dossier")
    scan.add_argument("--include-headers", action="store_true")
    scan.add_argument("--no-binaries", action="store_true")
    scan.add_argument("--include-snippets", action="store_true")
    scan.add_argument("--max-file-bytes", type=int, default=100 * 1024 * 1024)
    scan.add_argument("--rules", type=Path, help="Versioned detector rules JSON")
    scan.add_argument("--policy", type=Path, help="Versioned policy profile JSON")

    verify = subparsers.add_parser("verify", help="Verify hashes, counts, and stable record IDs")
    verify.add_argument("bundle", type=Path)
    verify.add_argument(
        "--expected-receipt",
        help="SHA-256 receipt retained separately when the scan was created",
    )

    inspect = subparsers.add_parser("inspect-profile", help="Print bundled profile metadata")
    inspect.add_argument("--full", action="store_true", help="Include policy sources and detector symbols")
    return parser


def _scan(args: argparse.Namespace) -> int:
    selected_scan_id = args.scan_id or new_scan_id()
    output = args.output or Path("outputs") / selected_scan_id
    ruleset = load_rules(args.rules)
    policy = load_policy(args.policy)
    result = create_scan_bundle(
        target=args.target,
        output=output,
        ruleset=ruleset,
        policy=policy,
        options=ScanOptions(
            include_headers=args.include_headers,
            include_binaries=not args.no_binaries,
            include_snippets=args.include_snippets,
            max_file_bytes=args.max_file_bytes,
            target_label=args.target_label,
        ),
        scan_id=selected_scan_id,
    )
    summary = {
        "bundle": str(result.bundle_path),
        "bundle_id": result.manifest["bundle_id"],
        "scan_id": result.manifest["scan_id"],
        "status": result.manifest["status"],
        "record_counts": result.manifest["record_counts"],
        "integrity_receipt": result.integrity_receipt,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _verify(args: argparse.Namespace) -> int:
    result = verify_bundle(args.bundle, expected_receipt=args.expected_receipt)
    print(
        json.dumps(
            {
                "ok": result.ok,
                "verified_files": result.verified_files,
                "verified_records": result.verified_records,
                "issues": result.issues,
                "integrity_receipt": result.integrity_receipt,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result.ok else 1


def _inspect_profile(args: argparse.Namespace) -> int:
    ruleset = load_rules()
    policy = load_policy()
    output: dict[str, object] = {
        "ruleset": {
            "id": ruleset.id,
            "version": ruleset.version,
            "digest": ruleset.digest,
            "rule_count": len(ruleset.rules),
        },
        "policy": {
            "id": policy.id,
            "version": policy.version,
            "digest": policy.digest,
            "as_of": policy.raw["as_of"],
            "disclaimer": policy.raw["disclaimer"],
        },
    }
    if args.full:
        output["detector_symbols"] = sorted(rule.symbol for rule in ruleset.rules)
        output["policy_sources"] = policy.raw["sources"]
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "inspect-profile":
            return _inspect_profile(args)
        raise AssertionError(f"unhandled command: {args.command}")
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
