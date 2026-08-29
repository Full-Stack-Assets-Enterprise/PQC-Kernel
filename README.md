# PQC Evidence Kernel v0.1

An offline, assessment-operated scanner for Linux x86-64 C/C++ source and ELF
binaries. It produces a self-contained, write-once, integrity-verifiable evidence bundle with atomic
observations, explicit coverage records, versioned policy interpretations, an
integrity manifest, and a Markdown assessment dossier.

This is deliberately a professional-services instrument, not a self-service
platform. It does not claim that a detected API executed at runtime, that an
undetected primitive is absent, or that a detected PQC primitive makes a system
compliant.

## Commercial v0.1 boundary

- Supported: Linux C/C++ source, OpenSSL and PKCS#11 API references, ELF dynamic
  imports, offline execution, write-once per-scan bundles.
- Best-evidence statement: exact symbol, relative path, line or ELF symbol
  location, artifact digest, detector version, confidence basis.
- Explicitly excluded: Java, .NET, Windows CNG, firmware, ARM-specific analysis,
  macro expansion, function-pointer resolution, `dlopen()` resolution, call
  reachability, runtime proof, static-link recovery, and stripped-binary
  constant heuristics.
- Policy output is advisory and applicability-dependent. It is not legal advice
  or a compliance certification.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
pqc-evidence scan ./project --output ./outputs/customer-scan-001
pqc-evidence verify ./outputs/customer-scan-001 --expected-receipt sha256:RETAINED_SCAN_RECEIPT
```

To scan source only, add `--no-binaries`. Header files are excluded by default
because declarations create noisy findings; add `--include-headers` when the
assessment scope requires them. Evidence excerpts are excluded by default to
minimize source disclosure; add `--include-snippets` only with customer
authorization.

## Bundle contents

| File | Purpose |
| --- | --- |
| `scan_manifest.json` | Scan identity, engine/rules/policy versions, counts, and execution boundary |
| `detector_rules.json` | Exact detector-rule snapshot used for the scan |
| `policy_profile.json` | Exact policy-profile snapshot used for the projection |
| `observations.jsonl` | Atomic detector evidence; one canonical JSON record per line |
| `coverage.jsonl` | Per-artifact detector success, partial coverage, failure, or exclusion |
| `policy_evaluations.jsonl` | Versioned interpretations that never overwrite observations |
| `dossier.md` | Human-readable assessment projection |
| `integrity.json` | SHA-256 digest for every other bundle artifact |

Every scan writes to a new directory and refuses to overwrite an existing
bundle. The CLI prints an integrity receipt: retain it separately from the
bundle, then supply it to `verify`, which recomputes file hashes, record counts,
references, and deterministic record identifiers. Without a separately retained
receipt or signature, verification establishes internal consistency rather than
origin authenticity. Filesystem deletion is still possible; durable retention
controls belong to the customer delivery workflow.

## Development gate

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m compileall -q src tests
```

See [docs/SCOPE.md](docs/SCOPE.md) for detector semantics and
[docs/CUSTOMER_DATA_COLLECTION.md](docs/CUSTOMER_DATA_COLLECTION.md) for the
controlled collection procedure.
