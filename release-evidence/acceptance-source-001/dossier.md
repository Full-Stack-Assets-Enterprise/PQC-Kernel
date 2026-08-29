# Cryptographic Discovery Evidence Dossier

**Customer Confidential — Assessment Draft**

- Scan ID: `acceptance-source-001`
- Engine: `pqc-evidence-kernel 0.1.0`
- Rules: `openssl-pkcs11-linux-source-elf 0.1.0`
- Policy projection: `us-federal-pqc-transition-discovery 0.1.0`
- Target label: `Golden source fixture`
- Completed: `2026-08-29T16:42:13Z`
- Gate status: **PASS**

## Executive Summary

The assessment produced **6 atomic observation(s)** across **2 coverage record(s)**. 2 artifact-detector result(s) completed at full v0.1 scope, 0 were partial, 0 failed, and 0 were explicitly excluded.

This dossier distinguishes detector evidence from policy interpretation. A detected API or dynamic import is not proof of runtime execution. A PQC reference is not proof of correct implementation, FIPS validation, or compliance. An absent finding is not proof that cryptography is absent.

### Policy disposition

| Disposition | Count |
| --- | --- |
| MANUAL_RESOLUTION_REQUIRED | 2 |
| PQC_CANDIDATE_DETECTED | 1 |
| TRANSITION_REVIEW_REQUIRED | 3 |

### Algorithm evidence

| Normalized algorithm or context | Observations |
| --- | --- |
| RSA | 2 |
| ECDSA | 1 |
| ML-KEM | 1 |
| UNKNOWN_HSM_PUBLIC_KEY | 1 |
| UNKNOWN_KEY_ESTABLISHMENT | 1 |

## Prioritized Findings

### HIGH

| # | Algorithm | Operation | Evidence location | Disposition | Confidence | Observation ID |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | RSA | SIGN | positive.c:2:5 | TRANSITION_REVIEW_REQUIRED | 0.98 | obs_43193dcffbc9c3c714b6252489346cad |
| 2 | RSA | CREATE_CONTEXT | positive.c:3:5 | TRANSITION_REVIEW_REQUIRED | 0.98 | obs_67a95557c19ef5b27f875991f1c24880 |
| 3 | UNKNOWN_KEY_ESTABLISHMENT | DERIVE_KEY | positive.c:5:5 | MANUAL_RESOLUTION_REQUIRED | 0.90 | obs_8f5806fd51d7417c1e232cfdc820023e |
| 4 | ECDSA | SIGN | positive.c:6:5 | TRANSITION_REVIEW_REQUIRED | 0.98 | obs_333a6b8c087378c507773b7fd322f6dc |
| 5 | UNKNOWN_HSM_PUBLIC_KEY | GENERATE_KEY_PAIR | positive.c:7:5 | MANUAL_RESOLUTION_REQUIRED | 0.94 | obs_3c8f15f40c4ebc475770d022a73d3014 |

### REVIEW

| # | Algorithm | Operation | Evidence location | Disposition | Confidence | Observation ID |
| --- | --- | --- | --- | --- | --- | --- |
| 6 | ML-KEM | CREATE_CONTEXT | positive.c:4:5 | PQC_CANDIDATE_DETECTED | 0.96 | obs_f66a534e07b6736085983b167f5babb0 |

## Coverage and Evidence Gaps

| Artifact | Detector | Status | Reason | Bytes | Lost symbols | Boundary note |
| --- | --- | --- | --- | --- | --- | --- |
| negative.c | source.lexical-call | FULL | ANALYSIS_COMPLETE | 298 | No | Token-aware lexical analysis completed; macro expansion, aliases, function pointers, and reachability are out of scope. |
| positive.c | source.lexical-call | FULL | ANALYSIS_COMPLETE | 319 | No | Token-aware lexical analysis completed; macro expansion, aliases, function pointers, and reachability are out of scope. |

## Interpretation Boundary

The following limitations are release-defining, not footnotes:

- Source detection is token-aware lexical matching, not Clang AST or CFG analysis.
- Macro expansion, aliases, templates, function pointers, dead-code reachability, and build-conditional resolution are not implemented.
- ELF analysis is limited to undefined dynamic symbols exposed to `readelf`.
- Static linkage, `dlopen()`/`dlsym()`, inlining, stripped implementation fingerprints, and NTT constant detection are not implemented.
- No runtime execution, key material, protocol negotiation, or effective cryptographic configuration is established.
- Customer system classification and contract coverage are required before applying any regulatory milestone.

## Policy Sources and Conditional Milestones

Advisory discovery mapping only. A finding does not establish system scope, contract coverage, FIPS validation, correct implementation, or legal compliance.

| Source | Status/date | Use in this dossier |
| --- | --- | --- |
| [Executive Order 14412 — Securing the Nation Against Advanced Cryptographic Attacks](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/) | 2026-06-22 | Sections 4-6 establish conditional federal transition milestones and direct publication of proposed FAR rules. |
| [NIST CSWP 39upd1 — Considerations for Achieving Crypto Agility](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final) | 2026-06-29 | Provides crypto-agility strategies and practices; it is not a detector-specific compliance rule. |
| [NIST SP 1800-38B — Public Key Application Discovery Tools (Preliminary Draft)](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) | 2023-12-19 | Preliminary discovery guidance; status must remain visible in downstream reports. |

### Reference milestones (applicability not established)

| Milestone | Date | Conditional applicability | Source |
| --- | --- | --- | --- |
| EO14412-HVA-KEY-ESTABLISHMENT | 2030-12-31 | Federal HVA and high-impact systems, excluding National Security Systems, for key establishment. | EO-14412 |
| EO14412-HVA-DIGITAL-SIGNATURE | 2031-12-31 | Federal HVA and high-impact systems, excluding National Security Systems, for digital signatures. | EO-14412 |
| EO14412-FAR-PROPOSED-RULE | 2030-12-31 | Target compliance date directed for a future proposed FAR rule covering covered contractors; not represented as a final FAR clause. | EO-14412 |

## Recommended Analyst Workflow

1. Resolve every `FAILED`, `PARTIAL`, and material `SKIPPED` coverage record before making an estate-level statement.
2. Confirm whether each referenced symbol is reachable in the shipped build and exercised in the relevant deployment path.
3. Resolve unknown EVP and PKCS#11 mechanisms from keys, provider configuration, HSM policy, or approved runtime evidence.
4. Establish system classification and contractual scope before attaching a transition deadline.
5. Build a migration dependency sequence only after provider, protocol, certificate, HSM, and downstream compatibility constraints are evidenced.

## Reproducibility and Integrity

The evidence bundle binds each observation to an artifact digest, detector version, ruleset digest, and stable observation ID. `integrity.json` binds every dossier input and projection. Retain the scan command's integrity receipt outside the bundle and run `pqc-evidence verify BUNDLE_DIRECTORY --expected-receipt RECEIPT` before analysis or delivery. Without that external receipt or a signature, verification establishes internal consistency rather than origin authenticity.
