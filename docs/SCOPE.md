# Assessment Scope and Evidence Semantics

## What an observation proves

A source observation proves that the versioned detector found a supported API
reference at a specific location in the supplied bytes. An ELF observation
proves that the inspected dynamic symbol table contained an undefined reference
to a supported API symbol. Both records bind the statement to the SHA-256 digest
of the inspected artifact.

Neither observation proves runtime execution, key material, effective protocol
configuration, exploitability, or regulatory applicability.

## What coverage proves

Coverage is recorded independently for every candidate artifact. `FULL` means
the named detector completed all analysis that detector v0.1 supports. It does
not mean the engine supports every discovery technique. `PARTIAL` identifies a
known evidence loss such as a stripped binary or absent dynamic symbol table.
`FAILED` means the detector did not complete. `SKIPPED` means an explicit scope
or safety limit excluded the candidate.

Absence of an observation is never projected as absence of cryptography unless
the relevant detector and evidence class explicitly support that conclusion.

## Version 0.1 limitations

- Source detection is token-aware lexical matching, not Clang semantic analysis.
- Comments and string literals cannot create API-call findings; string arguments
  are inspected only after a real API token is found.
- Macro-generated calls, aliases, function pointers, and build-conditional paths
  may be missed.
- Declarations are filtered heuristically; unusual declarations may still need
  analyst review.
- ELF analysis considers undefined dynamic symbol references. Static linkage,
  inlined implementations, `dlopen()`/`dlsym()`, and stripped implementation
  fingerprints are out of scope.
- A PQC API reference is reported as a candidate, never as proof of correct or
  validated PQC deployment.
- Policy interpretations require the customer to establish system and contract
  applicability.

## Deferred gates

The following work is intentionally deferred until paid-customer evidence
justifies it: Clang AST/CFG analysis, protobuf/SQLite internal storage, Rust
rewrite, CycloneDX/SARIF conformance projections, runtime probes, NTT constant
detection, web UI, multi-tenancy, CI plugins, and automated remediation.

## Integrity versus authenticity

The bundle contains hashes for internal consistency and the scan command emits a
root integrity receipt. Verification against a receipt retained outside the
bundle detects post-scan changes. The v0.1 bundle is not digitally signed and
does not independently authenticate who ran the scan; customer KMS/PKCS#11
signing is a later consequence-gated capability.
