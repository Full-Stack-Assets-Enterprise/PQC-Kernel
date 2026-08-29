# Customer Data Collection Guide — v0.1

## Supported collection

The assessment is designed to run wholly inside a customer-controlled Linux
environment with outbound networking disabled. The customer supplies either a
C/C++ source tree, one or more Linux ELF artifacts, or both. Source excerpts are
not retained unless `--include-snippets` is explicitly authorized.

## Static collection procedure

1. Create a dedicated, access-controlled working directory.
2. Place the scanner and the approved assessment target inside that environment.
3. Record the target version or source commit in the engagement worksheet.
4. Run `pqc-evidence scan TARGET --output BUNDLE_DIRECTORY`.
5. Run `pqc-evidence verify BUNDLE_DIRECTORY`.
6. Review `coverage.jsonl` before interpreting findings.
7. Transfer only the approved evidence bundle under the engagement data-handling
   procedure.

## Optional runtime enrichment

Runtime enrichment is customer-operated and is not part of the v0.1 engine. If
approved for a test environment, the customer may collect a bounded trace such
as:

```bash
strace -f -e trace=network,file -o crypto_trace.log ./approved-test-command
```

This trace can expose filenames, endpoints, process behavior, and other
sensitive data. It must not be collected in production without the customer's
security and privacy approval. Version 0.1 does not infer cryptographic
algorithm execution from this trace; any manual interpretation is labeled
analyst-supplied evidence.

## Data handling

- Do not include secrets, private keys, credentials, or production traffic.
- Treat source paths, binary names, symbol inventories, and findings as customer
  confidential.
- Preserve the original bundle unchanged. Create a separately identified
  derivative for redaction or dossier editing.
- Verify both the original and any approved derivative before delivery.

