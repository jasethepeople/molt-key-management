# MOLT manifest-signer key management — Camp 1 interoperability

## Result

The key-management policy layer now delegates package validation to the same MOLT-CORE v1.0 L1 verifier used by `molt-verify`. Its canonicalizer is byte-for-byte the shared `molt-canonical` implementation (SHA-256 `5e4c0503fbefa64503616551bc56e743e4681e40a009590f9eaf315a9c8dcff3`). Key-history signing remains a separate internal format; MOLT event hashing was not changed.

## Verification

- `npm test`: 13 passed, 0 failed on Node.js 22.23.4.
- The shared `molt-verify` `sample-good` package passes the vendored L1 verifier.
- Fresh key-management packages include `artifact_bytes` and `ledger_bytes`, canonical event JSONL, and Camp 1 five-field hashes/signatures.
- Bootstrap and re-signing update artifact byte counts and ledger byte counts.
- Rotation, revocation, recovery, re-issue policy, tamper checks, and owner-only identity handling remain covered.
- No live key, existing evidence package, or external service was accessed.

L1 interoperability is confirmed for ASCII event content. MOLT-CORE's non-ASCII canonicalization decision remains open; no alternate Foundry serializer was adopted. Older incomplete manifests or seven-field ledgers fail closed and require owner review rather than automatic rewriting.
