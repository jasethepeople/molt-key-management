# MOLT manifest-signer key management — report

## Verdict
Rotation works: yes.
Revocation works: yes.
Compromise procedure runs: yes.

## Files changed and added
- `bin/molt-keyctl.mjs` — offline CLI for key generation/inspection, bootstrap, rotation, revocation, emergency rotation, re-issue, and verification.
- `src/key-management.mjs` — signed key-history policy and package operations.
- `source/independent-verifier.ts` — copied byte-for-byte from the supplied L1 bundle; unchanged.
- `source/types.ts` — copied byte-for-byte from the supplied L1 bundle; unchanged.
- `tests/key-management.test.mjs` — Node-only fresh-directory suite.
- `README.md` — formats, behavior, and checks.
- `RUNBOOK.md` — owner-run real-key procedures and exact commands.
- `package.json` — zero dependencies; `npm test` invokes Node's built-in test runner.
- `REPORT.md` — this report.
- `molt-manifest-signer-key-management.zip` — deliverable bundle containing the files above except the archive itself.

## Test results
The final local run on Node v22.23.4 completed **12 passed, 0 failed**. Each test creates a new temporary directory, generates fresh `TEST-ONLY` Ed25519 identities, and removes the directory afterward. The suite uses only Node built-ins and the attached independent verifier; no network, live Foundry, or real private key is used.

1. Original signer before rotation — PASS: valid, 1 event, `standalone-molt-v1`.
2. Trust separation and active-key revocation guard — PASS: embedded trust rejected with `TRUST_MUST_BE_EXTERNAL`; normal revoke of the active key rejected with `CURRENT_KEY_REQUIRES_COMPROMISE`.
3. Test identity handling — PASS: mode 600; `inspect-identity` shows public metadata and does not print the private seed.
4. Recovery-key substitution — PASS: replacing the recovery public key fails with `GENESIS_PROOF_INVALID` because the initial signer did not authorize it.
5. Routine rotation — PASS: old-key authorization and new-key proof verify; the new package passes the L1 verifier and policy check.
6. Old key after rotation — PASS: rejected with `SIGNER_RETIRED`; the bare L1 verifier still accepts the cryptographically valid old package, demonstrating why consumers must use `molt-keyctl verify` with the latest trust checkpoint.
7. Revocation — PASS: old signer rejected with `KEY_REVOKED`; the current good signer remains valid.
8. Tampered rotation proof — PASS: rejected with `ROTATION_PROOF_INVALID`.
9. Tampered signed manifest note — PASS: rejected with `MANIFEST_NOTE_SIGNATURE_INVALID`.
10. Tampered event payload — PASS: rejected through the attached independent verifier as `INDEPENDENT_VERIFIER_FAIL` with `Event content hash is invalid.`
11. Compromise flow through the CLI — PASS: emergency operation records revocation then recovery-authorized rotation; new and reviewed re-issued packages verify; old signer fails with `KEY_REVOKED`; original package remains unchanged.
12. Unreviewed re-issue — PASS: rejected with `REVIEW_REQUIRED`.

**Final archive verification: PASS.** I extracted this exact ZIP into a newly created temporary directory and ran `node --experimental-strip-types --test tests/key-management.test.mjs`: 12 passed, 0 failed. No package installation or network access was required.

Build-round notes: an early fixture run exposed an output-directory collision (`EEXIST`); it was corrected. A subsequent proof-tamper test initially changed the test trust copy before the intended check; the fixture was corrected. Security review also found that bootstrap needed the current signer to authenticate the recovery key; genesis now requires that proof and test 4 covers substitution. The final local suite is green.

## The compromise decision
Every package signed by a compromised key is rejected by the current trust checkpoint, including packages that may predate discovery. Original bytes are preserved unchanged for investigation; an owner may re-issue a copy only after independently reviewing its content and provenance, using `reissue --reviewed` with the current key. This is conservative because the package format has no independent trusted timestamp that can reliably separate pre-compromise signatures from attacker-made signatures. Re-signing without review could bless attacker-controlled content as historical fact, so uncertain artifacts remain untrusted.

## Open items
1. **The real-key rotation is the owner's step.** The private file `~/.config/molt-forge/manifest-signer-identity.json` was never accessed. The owner must bootstrap recovery while the current signer is still trusted, then run the routine or emergency procedure in `RUNBOOK.md`.
2. The attached sources do not specify the existing identity JSON field names. This CLI accepts `molt.ed25519-identity.v1` (`privateKeyHex`, `publicKeyHex`, `keyId`) and fails closed otherwise. The owner must run `inspect-identity` locally; if the real file differs, adapt the local key loader without exposing or copying the key.
3. No real MOLT evidence package was attached. Tests use a locally generated package and a `TEST-ONLY` signed-note fixture matching the supplied signature layout. The owner must use the actual `manifest.json`, `events.jsonl`, `ed25519-public.pem`, signed note, and artifacts.
4. Rotation/revocation enforcement requires the latest `trust.json` to be distributed and protected separately from packages. A stale checkpoint can still validate an earlier package; record each checkpoint hash through an independent controlled channel.
5. `molt-keyctl verify` is the policy gate. The unchanged standalone L1 verifier verifies signatures against a package's own public key and does not itself know the current rotation/revocation history.
6. The real signer was not rotated, no files were pushed or deployed, and no live service was changed.

## What I did NOT do
- Every keypair used to generate, sign, or verify test artifacts was freshly generated and marked `TEST-ONLY`. The attached document's public-key/signature sample was read only to confirm the exact signed-statement byte boundary; it was not used to sign test artifacts.
- The real manifest-signer private key was never touched, read, copied, printed, or rotated. I did not access the path `~/.config/molt-forge/manifest-signer-identity.json`.
- I did not use any live signing key, alter the MOLT/Room hashing path, change a Room contract, access Foundry, push to GitHub, or deploy anything.
- The deliverable was secret-scanned: 9 files, 0 secret-shaped matches. Test-only temporary key directories were cleaned up.
