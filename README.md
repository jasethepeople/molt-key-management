# MOLT manifest-signer key management

This package adds offline rotation, revocation, emergency recovery, and re-issue policy around the supplied L1 MOLT package verifier. It uses only Node built-ins and the attached `independent-verifier.ts`; it does not contact Foundry, read a live key, or change any MOLT or Room hashing code.

## Run

Requires Node.js 22.6 or later. No install step or network access is required.

```sh
node bin/molt-keyctl.mjs --help
node --experimental-strip-types --test tests/key-management.test.mjs
```

`npm test` runs the same test command. The tests create a separate temporary directory and fresh `TEST-ONLY` Ed25519 identities for every case, then remove those directories. No test private key is stored in the package.

## What the verifier checks

Run `node bin/molt-keyctl.mjs verify --package PACKAGE_DIR --trust TRUST.json` for every policy decision. The command first validates the signed key-history against the separately held trust checkpoint, then checks whether the package signer is current, retired, or revoked, verifies the exact signed manifest-note entry, and finally calls the supplied `independentlyVerifyMoltPackage` implementation for artifact digests, event hash-chain integrity, Ed25519 event signatures, and actor binding.

The supplied independent verifier alone intentionally has no key-history input. It will verify an old package against the old public key embedded in that package even after a rotation. The `molt-keyctl verify` policy layer is what rejects that package against the latest trust checkpoint. Do not use the bare L1 verifier as the rotation/revocation policy gate.

The signed manifest note follows the attached document's exact format: the UTF-8 text inside `Statement signed (exact bytes, UTF-8)` is signed with Ed25519; the public-key and signature hex lines identify that signature. The package stores it as `manifest-note.md`, hashes it in `manifest.json.artifacts`, updates `manifest.json.agent_pubkeys`, updates `ed25519-public.pem`, and re-signs each unchanged event hash. The note signature covers only its exact fenced statement; it does not add a new signature format for the full JSON manifest. The supplied verifier continues to enforce the existing manifest artifact digests and event-signature contract.

## Key and record formats

Identity files use `molt.ed25519-identity.v1`: `algorithm: "Ed25519"`, a 32-byte raw private seed in `privateKeyHex`, the matching raw `publicKeyHex`, and `keyId` equal to SHA-256 of the 32 public-key bytes. Identity files must be regular non-symlink files with owner-only permissions (mode 600 or stricter). `inspect-identity` prints public metadata only; it never prints the private seed.

`key-history.json` uses `molt.key-history.v1`:

- Its genesis record binds the initial manifest-signing key, the recovery public key, and the original signed manifest-note statement. The initial signer signs the genesis hash, so an attacker cannot substitute a recovery key without `GENESIS_PROOF_INVALID`.
- A `rotate` record contains the old and new key IDs/public keys and proofs from both the old signer and the new key. It retires the old key and makes the new key current.
- A `revoke` record is authorized by the pinned recovery key. A normal revoke can target only a non-current key.
- An `emergency-rotate` record follows a recovery-key-signed revocation of the current key and includes both recovery authorization and a proof from the replacement key.
- Each record is sequence-numbered, hash-chained, and signed over its hash. The package embeds the history; `TRUST.json` is a separate trusted copy and must remain outside the package.

The trust checkpoint is the authority for freshness. Always use the latest checkpoint and preserve it independently of packages; an older checkpoint can still validate an older package. Back up the current checkpoint and record its SHA-256 through an independent, controlled channel after every update. This offline package cannot discover a newer checkpoint by itself.

## Artifact policy

After normal rotation, old-key packages fail against the new checkpoint with `SIGNER_RETIRED`. After compromise revocation, packages under that key fail with `KEY_REVOKED`, including artifacts that may predate discovery. They are not grandfathered as trusted under the current policy. An owner may re-issue an artifact only after reviewing its contents and provenance against independent sources; `reissue --reviewed` copies it to a new directory and re-signs it with the current key without modifying the source. If review cannot establish provenance, keep the artifact marked untrusted and do not re-issue it.

## Important checks

- `GENESIS_PROOF_INVALID`: the initial signer did not authorize the recovery key.
- `ROTATION_PROOF_INVALID`: the old-key or new-key rotation proof is missing or invalid.
- `KEY_REVOKED`: the package key appears in signed revocation history.
- `SIGNER_RETIRED`: a signed rotation retired the package key.
- `SIGNER_NOT_CURRENT`: the package key is not the current trusted signer.
- `MANIFEST_NOTE_SIGNATURE_INVALID`: the note's signature does not verify over its exact UTF-8 statement.
- `INDEPENDENT_VERIFIER_FAIL`: the supplied L1 verifier rejected the package; the message includes its failing check.
- `KEY_HISTORY_NOT_TRUSTED` / `KEY_HISTORY_HEAD_MISMATCH`: package history diverges from or does not match the trusted history.
- `REVIEW_REQUIRED`: an artifact re-issue was requested without explicit owner review.

This package is a local mechanism and test suite, not a deployment or publication. It does not rotate the owner's real signer key.
