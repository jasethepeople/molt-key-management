# Manifest-signer key runbook

This is for the owner operating on the build machine. The commands are offline and write new package/checkpoint outputs; they do not edit the source package in place. Never paste private identity contents into chat, logs, or this package.

## 1. Stage and check the current identity

Unzip the delivered bundle into a protected directory and set its path. Set `PACKAGE` to a real MOLT evidence package containing `manifest.json`, `events.jsonl`, and `ed25519-public.pem`. Set `MANIFEST_NOTE` to the signed v2 manifest document. The tool adds that exact note to a copied package and records its digest.

```sh
ROOT="$HOME/molt-manifest-key-management-2026-11-11"
IDENTITY="$HOME/.config/molt-forge/manifest-signer-identity.json"
PACKAGE="$HOME/path/to/current-molt-package"
MANIFEST_NOTE="$HOME/path/to/molt-forge-demo-manifest-v2-2026-10-30.md"
node "$ROOT/bin/molt-keyctl.mjs" inspect-identity --identity "$IDENTITY"
stat -c '%a %n' "$IDENTITY"
```

Expected: `inspect-identity` prints `schema`, `purpose`, Ed25519 `publicKeyHex`, and `keyId` only; the public key must match the signed manifest document (`5147d00bd8bc3c3cc475677299f336f5761b3b38290bda86130487b436573fc1`), and `stat` must show mode `600`. The tool accepts the documented `molt.ed25519-identity.v1` JSON fields (`privateKeyHex`, `publicKeyHex`, `keyId`). The attached manifest document does not specify the existing identity JSON field names. If `inspect-identity` reports `IDENTITY_FORMAT_INVALID`, `IDENTITY_PERMISSIONS_INVALID`, or a different public key, stop; do not convert, copy, or expose the private key. Have the owner adapt the local key-loader against the actual Forge identity format.

## 2. Establish the recovery key and first trusted history (once)

Do this only while the current signer is known uncompromised. Generate a distinct recovery identity and store its private file offline or in the owner's approved secret store. `generate-identity` prints public metadata only; the private file is created with mode 600.

```sh
umask 077
RECOVERY="$HOME/.config/molt-forge/manifest-signer-recovery-identity.json"
node "$ROOT/bin/molt-keyctl.mjs" generate-identity --purpose recovery --out "$RECOVERY"
stat -c '%a %n' "$RECOVERY"
node "$ROOT/bin/molt-keyctl.mjs" inspect-identity --identity "$RECOVERY"
BOOTSTRAP_PACKAGE="$HOME/molt-managed/package-bootstrap"
BOOTSTRAP_TRUST="$HOME/molt-managed/trust-bootstrap.json"
node "$ROOT/bin/molt-keyctl.mjs" bootstrap --package "$PACKAGE" --manifest-note "$MANIFEST_NOTE" --current-identity "$IDENTITY" --recovery-identity "$RECOVERY" --out "$BOOTSTRAP_PACKAGE" --trust-out "$BOOTSTRAP_TRUST"
node "$ROOT/bin/molt-keyctl.mjs" verify --package "$BOOTSTRAP_PACKAGE" --trust "$BOOTSTRAP_TRUST"
sha256sum "$BOOTSTRAP_TRUST"
```

Expected checks: identity mode `600`; bootstrap succeeds only if the current identity matches the package public key and the signed note; `verify` prints `PASS check: KEY_HISTORY_CURRENT + standalone-molt-v1`. The initial signer signs the genesis record that binds the recovery public key. Keep `BOOTSTRAP_TRUST` outside every evidence package. Save its hash through an independent controlled channel and protect/backup the checkpoint; if the current signer was already compromised before this bootstrap, do not trust a newly introduced recovery key.

## 3. Routine rotation

Generate a new signer identity at a new path; never overwrite the old identity. Replace `TRUST` and `CURRENT_PACKAGE` with the latest trusted values. Use a new output path for both outputs.

```sh
TRUST="$BOOTSTRAP_TRUST"
CURRENT_PACKAGE="$BOOTSTRAP_PACKAGE"
NEW_IDENTITY="$HOME/.config/molt-forge/manifest-signer-next-identity.json"
node "$ROOT/bin/molt-keyctl.mjs" generate-identity --purpose manifest-signer --out "$NEW_IDENTITY"
stat -c '%a %n' "$NEW_IDENTITY"
node "$ROOT/bin/molt-keyctl.mjs" inspect-identity --identity "$NEW_IDENTITY"
ROTATED_PACKAGE="$HOME/molt-managed/package-rotated"
ROTATED_TRUST="$HOME/molt-managed/trust-rotated.json"
node "$ROOT/bin/molt-keyctl.mjs" rotate --package "$CURRENT_PACKAGE" --trust "$TRUST" --old-identity "$IDENTITY" --new-identity "$NEW_IDENTITY" --out "$ROTATED_PACKAGE" --trust-out "$ROTATED_TRUST"
node "$ROOT/bin/molt-keyctl.mjs" verify --package "$ROTATED_PACKAGE" --trust "$ROTATED_TRUST"
sha256sum "$ROTATED_TRUST"
```

Expected: the new package verifies with the latest trust file. The rotation record has valid old-key authorization and new-key proof. Checking the original package against `ROTATED_TRUST` must fail with `FAIL check: SIGNER_RETIRED;`. Preserve the original unchanged. After recording the new checkpoint hash independently, set `IDENTITY="$NEW_IDENTITY"`, `CURRENT_PACKAGE="$ROTATED_PACKAGE"`, and `TRUST="$ROTATED_TRUST"`; use those values for subsequent operations. Keep every previous checkpoint as an auditable record, but never treat an older checkpoint as current.

## 4. Revoke a non-current key

Ordinary revocation is for a key already retired or otherwise not current. Copy the `keyId` for the target from its `inspect-identity` output; this is public metadata. Use the current package and trust checkpoint.

```sh
RETIRED_KEY_ID="<keyId printed by inspect-identity>"
REVOKED_PACKAGE="$HOME/molt-managed/package-after-revocation"
REVOKED_TRUST="$HOME/molt-managed/trust-after-revocation.json"
node "$ROOT/bin/molt-keyctl.mjs" revoke --package "$CURRENT_PACKAGE" --trust "$TRUST" --recovery-identity "$RECOVERY" --key-id "$RETIRED_KEY_ID" --out "$REVOKED_PACKAGE" --trust-out "$REVOKED_TRUST"
node "$ROOT/bin/molt-keyctl.mjs" verify --package "$REVOKED_PACKAGE" --trust "$REVOKED_TRUST"
sha256sum "$REVOKED_TRUST"
```

Expected: the current package still prints `PASS`; an artifact signed by the revoked key fails with `KEY_REVOKED`. Revoking the active key through `revoke` is intentionally refused; use the emergency procedure.

## 5. Compromise response

If the active key may have been taken, stop issuing manifests and isolate the affected machine/account. Preserve original packages and source artifacts unchanged. Do not use the suspected key to authorize its own replacement. Confirm the last trusted checkpoint and the recovery identity. Generate a fresh signer identity, then let the recovery key revoke the compromised signer and authorize the new key in one emergency transition.

```sh
CURRENT_PACKAGE="${ROTATED_PACKAGE:-$BOOTSTRAP_PACKAGE}"
TRUST="${ROTATED_TRUST:-$BOOTSTRAP_TRUST}"
EMERGENCY_IDENTITY="$HOME/.config/molt-forge/manifest-signer-emergency-identity.json"
node "$ROOT/bin/molt-keyctl.mjs" generate-identity --purpose manifest-signer --out "$EMERGENCY_IDENTITY"
EMERGENCY_PACKAGE="$HOME/molt-managed/package-emergency"
EMERGENCY_TRUST="$HOME/molt-managed/trust-emergency.json"
node "$ROOT/bin/molt-keyctl.mjs" emergency --package "$CURRENT_PACKAGE" --trust "$TRUST" --recovery-identity "$RECOVERY" --new-identity "$EMERGENCY_IDENTITY" --out "$EMERGENCY_PACKAGE" --trust-out "$EMERGENCY_TRUST"
node "$ROOT/bin/molt-keyctl.mjs" verify --package "$EMERGENCY_PACKAGE" --trust "$EMERGENCY_TRUST"
sha256sum "$EMERGENCY_TRUST"
```

Expected: emergency output verifies; checking a package signed by the compromised key against `EMERGENCY_TRUST` fails with `KEY_REVOKED`. The command writes a new package/checkpoint and does not modify its input. Store the new trust checkpoint and its hash independently, then use it for every verifier and manifest consumer.

Already-signed artifacts are treated as untrusted under the new checkpoint, even if they may predate discovery. Compare each candidate artifact with independent source records and review its contents/provenance. Only if that review succeeds, re-issue a copy under the current signer:

```sh
AFFECTED_PACKAGE="$HOME/path/to/affected-old-package"
REISSUED_PACKAGE="$HOME/molt-managed/package-reissued"
node "$ROOT/bin/molt-keyctl.mjs" reissue --package "$AFFECTED_PACKAGE" --trust "$EMERGENCY_TRUST" --new-identity "$EMERGENCY_IDENTITY" --out "$REISSUED_PACKAGE" --reviewed
node "$ROOT/bin/molt-keyctl.mjs" verify --package "$REISSUED_PACKAGE" --trust "$EMERGENCY_TRUST"
```

`--reviewed` is an owner assertion, not an automated provenance check. If source integrity or provenance is uncertain, do not re-issue; keep the artifact marked untrusted. The original file remains unchanged. If the recovery key is also compromised or the latest checkpoint cannot be trusted, stop for a separate owner-governed recovery decision; this tool cannot safely invent a new root of trust.

## Verification and rollback limits

A successful `verify` must print `PASS check: KEY_HISTORY_CURRENT + standalone-molt-v1`. Expected negative checks include `SIGNER_RETIRED`, `KEY_REVOKED`, `ROTATION_PROOF_INVALID`, `GENESIS_PROOF_INVALID`, and `INDEPENDENT_VERIFIER_FAIL` with the L1 verifier's reason. All consumers must receive the latest separately held trust checkpoint. A stale checkpoint can still accept a package from its own earlier state; this offline tool cannot discover a newer checkpoint or prevent rollback if both the checkpoint and its independent backup are replaced.

The manifest signer identity file's actual JSON schema was not included in the supplied sources, so these commands have only been tested with the package's `molt.ed25519-identity.v1` test identities. The owner must run `inspect-identity` locally and stop if the real file is not compatible. No real-key rotation is performed by this bundle.
