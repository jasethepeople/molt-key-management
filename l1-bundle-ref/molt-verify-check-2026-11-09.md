# Foundry verifier extractability check — 2026-11-09

Source: GitLab `jasonclarkagain-group/master-dev-team` (id 88135081), branch main, read via API. No writes, no pushes.

## Verdict: extractable. Only one gap — no CLI.

The verifier is `foundry/independent-verifier.ts` (137 lines), one export:
`independentlyVerifyMoltPackage(directory)` — reads `manifest.json`, `events.jsonl`,
`ed25519-public.pem` from the given directory and checks artifact digests, the hash
chain, Ed25519 signatures, and actor binding. Own JCS-style canonicalizer, own
sha256, size limits, path-traversal hardening.

## Failure-mode check (from the molt-verify gate)

1. Imports the signing module — CLEAR. Runtime imports are only `node:crypto`,
   `node:fs/promises`, `node:path`.
2. Reads `<FOUNDRY_DATA_DIR>.signing` — CLEAR. Reads only files inside the
   passed directory.
3. Only exists inside tests — CLEAR. Real module in `foundry/`; tests only call
   it. It is also wired into production: `foundry/run.ts:58` fails a run if the
   independent verification fails, and the service returns both reports
   (`FoundryVerification.independent`, types.ts:134).
4. Depends on Foundry schemas/config at runtime — CLEAR. Inline structural
   checks only; no schema or config imports.
5. No CLI — APPLIES. No verify script in package.json (scripts are
   dev/build/prod/preview/typecheck/test/foundry:run). Fix: small CLI wrapper
   taking a directory, printing PASS/FAIL + reason — about half a day.
6. Reads mutable state — CLEAR. Reads only the passed directory.

## Types needed (all pure `export type`, foundry/types.ts)

`MOLTEventBody` (105), `MOLTEvent` (113), `VerificationReport` (121),
`IndependentVerificationReport` (129). The verifier imports them with
`import type`, so they are erased at runtime — copy ~30 lines into the new repo.

## Proven by test (tests/foundry.test.ts:202-211)

A real signed ledger built by `MoltLedger` verifies valid; tampering one payload
field makes both the primary (`ledger.ts:363`) and independent verifiers fail.
The primary and independent verifiers are separate implementations (the
independent one has its own canonicalizer; it imports nothing from ledger.ts).

## Still missing for molt-verify

- The sample pair (sample-good + sample-tampered). No shipped sample package
  exists in the repo — the test builds its package on the fly. Must come from
  the iknow laptop's Foundry ledger (check it holds signed events first).
- The CLI wrapper (failure mode 5).

## Bottom line

molt-verify is a half-day to a day of work once the sample package exists. The
gate is now the laptop ledger, not the code.
