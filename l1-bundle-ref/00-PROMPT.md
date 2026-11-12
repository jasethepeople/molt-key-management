# Prompt for Zo — build molt-verify, layer 1: standalone verifier + CLI + sample pair

Paste this into a NEW Zo chat, with the files listed at the bottom attached in the same chat.

## What this is

molt-verify is the public proof that a MOLT signed package is real. The owner's GitLab group stays private (it holds live Foundry code and may hold secrets), so the verifier must live in its own new public GitHub repo: schemas + standalone verifier + a sample-good package + a sample-tampered package + README. The verifier already exists inside Foundry — your job is to extract it, give it a CLI, and prove it with the sample pair. Layer 1 only. Layer 2 (a second, ideally different-language verifier agreeing under differential fuzzing) is a SEPARATE round — do not build it here and do not conflate it with layer 1.

## Source (read this first)

- The verifier is `foundry/independent-verifier.ts` (137 lines, attached in `source/`). One export: `independentlyVerifyMoltPackage(directory)` — reads `manifest.json`, `events.jsonl`, `ed25519-public.pem` from the given directory and checks artifact digests, the hash chain, Ed25519 signatures, and actor binding. It has its own JCS-style canonicalizer and its own sha256, plus size limits and path-traversal hardening.
- It was checked extractable on Nov 9: runtime imports are only `node:crypto`, `node:fs/promises`, `node:path`. It reads only files inside the passed directory. It imports the types with `import type` (erased at runtime). It is wired into production (`foundry/run.ts:58` fails a run if independent verification fails). The check doc is attached (`molt-verify-check-2026-11-09.md`) — read it.
- Types needed (all pure `export type`, in attached `source/types.ts`): `MOLTEventBody`, `MOLTEvent`, `VerificationReport`, `IndependentVerificationReport`. Copy those ~30 lines into the new repo.
- Proven by test (attached `source/tests/foundry.test.ts`, lines 202-211): a real signed ledger built by `MoltLedger` verifies valid; tampering one payload field makes BOTH the primary verifier (`foundry/ledger.ts:363`, attached for reference) and the independent verifier fail. The two verifiers are separate implementations — the independent one imports nothing from ledger.ts.
- WARNING on sources: the live deployable Foundry tree (Kimi Seed Update 11) does NOT contain a `foundry/` directory — the verifier comes from the GitLab master-dev-team tree, attached in `source/`. If you find the verifier differs between any two sources you can read, the attached source wins and you must say so in the report.

## What to build

1. **Standalone package.** The verifier plus the copied types, nothing else from Foundry. Runtime imports stay `node:crypto`, `node:fs/promises`, `node:path` only. No Foundry imports at runtime, no schema or config imports, no network, no mutable state — it reads only the directory it is given.
2. **CLI wrapper (the one known gap).** A small CLI taking a directory, printing PASS or FAIL plus the name of the failing check. It must run standalone in a fresh empty directory with only node and the package — no Foundry checkout, no build step beyond the package itself.
3. **Sample pair.** A `sample-good` package that MUST pass, and a `sample-tampered` package that MUST fail, naming the check that caught it.
   - The only real signed events live in the Foundry ledger on the owner's iknow laptop, which you cannot reach. So build the pair by generating a signed ledger with the same code paths the test uses (`MoltLedger` + the independent verifier, as in `tests/foundry.test.ts:202-211`), then tamper one payload field for the tampered sample.
   - Say PLAINLY in the report that the samples are locally generated, not from the laptop ledger. Do NOT claim they came from the laptop. Swapping in a real laptop-ledger sample later is a one-file change — say that too.
4. **README.** What it verifies, how to run it, what each failure means, and the honest limit: this proves a package verifies, not that the events in it are true.

## Hard rules

- No pushes to GitHub. No deploys. No secrets in any file. No paid services.
- Secret-scan the tree before delivery. The whole point of this repo is that it goes public — if anything secret-shaped is in it, stop and report, do not deliver it.
- Do not build layer 2 in this round.
- Follow the attached backend-prime skill for how to build, test, and report.

## Deliverables

A zip with every file (standalone package, CLI, sample-good, sample-tampered, README), plus a written report: what you built, test results (including sample-good PASS and sample-tampered FAIL naming the check), what is still open (layer 2 second verifier + differential fuzzing; the laptop-ledger sample swap), and the next phase. Stop and report when done.

## Files to attach in the chat

- backend-prime SKILL.md (the process — follow it)
- molt-verify-check-2026-11-09.md (the extractability check — read it first)
- source/independent-verifier.ts, source/types.ts, source/ledger.ts (reference only), source/run.ts (caller proof), source/tests/foundry.test.ts
