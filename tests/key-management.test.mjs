import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";

import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { reissuePackage, verifyPackage } from "../src/key-management.mjs";
import { independentlyVerifyMoltPackage } from "../source/independent-verifier.ts";

const roots = new Set();
const testDirectory = dirname(fileURLToPath(import.meta.url));
const cliPath = fileURLToPath(new URL("../bin/molt-keyctl.mjs", import.meta.url));
const PRIVATE_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
async function treeDigest(root, directory = root, entries = []) {
  const children = await readdir(directory, { withFileTypes: true });
  children.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const child of children) {
    const path = join(directory, child.name);
    if (child.isDirectory()) await treeDigest(root, path, entries);
    else if (child.isFile()) entries.push(`${relative(root, path)}:${sha256(await readFile(path))}`);
    else throw new Error("Test fixture contains a non-regular file.");
  }
  return sha256(entries.join("\n"));
}
function runCli(args) {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: testDirectory,
    env: { PATH: process.env.PATH || "" },
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  return result;
}


function stableString(value) {
  let out = '"';
  for (const character of value) {
    const point = character.codePointAt(0);
    if (character === '"') out += '\\"';
    else if (character === "\\") out += "\\\\";
    else if (character === "\b") out += "\\b";
    else if (character === "\f") out += "\\f";
    else if (character === "\n") out += "\\n";
    else if (character === "\r") out += "\\r";
    else if (character === "\t") out += "\\t";
    else if (point < 0x20 || point > 0x7e) {
      const units = character.length === 2 ? [character.charCodeAt(0), character.charCodeAt(1)] : [point];
      out += units.map((unit) => `\\u${unit.toString(16).padStart(4, "0")}`).join("");
    } else out += character;
  }
  return `${out}"`;
}

function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") return stableString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => `${stableString(key)}:${canonical(value[key])}`).join(",")}}`;
}

function privateObject(seed) {
  return createPrivateKey({ key: Buffer.concat([PRIVATE_PREFIX, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
}

function publicObject(publicHex) {
  return createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, Buffer.from(publicHex, "hex")]), format: "der", type: "spki" });
}

async function testRoot() {
  const root = await mkdtemp(join(tmpdir(), "molt-key-management-TEST-ONLY-"));
  roots.add(root);
  return root;
}

after(async () => {
  for (const root of roots) await rm(root, { recursive: true, force: true });
});

async function createTestIdentity(root, name) {
  const path = join(root, `${name}-TEST-ONLY-identity.json`);
  const generated = runCli(["generate-identity", "--out", path, "--purpose", "TEST-ONLY"]);
  assert.equal(generated.status, 0, generated.stderr);
  assert.doesNotMatch(generated.stdout, /privateKeyHex/);
  const identity = JSON.parse(await readFile(path, "utf8"));
  return { ...identity, path, privateKey: privateObject(identity.privateKeyHex) };
}

function signedNote(identity) {
  const statement = [
    "MOLT Forge demo video v2 manifest",
    "video sha256: 7a70370c6d3b82a95eb1d4caa8961ff5bc03944acacf0776afc86c057829781a",
    "duration: 151.866016s",
    "approved: 2026-10-30",
  ].join("\n");
  const signatureHex = sign(null, Buffer.from(statement, "utf8"), identity.privateKey).toString("hex");
  return `# TEST-ONLY manifest signer fixture\n\n## Signature status\n\nStatement signed (exact bytes, UTF-8):\n\n\`\`\`\n${statement}\n\`\`\`\n\nPublic key (hex): ${identity.publicKeyHex}\nSignature (hex): ${signatureHex}\n`;
}

async function makeEvidencePackage(root, identity, actor = "molt-forge-demo") {
  const packageDir = join(root, "TEST-ONLY-package");
  await mkdir(packageDir, { recursive: true });
  const artifact = Buffer.from("TEST-ONLY evidence artifact\n");
  await writeFile(join(packageDir, "artifact.bin"), artifact);
  const notePath = join(packageDir, "manifest-note.md");
  const note = signedNote(identity);
  await writeFile(notePath, note);
  const body = { seq: 0, ts: 1791590400000, type: "manifest.created", payload: { label: "TEST-ONLY" }, actor };
  const eventHash = sha256(`${"0".repeat(64)}${canonical(body)}`);
  const event = {
    ...body,
    prev_hash: "0".repeat(64),
    hash: eventHash,
    pub: identity.publicKeyHex,
    sig: sign(null, Buffer.from(eventHash, "hex"), identity.privateKey).toString("hex"),
  };
  await writeFile(join(packageDir, "events.jsonl"), `${JSON.stringify(event)}\n`);
  await writeFile(join(packageDir, "ed25519-public.pem"), publicObject(identity.publicKeyHex).export({ format: "pem", type: "spki" }));
  const manifest = {
    schema: "molt.evidence.v1",
    key_management_fixture: "TEST-ONLY",
    artifacts: { "artifact.bin": sha256(artifact), "manifest-note.md": sha256(Buffer.from(note)) },
    agent_pubkeys: { [actor]: identity.publicKeyHex },
  };
  await writeFile(join(packageDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { packageDir, notePath };
}

async function fixture() {
  const root = await testRoot();
  const old = await createTestIdentity(root, "old");
  const recovery = await createTestIdentity(root, "recovery");
  const next = await createTestIdentity(root, "next");
  const evidence = await makeEvidencePackage(root, old);
  const packageDir = join(root, "TEST-ONLY-bootstrapped");
  const trustPath = join(root, "TEST-ONLY-trust.json");
  const bootstrapped = runCli(["bootstrap", "--package", evidence.packageDir, "--manifest-note", evidence.notePath, "--current-identity", old.path, "--recovery-identity", recovery.path, "--out", packageDir, "--trust-out", trustPath]);
  assert.equal(bootstrapped.status, 0, bootstrapped.stderr);
  return { root, old, recovery, next, originalPackage: packageDir, trustPath };
}

async function rotate(fx, identity = fx.next, suffix = "rotated") {
  const packageDir = join(fx.root, `TEST-ONLY-${suffix}`);
  const trustPath = join(fx.root, `TEST-ONLY-${suffix}-trust.json`);
  const result = runCli(["rotate", "--package", fx.originalPackage, "--trust", fx.trustPath, "--old-identity", fx.old.path, "--new-identity", identity.path, "--out", packageDir, "--trust-out", trustPath]);
  assert.equal(result.status, 0, result.stderr);
  return { packageDir, trustPath, result: JSON.parse(result.stdout) };
}

describe("MOLT manifest signer key management (fresh TEST-ONLY directories)", () => {
  it("accepts the original signer before rotation with the attached independent verifier", async () => {
    const fx = await fixture();
    const report = await verifyPackage(fx.originalPackage, fx.trustPath);
    assert.equal(report.valid, true);
    assert.equal(report.count, 1);
    assert.equal(report.verifier, "standalone-molt-v1");
  });

  it("requires an external trust checkpoint and the emergency path for active-key revocation", async () => {
    const fx = await fixture();
    await assert.rejects(() => verifyPackage(fx.originalPackage, join(fx.originalPackage, "key-history.json")), (error) => error.check === "TRUST_MUST_BE_EXTERNAL");
    const result = runCli(["revoke", "--package", fx.originalPackage, "--trust", fx.trustPath, "--recovery-identity", fx.recovery.path, "--key-id", fx.old.keyId, "--out", join(fx.root, "TEST-ONLY-invalid-revoke"), "--trust-out", join(fx.root, "TEST-ONLY-invalid-trust.json")]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^FAIL check: CURRENT_KEY_REQUIRES_COMPROMISE;/);
  });

  it("creates TEST-ONLY identities with owner-only permissions and inspects public metadata without exposing the seed", async () => {
    const fx = await fixture();
    const info = await stat(fx.next.path);
    assert.equal(info.mode & 0o077, 0);
    const result = runCli(["inspect-identity", "--identity", fx.next.path]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"purpose": "TEST-ONLY"/);
    assert.match(result.stdout, new RegExp(fx.next.publicKeyHex));
    assert.doesNotMatch(result.stdout, new RegExp(fx.next.privateKeyHex));
  });

  it("rejects an attacker-substituted recovery key at GENESIS_PROOF_INVALID", async () => {
    const fx = await fixture();
    const attacker = await createTestIdentity(fx.root, "attacker-recovery");
    const trust = JSON.parse(await readFile(fx.trustPath, "utf8"));
    const genesis = trust.history.genesis;
    genesis.recoveryKeyId = attacker.keyId;
    genesis.recoveryPublicKeyHex = attacker.publicKeyHex;
    const { hash, proofs, ...core } = genesis;
    genesis.hash = sha256(canonical(core));
    trust.history.genesis = genesis;
    await writeFile(fx.trustPath, `${JSON.stringify(trust, null, 2)}\n`);
    await assert.rejects(() => verifyPackage(fx.originalPackage, fx.trustPath), (error) => error.check === "GENESIS_PROOF_INVALID");
  });

  it("rotates with old-key authorization and new-key proof; new package passes both checks", async () => {
    const fx = await fixture();
    const rotated = await rotate(fx);
    const report = await verifyPackage(rotated.packageDir, rotated.trustPath);
    const history = JSON.parse(await readFile(join(rotated.packageDir, "key-history.json"), "utf8"));
    const record = history.records[0];
    const signedHash = Buffer.from(record.hash, "hex");
    assert.equal(verify(null, signedHash, publicObject(fx.old.publicKeyHex), Buffer.from(record.proofs.old, "hex")), true);
    assert.equal(verify(null, signedHash, publicObject(fx.next.publicKeyHex), Buffer.from(record.proofs.new, "hex")), true);
    assert.equal(report.valid, true);
    assert.equal(report.verifier, "standalone-molt-v1");
  });

  it("rejects the old signer after rotation at SIGNER_RETIRED while the legacy independent check alone still validates its package", async () => {
    const fx = await fixture();
    const rotated = await rotate(fx);
    await assert.rejects(() => verifyPackage(fx.originalPackage, rotated.trustPath), (error) => error.check === "SIGNER_RETIRED");
    assert.equal((await verifyPackage(fx.originalPackage, fx.trustPath)).valid, true);
    const underlying = await independentlyVerifyMoltPackage(fx.originalPackage);
    assert.equal(underlying.valid, true);
  });

  it("rejects a revoked key at KEY_REVOKED while the current good signer remains accepted", async () => {
    const fx = await fixture();
    const rotated = await rotate(fx);
    const revokedDir = join(fx.root, "TEST-ONLY-after-revocation");
    const revokedTrust = join(fx.root, "TEST-ONLY-after-revocation-trust.json");
    const revoked = runCli(["revoke", "--package", rotated.packageDir, "--trust", rotated.trustPath, "--recovery-identity", fx.recovery.path, "--key-id", fx.old.keyId, "--out", revokedDir, "--trust-out", revokedTrust]);
    assert.equal(revoked.status, 0, revoked.stderr);
    assert.equal((await verifyPackage(revokedDir, revokedTrust)).valid, true);
    await assert.rejects(() => verifyPackage(fx.originalPackage, revokedTrust), (error) => error.check === "KEY_REVOKED");
  });

  it("rejects a rotation record whose new-key proof was removed at ROTATION_PROOF_INVALID", async () => {
    const fx = await fixture();
    const rotated = await rotate(fx);
    const historyPath = join(rotated.packageDir, "key-history.json");
    const history = JSON.parse(await readFile(historyPath, "utf8"));
    delete history.records[0].proofs.new;
    await writeFile(historyPath, `${JSON.stringify(history, null, 2)}\n`);
    const trust = JSON.parse(await readFile(rotated.trustPath, "utf8"));
    trust.history = history;
    await writeFile(rotated.trustPath, `${JSON.stringify(trust, null, 2)}\n`);
    await assert.rejects(() => verifyPackage(rotated.packageDir, rotated.trustPath), (error) => error.check === "ROTATION_PROOF_INVALID");
  });

  it("rejects a manifest note signed by the wrong key at MANIFEST_NOTE_SIGNATURE_INVALID", async () => {
    const fx = await fixture();
    const notePath = join(fx.originalPackage, "manifest-note.md");
    let note = await readFile(notePath, "utf8");
    const match = note.match(/Signature \(hex\): ([a-f0-9]{128})/);
    assert.ok(match);
    const invalid = `${match[1][0] === "0" ? "1" : "0"}${match[1].slice(1)}`;
    note = note.replace(match[1], invalid);
    await writeFile(notePath, note);
    const manifestPath = join(fx.originalPackage, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.artifacts["manifest-note.md"] = sha256(Buffer.from(note));
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await assert.rejects(() => verifyPackage(fx.originalPackage, fx.trustPath), (error) => error.check === "MANIFEST_NOTE_SIGNATURE_INVALID");
  });

  it("rejects event tampering through the attached independent verifier", async () => {
    const fx = await fixture();
    const eventPath = join(fx.originalPackage, "events.jsonl");
    const event = JSON.parse((await readFile(eventPath, "utf8")).trim());
    event.payload.label = "tampered";
    await writeFile(eventPath, `${JSON.stringify(event)}\n`);
    await assert.rejects(() => verifyPackage(fx.originalPackage, fx.trustPath), (error) => error.check === "INDEPENDENT_VERIFIER_FAIL" && error.message.includes("Event content hash is invalid"));
  });

  it("runs compromise response end to end, revokes the taken key, and re-issues only after review", async () => {
    const fx = await fixture();
    const emergency = await createTestIdentity(fx.root, "emergency-new");
    const before = await treeDigest(fx.originalPackage);
    const emergencyDir = join(fx.root, "TEST-ONLY-emergency-package");
    const emergencyTrust = join(fx.root, "TEST-ONLY-emergency-trust.json");
    const emergencyRun = runCli(["emergency", "--package", fx.originalPackage, "--trust", fx.trustPath, "--recovery-identity", fx.recovery.path, "--new-identity", emergency.path, "--out", emergencyDir, "--trust-out", emergencyTrust]);
    assert.equal(emergencyRun.status, 0, emergencyRun.stderr);
    const verified = runCli(["verify", "--package", emergencyDir, "--trust", emergencyTrust]);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /PASS check: KEY_HISTORY_CURRENT \+ standalone-molt-v1; count=1/);
    const oldVerify = runCli(["verify", "--package", fx.originalPackage, "--trust", emergencyTrust]);
    assert.equal(oldVerify.status, 1);
    assert.match(oldVerify.stderr, /^FAIL check: KEY_REVOKED;/);
    const reissuedDir = join(fx.root, "TEST-ONLY-reissued-package");
    const reissueRun = runCli(["reissue", "--package", fx.originalPackage, "--trust", emergencyTrust, "--new-identity", emergency.path, "--out", reissuedDir, "--reviewed"]);
    assert.equal(reissueRun.status, 0, reissueRun.stderr);
    assert.equal((await verifyPackage(reissuedDir, emergencyTrust)).valid, true);
    assert.equal(await treeDigest(fx.originalPackage), before);
    assert.equal((await verifyPackage(emergencyDir, emergencyTrust)).valid, true);
  });

  it("requires owner review before re-issuing already-signed artifacts", async () => {
    const fx = await fixture();
    await assert.rejects(() => reissuePackage({ packageDir: fx.originalPackage, trustPath: fx.trustPath, newIdentityPath: fx.old.path, outDir: join(fx.root, "TEST-ONLY-unreviewed"), reviewed: false }), (error) => error.check === "REVIEW_REQUIRED");
  });
});
