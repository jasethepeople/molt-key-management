import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { independentlyVerifyMoltPackage } from "../source/independent-verifier.ts";
import { canonicalizeJsonText } from "../source/molt-canonical.mjs";

const PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PRIVATE_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ZERO_HASH = "0".repeat(64);
const HISTORY_SCHEMA = "molt.key-history.v1";
const TRUST_SCHEMA = "molt.key-trust.v1";
const IDENTITY_SCHEMA = "molt.ed25519-identity.v1";

export class KeyManagementError extends Error {
  constructor(check, message) {
    super(message);
    this.name = "KeyManagementError";
    this.check = check;
  }
}

function fail(check, message) {
  throw new KeyManagementError(check, message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stableString(value) {
  let out = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (character === '"') out += '\\"';
    else if (character === "\\") out += "\\\\";
    else if (character === "\b") out += "\\b";
    else if (character === "\f") out += "\\f";
    else if (character === "\n") out += "\\n";
    else if (character === "\r") out += "\\r";
    else if (character === "\t") out += "\\t";
    else if (codePoint < 0x20 || codePoint > 0x7e) {
      const units = character.length === 2 ? [character.charCodeAt(0), character.charCodeAt(1)] : [codePoint];
      out += units.map((unit) => `\\u${unit.toString(16).padStart(4, "0")}`).join("");
    } else out += character;
  }
  return `${out}"`;
}

function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") return stableString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("HISTORY_FORMAT_INVALID", "Key history contains a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail("HISTORY_FORMAT_INVALID", "Key history is not plain JSON.");
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => `${stableString(key)}:${canonical(value[key])}`).join(",")}}`;
}

function publicKeyObject(publicKeyHex) {
  if (!/^[a-f0-9]{64}$/i.test(publicKeyHex)) fail("PUBLIC_KEY_FORMAT_INVALID", "Ed25519 public key must be 32-byte hex.");
  return createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, Buffer.from(publicKeyHex, "hex")]), format: "der", type: "spki" });
}

function privateKeyObject(privateKeyHex) {
  if (!/^[a-f0-9]{64}$/i.test(privateKeyHex)) fail("IDENTITY_FORMAT_INVALID", "Ed25519 private seed must be 32-byte hex.");
  return createPrivateKey({ key: Buffer.concat([PRIVATE_PREFIX, Buffer.from(privateKeyHex, "hex")]), format: "der", type: "pkcs8" });
}

function keyId(publicKeyHex) {
  return sha256(Buffer.from(publicKeyHex, "hex"));
}

function rawPublicKey(key) {
  const der = key.export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32).toString("hex");
}

function publicPem(publicKeyHex) {
  return publicKeyObject(publicKeyHex).export({ format: "pem", type: "spki" }).toString();
}

function createIdentity(purpose = "manifest-signer") {
  const pair = generateKeyPairSync("ed25519");
  const privateDer = Buffer.from(pair.privateKey.export({ format: "der", type: "pkcs8" }));
  const publicKeyHex = rawPublicKey(pair.publicKey);
  const identity = {
    schema: IDENTITY_SCHEMA,
    purpose,
    algorithm: "Ed25519",
    privateKeyHex: privateDer.subarray(-32).toString("hex"),
    publicKeyHex,
    keyId: keyId(publicKeyHex),
  };
  return identity;
}

async function readIdentity(path) {
  let identity;
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink()) fail("IDENTITY_FILE_INVALID", "Identity must be a regular, non-symlink file.");
    if ((info.mode & 0o077) !== 0) fail("IDENTITY_PERMISSIONS_INVALID", "Identity file must be owner-only (mode 600 or stricter).");
    if (info.size > 16_384) fail("IDENTITY_FILE_TOO_LARGE", "Identity file exceeds the 16 KiB limit.");
    identity = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error instanceof KeyManagementError) throw error;
    fail("IDENTITY_FORMAT_INVALID", "Identity file is not readable JSON in the documented molt.ed25519-identity.v1 format.");
  }
  // Accept the real Forge identity file format in addition to molt.ed25519-identity.v1.
  // The Forge file is {"manifest-signer": {"priv": "<64-hex seed>", "pub": "<64-hex key>"}}.
  // It carries no schema/algorithm/purpose/keyId fields, so normalize it to the v1 shape.
  // The pair-mismatch check below then verifies priv actually derives to pub.
  // Files already in v1 format (with a schema field) are left untouched.
  if (identity && typeof identity === "object" && !Array.isArray(identity) && identity.schema === undefined) {
    const forge = identity["manifest-signer"];
    if (forge && typeof forge === "object" && typeof forge.priv === "string" && typeof forge.pub === "string" && /^[a-f0-9]{64}$/i.test(forge.priv) && /^[a-f0-9]{64}$/i.test(forge.pub)) {
      identity = {
        schema: IDENTITY_SCHEMA,
        algorithm: "Ed25519",
        purpose: "manifest-signer",
        privateKeyHex: forge.priv,
        publicKeyHex: forge.pub,
        keyId: keyId(forge.pub),
      };
    }
  }
  if (!identity || identity.schema !== IDENTITY_SCHEMA || identity.algorithm !== "Ed25519" || !["TEST-ONLY", "manifest-signer", "recovery"].includes(identity.purpose)) fail("IDENTITY_FORMAT_INVALID", "Identity file schema or purpose is not supported.");
  const privateKey = privateKeyObject(identity.privateKeyHex);
  const actualPublicHex = rawPublicKey(createPublicKey(privateKey));
  if (actualPublicHex !== identity.publicKeyHex || identity.keyId !== keyId(actualPublicHex)) fail("IDENTITY_PAIR_MISMATCH", "Identity public key does not match its private key.");
  return { ...identity, privateKey };
}

export async function generateIdentityFile(path, purpose = "manifest-signer") {
  if (!["TEST-ONLY", "manifest-signer", "recovery"].includes(purpose)) fail("IDENTITY_PURPOSE_INVALID", "Purpose must be TEST-ONLY, manifest-signer, or recovery.");
  const identity = createIdentity(purpose);
  const { privateKeyHex, ...publicFields } = identity;
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, `${JSON.stringify(identity, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
  return { ...publicFields, privateKeyHex: undefined };
}

export async function inspectIdentityFile(path) {
  const identity = await readIdentity(path);
  return {
    schema: identity.schema,
    purpose: identity.purpose,
    algorithm: identity.algorithm,
    publicKeyHex: identity.publicKeyHex,
    keyId: identity.keyId,
  };
}

function parseManifestNote(text) {
  const marker = "Statement signed (exact bytes, UTF-8):";
  const first = text.indexOf(marker);
  if (first < 0 || text.indexOf(marker, first + marker.length) >= 0) fail("MANIFEST_NOTE_FORMAT_INVALID", "Manifest note must contain exactly one signed-entry section.");
  const tail = text.slice(first);
  const block = /Statement signed \(exact bytes, UTF-8\):\r?\n\r?\n```\r?\n([\s\S]*?)\r?\n```/.exec(tail);
  if (!block) fail("MANIFEST_NOTE_FORMAT_INVALID", "Manifest note lacks the documented fenced UTF-8 statement.");
  const linePattern = /^Public key \(hex\): ([a-f0-9]{64})\r?\nSignature \(hex\): ([a-f0-9]{128})$/gm;
  const fields = [...text.matchAll(linePattern)];
  if (fields.length !== 1) fail("MANIFEST_NOTE_FORMAT_INVALID", "Manifest note must contain exactly one public-key/signature pair.");
  return { statement: block[1], publicKeyHex: fields[0][1], signatureHex: fields[0][2] };
}

function verifyManifestNote(text, expectedPublicKeyHex) {
  const parsed = parseManifestNote(text);
  if (parsed.publicKeyHex !== expectedPublicKeyHex) fail("MANIFEST_NOTE_KEY_MISMATCH", "Signed manifest note does not name the package public key.");
  const valid = verify(null, Buffer.from(parsed.statement, "utf8"), publicKeyObject(parsed.publicKeyHex), Buffer.from(parsed.signatureHex, "hex"));
  if (!valid) fail("MANIFEST_NOTE_SIGNATURE_INVALID", "Signed manifest note signature is invalid.");
  return parsed;
}

async function readJson(path, check) {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 8_000_000) fail(check, `${basename(path)} is not a regular JSON file within the size limit.`);
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error instanceof KeyManagementError) throw error;
    fail(check, `${basename(path)} is missing or is not valid JSON.`);
  }
}

async function writeJson(path, value, exclusive = false) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { flag: exclusive ? "wx" : "w", mode: 0o600 });
}

async function copyTree(source, destination, createRoot = true) {
  if (createRoot) await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    const info = await lstat(from);
    if (info.isSymbolicLink()) fail("PACKAGE_SYMLINK_REJECTED", "Package copies do not permit symbolic links.");
    if (info.isDirectory()) await copyTree(from, to);
    else if (info.isFile()) await copyFile(from, to);
    else fail("PACKAGE_FILETYPE_REJECTED", "Package contains a non-regular file.");
  }
}

async function ensureNewDirectory(path) {
  try {
    await mkdir(path, { recursive: false });
  } catch {
    fail("OUTPUT_EXISTS", "Output directory already exists or cannot be created; choose a new empty path.");
  }
}

function assertOutsidePackage(candidate, packageDir) {
  const rel = relative(resolve(packageDir), resolve(candidate));
  if (rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`))) fail("TRUST_MUST_BE_EXTERNAL", "The trusted checkpoint must be stored outside every evidence package.");
}

function stateFromHistory(history) {
  if (!history || history.schema !== HISTORY_SCHEMA || !history.genesis || !Array.isArray(history.records)) fail("HISTORY_FORMAT_INVALID", "Key history schema is invalid.");
  const genesis = history.genesis;
  if (genesis.schema !== "molt.key-genesis.v1" || genesis.currentKeyId !== keyId(genesis.currentPublicKeyHex) || genesis.recoveryKeyId !== keyId(genesis.recoveryPublicKeyHex)) fail("GENESIS_INVALID", "Key history genesis keys are invalid.");
  const anchor = genesis.anchor;
  if (!anchor || anchor.publicKeyHex !== genesis.currentPublicKeyHex || sha256(Buffer.from(anchor.statement, "utf8")) !== anchor.statementSha256) fail("GENESIS_ANCHOR_INVALID", "Key history genesis anchor is malformed.");
  if (!verify(null, Buffer.from(anchor.statement, "utf8"), publicKeyObject(anchor.publicKeyHex), Buffer.from(anchor.signatureHex, "hex"))) fail("GENESIS_ANCHOR_SIGNATURE_INVALID", "Original manifest signature does not verify against the history anchor.");
  const { hash: genesisHash, proofs: genesisProofs, ...genesisCore } = genesis;
  if (genesisHash !== sha256(canonical(genesisCore))) fail("GENESIS_HASH_INVALID", "Key history genesis hash is invalid.");
  if (!genesisProofs || typeof genesisProofs.current !== "string" || !/^[a-f0-9]{128}$/.test(genesisProofs.current) || !verify(null, Buffer.from(genesisHash, "hex"), publicKeyObject(genesis.currentPublicKeyHex), Buffer.from(genesisProofs.current, "hex"))) fail("GENESIS_PROOF_INVALID", "Initial signer did not authorize the pinned recovery key.");
  let head = genesisHash;
  let currentKeyId = genesis.currentKeyId;
  const currentKeys = new Map([[genesis.currentKeyId, genesis.currentPublicKeyHex]]);
  const knownKeys = new Map([[genesis.currentKeyId, genesis.currentPublicKeyHex]]);
  const retired = new Set();
  const revoked = new Set();
  const recovery = { id: genesis.recoveryKeyId, publicKeyHex: genesis.recoveryPublicKeyHex };
  for (let index = 0; index < history.records.length; index += 1) {
    const record = history.records[index];
    if (!record || record.seq !== index + 1 || record.previousHash !== head || !record.proofs || typeof record.proofs !== "object") fail("HISTORY_CHAIN_INVALID", `Key history record ${index + 1} has an invalid sequence or predecessor.`);
    const { hash, proofs, ...core } = record;
    const expectedHash = sha256(`${head}${canonical(core)}`);
    if (hash !== expectedHash) fail("HISTORY_HASH_INVALID", `Key history record ${index + 1} hash is invalid.`);
    const signedHash = Buffer.from(hash, "hex");
    const checkProof = (pub, proof) => typeof proof === "string" && /^[a-f0-9]{128}$/.test(proof) && verify(null, signedHash, publicKeyObject(pub), Buffer.from(proof, "hex"));
    if (record.type === "rotate") {
      if (currentKeyId !== record.fromKeyId || currentKeys.get(currentKeyId) !== record.fromPublicKeyHex || record.toKeyId !== keyId(record.toPublicKeyHex) || knownKeys.has(record.toKeyId)) fail("ROTATION_STATE_INVALID", `Rotation record ${record.seq} does not transition the current key.`);
      if (!checkProof(record.fromPublicKeyHex, proofs.old) || !checkProof(record.toPublicKeyHex, proofs.new)) fail("ROTATION_PROOF_INVALID", `Rotation record ${record.seq} lacks valid old-key authorization or new-key proof.`);
      retired.add(currentKeyId);
      currentKeys.delete(currentKeyId);
      currentKeyId = record.toKeyId;
      currentKeys.set(currentKeyId, record.toPublicKeyHex);
      knownKeys.set(currentKeyId, record.toPublicKeyHex);
    } else if (record.type === "revoke") {
      const target = knownKeys.get(record.keyId);
      if (!target || !checkProof(recovery.publicKeyHex, proofs.recovery)) fail("REVOCATION_PROOF_INVALID", `Revocation record ${record.seq} targets an unknown key or lacks recovery-key authorization.`);
      if (record.keyId === currentKeyId) {
        if (record.compromise !== true) fail("CURRENT_KEY_REQUIRES_COMPROMISE", "Revoking the current key requires the explicit compromise path.");
        currentKeys.delete(currentKeyId);
        currentKeyId = null;
      } else if (record.compromise === true) fail("REVOCATION_STATE_INVALID", "Compromise revocation must target the active key.");
      revoked.add(record.keyId);
    } else if (record.type === "emergency-rotate") {
      if (currentKeyId !== null || !revoked.has(record.fromRevokedKeyId) || record.toKeyId !== keyId(record.toPublicKeyHex) || knownKeys.has(record.toKeyId)) fail("EMERGENCY_ROTATION_STATE_INVALID", `Emergency rotation record ${record.seq} does not follow current-key revocation.`);
      if (!checkProof(recovery.publicKeyHex, proofs.recovery) || !checkProof(record.toPublicKeyHex, proofs.new)) fail("EMERGENCY_ROTATION_PROOF_INVALID", `Emergency rotation record ${record.seq} lacks valid recovery authorization or new-key proof.`);
      currentKeyId = record.toKeyId;
      currentKeys.set(currentKeyId, record.toPublicKeyHex);
      knownKeys.set(currentKeyId, record.toPublicKeyHex);
    } else fail("HISTORY_RECORD_TYPE_INVALID", `Key history record ${record.seq} has an unknown operation.`);
    head = hash;
  }
  return {
    genesisHash,
    historyHead: head,
    currentKeyId,
    currentPublicKeyHex: currentKeyId === null ? null : currentKeys.get(currentKeyId),
    knownKeys,
    retiredKeyIds: [...retired].sort(),
    revokedKeyIds: [...revoked].sort(),
    recoveryKeyId: recovery.id,
    recoveryPublicKeyHex: recovery.publicKeyHex,
    genesisAnchorStatementSha256: genesis.anchor.statementSha256,
  };
}

function trustFromState(state, history) {
  return {
    schema: TRUST_SCHEMA,
    genesisHash: state.genesisHash,
    historyHead: state.historyHead,
    currentKeyId: state.currentKeyId,
    currentPublicKeyHex: state.currentPublicKeyHex,
    retiredKeyIds: state.retiredKeyIds,
    revokedKeyIds: state.revokedKeyIds,
    recoveryKeyId: state.recoveryKeyId,
    recoveryPublicKeyHex: state.recoveryPublicKeyHex,
    history,
  };
}

function checkTrust(packageHistory, trust) {
  if (!trust || trust.schema !== TRUST_SCHEMA || !trust.history || !Array.isArray(trust.history.records)) fail("TRUST_FORMAT_INVALID", "Trust checkpoint does not contain the signed key history.");
  const trustedHistory = trust.history;
  const state = stateFromHistory(trustedHistory);
  const expected = trustFromState(state, trustedHistory);
  if (canonical(trust) !== canonical(expected)) fail("KEY_HISTORY_HEAD_MISMATCH", "Trust checkpoint fields do not match its signed history.");
  if (!packageHistory || packageHistory.schema !== HISTORY_SCHEMA || canonical(packageHistory.genesis) !== canonical(trustedHistory.genesis) || !Array.isArray(packageHistory.records) || packageHistory.records.length > trustedHistory.records.length) fail("KEY_HISTORY_NOT_TRUSTED", "Package key history is not a prefix of the independently held signed history.");
  for (let index = 0; index < packageHistory.records.length; index += 1) {
    if (canonical(packageHistory.records[index]) !== canonical(trustedHistory.records[index])) fail("KEY_HISTORY_NOT_TRUSTED", `Package key history diverges from the trusted record at sequence ${index + 1}.`);
  }
  return state;
}

function buildRecord(history, type, fields, signers) {
  const state = stateFromHistory(history);
  const previousHash = state.historyHead;
  const core = { seq: history.records.length + 1, type, ...fields, previousHash };
  const hash = sha256(`${previousHash}${canonical(core)}`);
  const signedHash = Buffer.from(hash, "hex");
  const proofs = {};
  for (const [name, identity] of Object.entries(signers)) proofs[name] = sign(null, signedHash, identity.privateKey).toString("hex");
  return { ...core, hash, proofs };
}

async function independentCheck(packageDir) {
  const result = await independentlyVerifyMoltPackage(resolve(packageDir));
  if (!result.valid) fail("INDEPENDENT_VERIFIER_FAIL", result.reason || "Attached independent verifier rejected the package.");
  return result;
}

async function readPackagePublic(packageDir) {
  try {
    const pem = await readFile(join(packageDir, "ed25519-public.pem"), "utf8");
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "ed25519") fail("PACKAGE_PUBLIC_KEY_INVALID", "Package public key is not Ed25519.");
    return rawPublicKey(key);
  } catch (error) {
    if (error instanceof KeyManagementError) throw error;
    fail("PACKAGE_PUBLIC_KEY_INVALID", "Package public key file is missing or invalid.");
  }
}

async function readPackageHistory(packageDir) {
  return readJson(join(packageDir, "key-history.json"), "HISTORY_FORMAT_INVALID");
}

async function readManifest(packageDir) {
  const manifest = await readJson(join(packageDir, "manifest.json"), "MANIFEST_FORMAT_INVALID");
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || !manifest.artifacts || !manifest.agent_pubkeys || Array.isArray(manifest.artifacts) || Array.isArray(manifest.agent_pubkeys)) fail("MANIFEST_FORMAT_INVALID", "Manifest requires artifacts and agent_pubkeys objects.");
  return manifest;
}

async function readAndVerifyNote(packageDir, expectedKey) {
  let text;
  const notePath = join(packageDir, "manifest-note.md");
  try {
    const info = await lstat(notePath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 1_000_000) fail("MANIFEST_NOTE_FORMAT_INVALID", "Manifest note must be a regular file no larger than 1 MB.");
    text = await readFile(notePath, "utf8");
  } catch (error) {
    if (error instanceof KeyManagementError) throw error;
    fail("MANIFEST_NOTE_MISSING", "Package must contain manifest-note.md in the documented signed-entry format.");
  }
  const parsed = verifyManifestNote(text, expectedKey);
  return { text, parsed };
}

export async function verifyPackage(packageDir, trustPath) {
  assertOutsidePackage(trustPath, packageDir);
  const history = await readPackageHistory(packageDir);
  const trust = await readJson(trustPath, "TRUST_FORMAT_INVALID");
  const state = checkTrust(history, trust);
  const packagePublicKey = await readPackagePublic(packageDir);
  const packageKeyId = keyId(packagePublicKey);
  if (state.revokedKeyIds.includes(packageKeyId)) fail("KEY_REVOKED", "Package signer is in the signed revocation history.");
  if (state.retiredKeyIds.includes(packageKeyId)) fail("SIGNER_RETIRED", "Package signer was retired by a signed rotation.");
  if (!state.currentKeyId || packageKeyId !== state.currentKeyId || packagePublicKey !== state.currentPublicKeyHex) fail("SIGNER_NOT_CURRENT", "Package signer is not the active manifest signer.");
  const note = await readAndVerifyNote(packageDir, packagePublicKey);
  if (sha256(Buffer.from(note.parsed.statement, "utf8")) !== state.genesisAnchorStatementSha256) fail("MANIFEST_STATEMENT_CHANGED", "Manifest signed statement differs from the genesis anchor.");
  return independentCheck(packageDir);
}

export async function bootstrapPackage({ packageDir, manifestNotePath, currentIdentityPath, recoveryIdentityPath, outDir, trustOutPath, at = new Date().toISOString() }) {
  await independentCheck(packageDir);
  const currentIdentity = await readIdentity(currentIdentityPath);
  const recovery = await readIdentity(recoveryIdentityPath);
  const sourcePublic = await readPackagePublic(packageDir);
  if (currentIdentity.publicKeyHex !== sourcePublic) fail("OLD_IDENTITY_MISMATCH", "Bootstrap identity does not match the package signer.");
  const noteText = await readFile(manifestNotePath, "utf8");
  const anchor = verifyManifestNote(noteText, sourcePublic);
  if (sourcePublic === recovery.publicKeyHex) fail("RECOVERY_KEY_REUSE", "Recovery key must be different from the current manifest signer.");
  const genesisCore = {
    schema: "molt.key-genesis.v1",
    createdAt: at,
    currentKeyId: keyId(sourcePublic),
    currentPublicKeyHex: sourcePublic,
    recoveryKeyId: recovery.keyId,
    recoveryPublicKeyHex: recovery.publicKeyHex,
    anchor: {
      statement: anchor.statement,
      statementSha256: sha256(Buffer.from(anchor.statement, "utf8")),
      publicKeyHex: anchor.publicKeyHex,
      signatureHex: anchor.signatureHex,
    },
  };
  const genesisHash = sha256(canonical(genesisCore));
  const genesis = {
    ...genesisCore,
    hash: genesisHash,
    proofs: { current: sign(null, Buffer.from(genesisHash, "hex"), currentIdentity.privateKey).toString("hex") },
  };
  const history = { schema: HISTORY_SCHEMA, genesis, records: [] };
  const state = stateFromHistory(history);
  const trust = trustFromState(state, history);
  assertOutsidePackage(trustOutPath, packageDir);
  assertOutsidePackage(trustOutPath, outDir);
  await ensureNewDirectory(outDir);
  try {
    await copyTree(packageDir, outDir, false);
    const notePath = join(outDir, "manifest-note.md");
    try {
      const existingNote = await readFile(notePath, "utf8");
      if (existingNote !== noteText) fail("MANIFEST_NOTE_CONFLICT", "The package already contains a different signed manifest note.");
    } catch (error) {
      if (error instanceof KeyManagementError) throw error;
      if (error?.code !== "ENOENT") throw error;
      await writeFile(notePath, noteText, { flag: "wx" });
    }
    const manifest = await readManifest(outDir);
    manifest.artifacts["manifest-note.md"] = sha256(Buffer.from(noteText, "utf8"));
    manifest.artifact_bytes["manifest-note.md"] = Buffer.byteLength(noteText, "utf8");
    await writeJson(join(outDir, "manifest.json"), manifest);
    await writeJson(join(outDir, "key-history.json"), history);
    await independentCheck(outDir);
    await readAndVerifyNote(outDir, sourcePublic);
    await finishOutput(outDir, trust, trustOutPath);
    return { trust, currentKeyId: state.currentKeyId, packageDir: resolve(outDir) };
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}

async function stagePackage(packageDir, outDir) {
  if (resolve(packageDir) === resolve(outDir)) fail("OUTPUT_EQUALS_INPUT", "Output package must be a new path; source packages are never edited in place.");
  await ensureNewDirectory(outDir);
  try {
    await copyTree(packageDir, outDir, false);
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}

async function reSignPackageFiles(packageDir, oldPublicKeyHex, newIdentity) {
  const manifest = await readManifest(packageDir);
  let actorCount = 0;
  for (const [actor, publicHex] of Object.entries(manifest.agent_pubkeys)) {
    if (publicHex === oldPublicKeyHex) {
      manifest.agent_pubkeys[actor] = newIdentity.publicKeyHex;
      actorCount += 1;
    }
  }
  if (!actorCount) fail("ACTOR_KEY_BINDING_MISSING", "Manifest has no actor bound to the signer being rotated.");
  const eventFile = join(packageDir, "events.jsonl");
  const text = await readFile(eventFile, "utf8");
  const lines = text ? text.split("\n") : [];
  if (lines.at(-1) === "") lines.pop();
  const events = lines.map((line) => JSON.parse(line));
  const newSignature = (hash) => sign(null, Buffer.from(hash, "hex"), newIdentity.privateKey).toString("hex");
  for (const event of events) {
    if (event.pub !== oldPublicKeyHex) fail("EVENT_SIGNER_MISMATCH", "Every package event must use the current signer before re-issue.");
    event.pub = newIdentity.publicKeyHex;
    event.sig = newSignature(event.hash);
  }
  const note = await readAndVerifyNote(packageDir, oldPublicKeyHex);
  const replacements = [...note.text.matchAll(/^Public key \(hex\): [a-f0-9]{64}\r?\nSignature \(hex\): [a-f0-9]{128}$/gm)];
  if (replacements.length !== 1) fail("MANIFEST_NOTE_FORMAT_INVALID", "Manifest note key/signature pair is ambiguous.");
  const updatedNote = note.text.replace(replacements[0][0], `Public key (hex): ${newIdentity.publicKeyHex}\nSignature (hex): ${sign(null, Buffer.from(note.parsed.statement, "utf8"), newIdentity.privateKey).toString("hex")}`);
  manifest.artifacts["manifest-note.md"] = sha256(Buffer.from(updatedNote, "utf8"));
  manifest.artifact_bytes["manifest-note.md"] = Buffer.byteLength(updatedNote, "utf8");
  const updatedEventsText = events.length ? `${events.map((event) => canonicalizeJsonText(JSON.stringify(event))).join("\n")}\n` : "";
  manifest.ledger_bytes = Buffer.byteLength(updatedEventsText, "utf8");
  await writeFile(eventFile, updatedEventsText);
  await writeFile(join(packageDir, "ed25519-public.pem"), publicPem(newIdentity.publicKeyHex));
  await writeFile(join(packageDir, "manifest-note.md"), updatedNote);
  await writeJson(join(packageDir, "manifest.json"), manifest);
}

async function prepareCurrentState(packageDir, trustPath) {
  const history = await readPackageHistory(packageDir);
  const trust = await readJson(trustPath, "TRUST_FORMAT_INVALID");
  const state = checkTrust(history, trust);
  if (!state.currentKeyId) fail("NO_ACTIVE_SIGNER", "No active manifest signer exists; complete emergency rotation before signing packages.");
  return { history, trust, state };
}

async function finishOutput(outDir, trust, trustOutPath) {
  assertOutsidePackage(trustOutPath, outDir);
  await writeJson(trustOutPath, trust, true);
  try {
    const report = await verifyPackage(outDir, trustOutPath);
    return report;
  } catch (error) {
    await rm(trustOutPath, { force: true });
    throw error;
  }
}

export async function rotatePackage({ packageDir, trustPath, oldIdentityPath, newIdentityPath, outDir, trustOutPath, at = new Date().toISOString() }) {
  const { history, state } = await prepareCurrentState(packageDir, trustPath);
  const oldIdentity = await readIdentity(oldIdentityPath);
  const newIdentity = await readIdentity(newIdentityPath);
  if (oldIdentity.publicKeyHex !== state.currentPublicKeyHex) fail("OLD_IDENTITY_MISMATCH", "Old identity does not match the active signer.");
  if (newIdentity.publicKeyHex === state.currentPublicKeyHex || state.knownKeys.has(newIdentity.keyId)) fail("NEW_KEY_NOT_FRESH", "Rotation requires a fresh key not already present in the history.");
  assertOutsidePackage(trustOutPath, packageDir);
  await verifyPackage(packageDir, trustPath);
  const record = buildRecord(history, "rotate", {
    at,
    fromKeyId: state.currentKeyId,
    fromPublicKeyHex: oldIdentity.publicKeyHex,
    toKeyId: newIdentity.keyId,
    toPublicKeyHex: newIdentity.publicKeyHex,
  }, { old: oldIdentity, new: newIdentity });
  const nextHistory = { ...history, records: [...history.records, record] };
  const nextTrust = trustFromState(stateFromHistory(nextHistory), nextHistory);
  await stagePackage(packageDir, outDir);
  try {
    await reSignPackageFiles(outDir, oldIdentity.publicKeyHex, newIdentity);
    await writeJson(join(outDir, "key-history.json"), nextHistory);
    await independentCheck(outDir);
    await finishOutput(outDir, nextTrust, trustOutPath);
    return { packageDir: resolve(outDir), trustPath: resolve(trustOutPath), recordHash: record.hash, currentKeyId: nextTrust.currentKeyId };
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}

export async function revokeKey({ packageDir, trustPath, recoveryIdentityPath, keyId: targetKeyId, outDir, trustOutPath, at = new Date().toISOString() }) {
  const { history, state } = await prepareCurrentState(packageDir, trustPath);
  const recovery = await readIdentity(recoveryIdentityPath);
  if (recovery.keyId !== state.recoveryKeyId) fail("RECOVERY_IDENTITY_MISMATCH", "Recovery identity does not match the pinned recovery key.");
  if (!state.knownKeys.has(targetKeyId)) fail("UNKNOWN_KEY", "Revocation target is not in the signed key history.");
  if (state.revokedKeyIds.includes(targetKeyId)) fail("KEY_ALREADY_REVOKED", "Revocation target is already revoked.");
  if (targetKeyId === state.currentKeyId) fail("CURRENT_KEY_REQUIRES_COMPROMISE", "Use emergency rotation to revoke the active signer.");
  assertOutsidePackage(trustOutPath, packageDir);
  const record = buildRecord(history, "revoke", { at, keyId: targetKeyId, compromise: false }, { recovery });
  const nextHistory = { ...history, records: [...history.records, record] };
  const nextTrust = trustFromState(stateFromHistory(nextHistory), nextHistory);
  await stagePackage(packageDir, outDir);
  try {
    await writeJson(join(outDir, "key-history.json"), nextHistory);
    await finishOutput(outDir, nextTrust, trustOutPath);
    return { packageDir: resolve(outDir), trustPath: resolve(trustOutPath), recordHash: record.hash, revokedKeyId: targetKeyId };
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}

export async function emergencyRotatePackage({ packageDir, trustPath, recoveryIdentityPath, newIdentityPath, outDir, trustOutPath, at = new Date().toISOString() }) {
  const { history, state } = await prepareCurrentState(packageDir, trustPath);
  const recovery = await readIdentity(recoveryIdentityPath);
  const newIdentity = await readIdentity(newIdentityPath);
  if (recovery.keyId !== state.recoveryKeyId) fail("RECOVERY_IDENTITY_MISMATCH", "Recovery identity does not match the pinned recovery key.");
  if (state.knownKeys.has(newIdentity.keyId)) fail("NEW_KEY_NOT_FRESH", "Emergency rotation requires a fresh key not already present in the history.");
  assertOutsidePackage(trustOutPath, packageDir);
  await verifyPackage(packageDir, trustPath);
  const revoked = buildRecord(history, "revoke", { at, keyId: state.currentKeyId, compromise: true }, { recovery });
  const afterRevoke = { ...history, records: [...history.records, revoked] };
  const rotated = buildRecord(afterRevoke, "emergency-rotate", { at, fromRevokedKeyId: state.currentKeyId, toKeyId: newIdentity.keyId, toPublicKeyHex: newIdentity.publicKeyHex }, { recovery, new: newIdentity });
  const nextHistory = { ...afterRevoke, records: [...afterRevoke.records, rotated] };
  const nextTrust = trustFromState(stateFromHistory(nextHistory), nextHistory);
  await stagePackage(packageDir, outDir);
  try {
    await reSignPackageFiles(outDir, state.currentPublicKeyHex, newIdentity);
    await writeJson(join(outDir, "key-history.json"), nextHistory);
    await independentCheck(outDir);
    await finishOutput(outDir, nextTrust, trustOutPath);
    return { packageDir: resolve(outDir), trustPath: resolve(trustOutPath), revokedKeyId: state.currentKeyId, currentKeyId: nextTrust.currentKeyId, recordHashes: [revoked.hash, rotated.hash] };
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}

export async function reissuePackage({ packageDir, trustPath, newIdentityPath, outDir, reviewed = false }) {
  if (!reviewed) fail("REVIEW_REQUIRED", "Re-issue requires explicit owner review of the artifact contents.");
  const packageHistory = await readPackageHistory(packageDir);
  const trust = await readJson(trustPath, "TRUST_FORMAT_INVALID");
  const state = checkTrust(packageHistory, trust);
  const history = trust.history;
  const newIdentity = await readIdentity(newIdentityPath);
  if (!state.currentKeyId || newIdentity.keyId !== state.currentKeyId) fail("NEW_IDENTITY_NOT_CURRENT", "Re-issue identity must be the current key in the pinned history.");
  await independentCheck(packageDir);
  const oldPublicKeyHex = await readPackagePublic(packageDir);
  if (!state.knownKeys.has(keyId(oldPublicKeyHex))) fail("SIGNER_NOT_IN_HISTORY", "Original artifact signer is not present in the trusted key history.");
  await readAndVerifyNote(packageDir, oldPublicKeyHex);
  await stagePackage(packageDir, outDir);
  try {
    await reSignPackageFiles(outDir, oldPublicKeyHex, newIdentity);
    await writeJson(join(outDir, "key-history.json"), history);
    await independentCheck(outDir);
    await verifyPackage(outDir, trustPath);
    return { packageDir: resolve(outDir), currentKeyId: state.currentKeyId };
  } catch (error) {
    await rm(outDir, { recursive: true, force: true });
    throw error;
  }
}
