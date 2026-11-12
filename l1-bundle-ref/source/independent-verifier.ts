import { createHash, createPublicKey, verify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { IndependentVerificationReport, MOLTEvent } from "./types";

const ZERO_HASH = "0".repeat(64);
const MAX_LEDGER_BYTES = 32 * 1024 * 1024;
const MAX_EVENT_BYTES = 256 * 1024;
const MAX_MANIFEST_BYTES = 1_000_000;

function stableString(value: string): string {
  let out = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
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

function stableJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return stableString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number in evidence.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("Evidence is not plain JSON.");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return `{${keys.map((key) => `${stableString(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function fail(reason: string, sequence: number | null, count = 0, keyId: string | null = null): IndependentVerificationReport {
  return { valid: false, count, firstInvalidSequence: sequence, reason, keyId, anchoring: "local-only", verifier: "standalone-molt-v1" };
}

async function readContainedArtifact(root: string, name: string): Promise<Buffer> {
  if (!name || isAbsolute(name) || name.includes("\\") || name.split("/").some((part) => !part || part === "." || part === "..")) throw new Error("Manifest contains an unsafe artifact path.");
  let path = root;
  const parts = name.split("/");
  for (let index = 0; index < parts.length; index += 1) {
    path = resolve(path, parts[index]!);
    const info = await lstat(path);
    if (info.isSymbolicLink() || (index < parts.length - 1 && !info.isDirectory())) throw new Error("Manifest artifact path traverses a symlink or non-directory.");
  }
  const relativeName = relative(root, path);
  if (!relativeName || relativeName === ".." || relativeName.startsWith(`..${sep}`)) throw new Error("Manifest artifact path escapes the evidence package.");
  const info = await lstat(path);
  if (!info.isFile()) throw new Error("Manifest artifact is not a regular file.");
  return readFile(path);
}

export async function independentlyVerifyMoltPackage(directory: string): Promise<IndependentVerificationReport> {
  if (!isAbsolute(directory)) return fail("Evidence path must be absolute.", 0);
  const root = resolve(directory);
  try {
    const rootInfo = await lstat(root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) return fail("Evidence package is not a real directory.", 0);
    const manifestPath = resolve(root, "manifest.json");
    const eventsPath = resolve(root, "events.jsonl");
    const publicPath = resolve(root, "ed25519-public.pem");
    const [manifestStat, eventsStat] = await Promise.all([lstat(manifestPath), lstat(eventsPath)]);
    for (const path of [manifestPath, eventsPath, publicPath]) {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink()) return fail("Evidence package contains a non-regular control file.", 0);
    }
    if (manifestStat.size > MAX_MANIFEST_BYTES || eventsStat.size > MAX_LEDGER_BYTES) return fail("Evidence package exceeds its size limit.", 0);
    const [manifestText, ledgerText, publicPem] = await Promise.all([readFile(manifestPath, "utf8"), readFile(eventsPath, "utf8"), readFile(publicPath, "utf8")]);
    const manifestValue: unknown = JSON.parse(manifestText);
    if (!manifestValue || typeof manifestValue !== "object" || Array.isArray(manifestValue)) return fail("Manifest root is not a JSON object.", 0);
    const manifest = manifestValue as Record<string, unknown>;
    if (!manifest.artifacts || typeof manifest.artifacts !== "object" || Array.isArray(manifest.artifacts)) return fail("Manifest artifacts field is malformed.", 0);
    if (!manifest.agent_pubkeys || typeof manifest.agent_pubkeys !== "object" || Array.isArray(manifest.agent_pubkeys)) return fail("Manifest actor key map is malformed.", 0);
    const key = createPublicKey(publicPem);
    if (key.asymmetricKeyType !== "ed25519") return fail("Manifest verifier key is not Ed25519.", 0);
    const rawPublicKey = Buffer.from(key.export({ format: "der", type: "spki" })).subarray(-32);
    if (rawPublicKey.length !== 32) return fail("Manifest verifier key encoding is invalid.", 0);
    const publicHex = rawPublicKey.toString("hex");
    const keyId = sha256(rawPublicKey);
    for (const [name, digest] of Object.entries(manifest.artifacts as Record<string, unknown>)) {
      if (typeof digest !== "string" || !/^[a-f0-9]{64}$/i.test(digest)) return fail("Manifest contains an invalid artifact digest.", 0, 0, keyId);
      const bytes = await readContainedArtifact(root, name);
      if (sha256(bytes) !== digest.toLowerCase()) return fail(`Artifact digest mismatch for '${name}'.`, 0, 0, keyId);
    }
    const rows = ledgerText ? ledgerText.split("\n") : [];
    if (rows.at(-1) === "") rows.pop();
    let priorHash = ZERO_HASH;
    for (let index = 0; index < rows.length; index += 1) {
      let event: MOLTEvent;
      try {
        const row = rows[index]!;
        if (!row || Buffer.byteLength(row) > MAX_EVENT_BYTES) throw new Error("Event line is empty or too large.");
        const parsed: unknown = JSON.parse(row);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Event record is not an object.");
        const allowed = ["actor", "hash", "payload", "prev_hash", "pub", "seq", "sig", "ts", "type"];
        if (Object.keys(parsed).some((field) => !allowed.includes(field))) throw new Error("Event record contains unexpected fields.");
        event = parsed as MOLTEvent;
      } catch (error) {
        return fail(error instanceof Error ? error.message : "Malformed event record.", index, index, keyId);
      }
      try {
        if (event.seq !== index || !Number.isSafeInteger(event.seq)) throw new Error("Event sequence is not contiguous.");
        if (!Number.isSafeInteger(event.ts) || typeof event.type !== "string" || !event.type || typeof event.actor !== "string" || !event.actor) throw new Error("Event metadata is invalid.");
        if (!event.payload || typeof event.payload !== "object" || Array.isArray(event.payload)) throw new Error("Event payload is invalid.");
        if (event.prev_hash !== priorHash) throw new Error("Event chain link is invalid.");
        if (event.pub !== publicHex || (manifest.agent_pubkeys as Record<string, unknown>)[event.actor] !== publicHex) throw new Error("Event signer is not bound to its actor in the manifest.");
        if (!/^[a-f0-9]{64}$/.test(event.hash) || !/^[a-f0-9]{128}$/.test(event.sig)) throw new Error("Event hash or signature is malformed.");
        const signedBody: Record<string, unknown> = { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
        const actualHash = sha256(`${priorHash}${stableJson(signedBody)}`);
        if (actualHash !== event.hash) throw new Error("Event content hash is invalid.");
        if (!verify(null, Buffer.from(actualHash, "hex"), key, Buffer.from(event.sig, "hex"))) throw new Error("Ed25519 signature is invalid.");
      } catch (error) {
        return fail(error instanceof Error ? error.message : "Event verification failed.", index, index, keyId);
      }
      priorHash = event.hash;
    }
    return { valid: true, count: rows.length, firstInvalidSequence: null, reason: null, keyId, anchoring: "local-only", verifier: "standalone-molt-v1" };
  } catch (error) {
    return fail(error instanceof Error ? error.message : "Independent MOLT verification failed.", 0);
  }
}
