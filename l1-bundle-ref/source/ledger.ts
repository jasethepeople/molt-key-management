import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { MOLTEvent, MOLTEventBody, MOLTEventEvidence, VerificationReport } from "./types";

const ZERO_HASH = "0".repeat(64);
const MAX_LEDGER_BYTES = 32 * 1024 * 1024;
const MAX_EVENT_BYTES = 256 * 1024;
const MAX_MANIFEST_BYTES = 1_000_000;
const LOCK_STALE_MS = 5 * 60_000;
const LOCK_WAIT_MS = 10_000;

function canonicalString(value: string): string {
  let encoded = '"';
  for (const character of value) {
    const point = character.codePointAt(0)!;
    switch (character) {
      case '"': encoded += '\\"'; break;
      case "\\": encoded += "\\\\"; break;
      case "\b": encoded += "\\b"; break;
      case "\f": encoded += "\\f"; break;
      case "\n": encoded += "\\n"; break;
      case "\r": encoded += "\\r"; break;
      case "\t": encoded += "\\t"; break;
      default:
        if (point < 32 || point > 126) {
          const units = character.length === 2 ? [character.charCodeAt(0), character.charCodeAt(1)] : [point];
          encoded += units.map((unit) => `\\u${unit.toString(16).padStart(4, "0")}`).join("");
        } else encoded += character;
    }
  }
  return `${encoded}"`;
}

function canonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return canonicalString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("MOLT evidence values must use finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("MOLT evidence values must contain only plain JSON objects, arrays, and primitives.");
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return `{${keys.map((key) => `${canonicalString(key)}:${canonical(object[key])}`).join(",")}}`;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function rawPublicKey(publicPem: string): string {
  const der = createPublicKey(publicPem).export({ type: "spki", format: "der" });
  const raw = Buffer.from(der).subarray(-32);
  if (raw.length !== 32) throw new Error("The public key is not a valid Ed25519 key.");
  return raw.toString("hex");
}

function eventBody(event: MOLTEvent): MOLTEventBody {
  return { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
}

function eventHash(previous: string, body: MOLTEventBody): string {
  return sha256(`${previous}${canonical(body)}`);
}

async function ensureRegularFile(path: string, label: string): Promise<boolean> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} must be a regular file, not a symbolic link.`);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function ensureDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Evidence directory must be a real directory.");
  if ((info.mode & 0o077) !== 0) throw new Error("Evidence and signing directories must not be accessible to group or other users.");
}

async function createExclusive(path: string, content: string): Promise<void> {
  const handle = await open(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await createExclusive(temporary, content);
    await rename(temporary, path);
    const directory = await open(resolve(path, ".."), fsConstants.O_RDONLY);
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

function invalid(reason: string, firstInvalidSequence: number | null = 0, count = 0, keyId: string | null = null): VerificationReport {
  return { valid: false, count, firstInvalidSequence, reason, keyId, anchoring: "local-only" };
}

async function verifyPackage(directory: string): Promise<VerificationReport> {
  if (!isAbsolute(directory)) return invalid("Evidence path must be absolute.");
  const root = resolve(directory);
  try {
    const rootInfo = await lstat(root);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) return invalid("Evidence package must be a real directory.");
    const manifestPath = resolve(root, "manifest.json");
    const eventsPath = resolve(root, "events.jsonl");
    const publicPath = resolve(root, "ed25519-public.pem");
    const [manifestPresent, eventsPresent, publicPresent] = await Promise.all([
      ensureRegularFile(manifestPath, "MOLT manifest"),
      ensureRegularFile(eventsPath, "MOLT event ledger"),
      ensureRegularFile(publicPath, "MOLT verification key"),
    ]);
    if (!manifestPresent || !eventsPresent || !publicPresent) return invalid("Manifest, event ledger, or verification key is missing.");
    const [manifestInfo, eventsInfo] = await Promise.all([lstat(manifestPath), lstat(eventsPath)]);
    if (manifestInfo.size > MAX_MANIFEST_BYTES || eventsInfo.size > MAX_LEDGER_BYTES) return invalid("Evidence package exceeds its size limit.");
    const [manifestText, eventText, publicPem] = await Promise.all([
      readFile(manifestPath, "utf8"),
      readFile(eventsPath, "utf8"),
      readFile(publicPath, "utf8"),
    ]);
    const manifestValue: unknown = JSON.parse(manifestText);
    if (!manifestValue || typeof manifestValue !== "object" || Array.isArray(manifestValue)) return invalid("MOLT manifest must be a JSON object.");
    const manifest = manifestValue as Record<string, unknown>;
    const artifacts = manifest.artifacts;
    const actorKeys = manifest.agent_pubkeys;
    if (!artifacts || typeof artifacts !== "object" || Array.isArray(artifacts) || !actorKeys || typeof actorKeys !== "object" || Array.isArray(actorKeys)) return invalid("MOLT manifest artifacts and agent_pubkeys must be JSON objects.");
    const publicKey = createPublicKey(publicPem);
    if (publicKey.asymmetricKeyType !== "ed25519") return invalid("MOLT signer must be an Ed25519 key.");
    const publicHex = rawPublicKey(publicPem);
    const keyId = sha256(Buffer.from(publicHex, "hex"));
    for (const [filename, expected] of Object.entries(artifacts as Record<string, unknown>)) {
      if (typeof expected !== "string" || !/^[a-f0-9]{64}$/i.test(expected)) return invalid(`MOLT artifact '${filename}' has an invalid SHA-256 declaration.`, 0, 0, keyId);
      const artifactPath = await safeArtifactPath(root, filename);
      const info = await lstat(artifactPath);
      if (!info.isFile() || info.isSymbolicLink()) return invalid(`MOLT artifact '${filename}' is not a regular file.`, 0, 0, keyId);
      const actual = sha256(await readFile(artifactPath));
      if (actual !== expected.toLowerCase()) return invalid(`MOLT artifact '${filename}' hash mismatch.`, 0, 0, keyId);
    }
    const lines = eventText ? eventText.split("\n") : [];
    if (lines.at(-1) === "") lines.pop();
    let previous = ZERO_HASH;
    for (let index = 0; index < lines.length; index += 1) {
      let event: MOLTEvent;
      try {
        const line = lines[index]!;
        if (!line || Buffer.byteLength(line) > MAX_EVENT_BYTES) throw new Error("Event line is empty or oversized.");
        const value: unknown = JSON.parse(line);
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Event must be a JSON object.");
        event = value as MOLTEvent;
        const allowed = new Set(["actor", "hash", "payload", "prev_hash", "pub", "seq", "sig", "ts", "type"]);
        if (Object.keys(value).some((field) => !allowed.has(field))) throw new Error("Event contains an unknown field.");
      } catch (error) {
        return invalid(error instanceof Error ? error.message : "Malformed event.", index, index, keyId);
      }
      try {
        if (!Number.isSafeInteger(event.seq) || event.seq !== index) throw new Error("Event sequence is not contiguous from zero.");
        if (!Number.isSafeInteger(event.ts) || typeof event.type !== "string" || !event.type || typeof event.actor !== "string" || !event.actor) throw new Error("Event metadata is malformed.");
        if (!event.payload || typeof event.payload !== "object" || Array.isArray(event.payload)) throw new Error("Event payload must be a JSON object.");
        if (event.prev_hash !== previous) throw new Error("Previous event hash does not match.");
        if (event.pub !== publicHex || (actorKeys as Record<string, unknown>)[event.actor] !== publicHex) throw new Error("Event public key is not bound to its actor by the manifest.");
        if (!/^[a-f0-9]{64}$/.test(event.hash) || !/^[a-f0-9]{128}$/.test(event.sig)) throw new Error("Hash or Ed25519 signature encoding is invalid.");
        const computed = eventHash(previous, eventBody(event));
        if (computed !== event.hash) throw new Error("Event content hash mismatch.");
        if (!verify(null, Buffer.from(computed, "hex"), publicKey, Buffer.from(event.sig, "hex"))) throw new Error("Ed25519 signature verification failed.");
      } catch (error) {
        return invalid(error instanceof Error ? error.message : "Event verification failed.", index, index, keyId);
      }
      previous = event.hash;
    }
    return { valid: true, count: lines.length, firstInvalidSequence: null, reason: null, keyId, anchoring: "local-only" };
  } catch (error) {
    return invalid(error instanceof Error ? error.message : "MOLT evidence verification failed.");
  }
}

async function safeArtifactPath(root: string, filename: string): Promise<string> {
  if (!filename || isAbsolute(filename) || filename.includes("\\") || filename.split("/").some((part) => !part || part === "." || part === "..")) throw new Error(`Unsafe MOLT artifact path '${filename}'.`);
  let current = root;
  const parts = filename.split("/");
  for (let index = 0; index < parts.length; index += 1) {
    current = resolve(current, parts[index]!);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error(`MOLT artifact '${filename}' traverses a symbolic link.`);
    if (index < parts.length - 1 && !info.isDirectory()) throw new Error(`MOLT artifact '${filename}' has a non-directory parent.`);
  }
  const path = relative(root, current);
  if (!path || path === ".." || path.startsWith(`..${sep}`)) throw new Error(`MOLT artifact '${filename}' escapes the evidence package.`);
  return current;
}

export class MoltLedger {
  readonly directory: string;
  readonly eventsPath: string;
  readonly manifestPath: string;
  readonly signingDirectory: string;
  readonly privateKeyPath: string;
  readonly publicKeyPath: string;
  private readonly lockPath: string;
  private queued: Promise<unknown> = Promise.resolve();

  constructor(directory: string, signingDirectory?: string) {
    if (!isAbsolute(directory) || (signingDirectory !== undefined && !isAbsolute(signingDirectory))) throw new TypeError("Evidence and signing directories must be absolute paths.");
    this.directory = resolve(directory);
    this.signingDirectory = resolve(signingDirectory ?? `${this.directory}.signing`);
    const signingRelativePath = relative(this.directory, this.signingDirectory);
    if (!signingRelativePath || (signingRelativePath !== ".." && !signingRelativePath.startsWith(`..${sep}`))) throw new TypeError("Signing keys must be stored outside the exportable evidence package.");
    this.eventsPath = resolve(this.directory, "events.jsonl");
    this.manifestPath = resolve(this.directory, "manifest.json");
    this.privateKeyPath = resolve(this.signingDirectory, "ed25519-private.pem");
    this.publicKeyPath = resolve(this.directory, "ed25519-public.pem");
    this.lockPath = resolve(this.directory, ".ledger.lock");
  }

  async initialize(): Promise<void> {
    await ensureDirectory(this.directory);
    await ensureDirectory(this.signingDirectory);
    const [privatePresent, publicPresent, manifestPresent, eventsPresent] = await Promise.all([
      ensureRegularFile(this.privateKeyPath, "MOLT signing key"),
      ensureRegularFile(this.publicKeyPath, "MOLT verification key"),
      ensureRegularFile(this.manifestPath, "MOLT manifest"),
      ensureRegularFile(this.eventsPath, "MOLT event ledger"),
    ]);
    const initialized = [privatePresent, publicPresent, manifestPresent, eventsPresent];
    if (initialized.some(Boolean) && !initialized.every(Boolean)) throw new Error("MOLT package or signing keypair is incomplete; refusing to recreate missing trust material.");
    if (!initialized.some(Boolean)) {
      const pair = generateKeyPairSync("ed25519", {
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      });
      await createExclusive(this.privateKeyPath, pair.privateKey);
      try {
        await createExclusive(this.publicKeyPath, pair.publicKey);
        await createExclusive(this.eventsPath, "");
        await atomicWrite(this.manifestPath, JSON.stringify({ artifacts: {}, agent_pubkeys: {} }, null, 2) + "\n");
      } catch (error) {
        await unlink(this.privateKeyPath).catch(() => undefined);
        await unlink(this.publicKeyPath).catch(() => undefined);
        await unlink(this.eventsPath).catch(() => undefined);
        await unlink(this.manifestPath).catch(() => undefined);
        throw error;
      }
    }
    await chmod(this.privateKeyPath, 0o600);
    await chmod(this.publicKeyPath, 0o600);
    const privatePem = await readFile(this.privateKeyPath, "utf8");
    const publicPem = await readFile(this.publicKeyPath, "utf8");
    if (rawPublicKey(createPublicKey(privatePem).export({ type: "spki", format: "pem" }).toString()) !== rawPublicKey(publicPem)) throw new Error("MOLT signing and verification keys do not match; refusing to sign.");

    await chmod(this.eventsPath, 0o600);
    await chmod(this.manifestPath, 0o600);
  }

  private async acquireLock(): Promise<() => Promise<void>> {
    const deadline = Date.now() + LOCK_WAIT_MS;
    while (Date.now() < deadline) {
      try {
        await createExclusive(this.lockPath, `${process.pid}\n${Date.now()}\n`);
        return async () => unlink(this.lockPath).catch(() => undefined);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        try {
          const info = await lstat(this.lockPath);
          if (!info.isFile() || info.isSymbolicLink()) throw new Error("MOLT ledger lock must be a regular file.");
          if (Date.now() - info.mtimeMs > LOCK_STALE_MS) await unlink(this.lockPath);
        } catch (statError) {
          if ((statError as NodeJS.ErrnoException).code !== "ENOENT") throw statError;
        }
        await sleep(25 + Math.floor(Math.random() * 30));
      }
    }
    throw new Error("Timed out waiting for the MOLT evidence ledger lock.");
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    const current = this.queued.then(async () => {
      await ensureDirectory(this.directory);
      await ensureDirectory(this.signingDirectory);
      const release = await this.acquireLock();
      try {
        return await operation();
      } finally {
        await release();
      }
    });
    this.queued = current.catch(() => undefined);
    return current;
  }

  async append(input: { type: string; actor: string; payload: Record<string, unknown> }): Promise<MOLTEvent> {
    return this.withLock(async () => {
      await this.initialize();
      const verified = await verifyPackage(this.directory);
      if (!verified.valid) throw new Error(`MOLT evidence verification failed at sequence ${verified.firstInvalidSequence ?? "unknown"}; refusing to append.`);
      const existing = await this.readEventsUnlocked();
      const previous = existing.at(-1)?.hash ?? ZERO_HASH;
      const manifest = await this.readManifestUnlocked();
      const publicPem = await readFile(this.publicKeyPath, "utf8");
      const publicHex = rawPublicKey(publicPem);
      const actorKeys = manifest.agent_pubkeys as Record<string, unknown>;
      if (actorKeys[input.actor] && actorKeys[input.actor] !== publicHex) throw new Error("MOLT actor is already bound to a different public key.");
      if (typeof input.actor !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.actor)) throw new TypeError("MOLT actor name is invalid.");
      if (typeof input.type !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.type)) throw new TypeError("MOLT event type is invalid.");
      actorKeys[input.actor] = publicHex;
      await atomicWrite(this.manifestPath, JSON.stringify(manifest, null, 2) + "\n");
      const body: MOLTEventBody = {
        seq: existing.length,
        ts: Math.floor(Date.now() / 1000),
        type: input.type,
        payload: input.payload,
        actor: input.actor,
      };
      const hash = eventHash(previous, body);
      const signature = sign(null, Buffer.from(hash, "hex"), createPrivateKey(await readFile(this.privateKeyPath, "utf8"))).toString("hex");
      const event: MOLTEvent = { ...body, prev_hash: previous, hash, pub: publicHex, sig: signature };
      const line = `${canonical(event)}\n`;
      if (Buffer.byteLength(line) > MAX_EVENT_BYTES) throw new Error("MOLT event exceeds the 256 KiB safety limit.");
      const handle = await open(this.eventsPath, fsConstants.O_APPEND | fsConstants.O_WRONLY | (fsConstants.O_NOFOLLOW ?? 0));
      try {
        await handle.writeFile(line, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      return event;
    });
  }

  async readEvents(): Promise<MOLTEvent[]> {
    return this.withLock(async () => {
      await this.initialize();
      const verified = await verifyPackage(this.directory);
      if (!verified.valid) throw new Error(`MOLT evidence verification failed at sequence ${verified.firstInvalidSequence ?? "unknown"}.`);
      return this.readEventsUnlocked();
    });
  }

  async verify(): Promise<VerificationReport> {
    return this.withLock(async () => {
      await this.initialize();
      return verifyPackage(this.directory);
    });
  }

  private async readManifestUnlocked(): Promise<{ artifacts: Record<string, string>; agent_pubkeys: Record<string, string> }> {
    const info = await lstat(this.manifestPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_MANIFEST_BYTES) throw new Error("MOLT manifest is not a regular file or exceeds its size limit.");
    const value: unknown = JSON.parse(await readFile(this.manifestPath, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("MOLT manifest is malformed.");
    const object = value as Record<string, unknown>;
    if (!object.artifacts || typeof object.artifacts !== "object" || Array.isArray(object.artifacts) || !object.agent_pubkeys || typeof object.agent_pubkeys !== "object" || Array.isArray(object.agent_pubkeys)) throw new Error("MOLT manifest artifacts and agent_pubkeys must be objects.");
    return object as { artifacts: Record<string, string>; agent_pubkeys: Record<string, string> };
  }

  private async readEventsUnlocked(): Promise<MOLTEvent[]> {
    const info = await lstat(this.eventsPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_LEDGER_BYTES) throw new Error("MOLT event ledger is not a regular file or exceeds its size limit.");
    const content = await readFile(this.eventsPath, "utf8");
    if (!content) return [];
    const lines = content.split("\n");
    if (lines.at(-1) === "") lines.pop();
    if (lines.some((line) => !line || Buffer.byteLength(line) > MAX_EVENT_BYTES)) throw new Error("MOLT event ledger contains an empty or oversized event line.");
    return lines.map((line) => JSON.parse(line) as MOLTEvent);
  }
}

export async function verifyLedger(directory: string): Promise<VerificationReport> {
  return verifyPackage(directory);
}

export async function serializeEvidence(event: MOLTEvent, directory: string): Promise<MOLTEventEvidence> {
  const pem = await readFile(resolve(directory, "ed25519-public.pem"), "utf8");
  const publicKey = rawPublicKey(pem);
  return {
    schema: "molt.evidence.v1",
    event,
    eventId: event.hash,
    sequence: event.seq,
    hash: event.hash,
    signature: event.sig,
    keyId: sha256(Buffer.from(publicKey, "hex")),
    publicKey,
    anchoring: "local-only",
  };
}
