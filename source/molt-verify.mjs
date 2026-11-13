#!/usr/bin/env node
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { canonicalizeJsonText } from './molt-canonical.mjs';

const ZERO_HASH = '0'.repeat(64);
const FIELD_NAMES = ['seq', 'ts', 'type', 'actor', 'payload', 'prev_hash', 'pub', 'sig', 'hash'];
const HASH_FORMAT = /^[0-9a-f]{64}$/;
const SIGNATURE_FORMAT = /^[0-9a-f]{128}$/;
const MAX_LEDGER_BYTES = 32 * 1024 * 1024;
const MAX_EVENT_BYTES = 256 * 1024;
const MAX_MANIFEST_BYTES = 1_000_000;

const CHECK_NAMES = {
  'V-01': 'package path and directory',
  'V-02': 'control files present and regular',
  'V-03': 'size limits',
  'V-04': 'file completeness and truncation',
  'V-05': 'manifest JSON object',
  'V-06': 'manifest schema',
  'V-07': 'Ed25519 public key',
  'V-08': 'artifact digests and byte counts',
  'V-09': 'ledger event checks',
  'V-10': 'anchor check',
};

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fail(checkId, reason, extra = {}) {
  return {
    valid: false,
    checkId,
    checkName: CHECK_NAMES[checkId] ?? checkId,
    reason,
    count: extra.count ?? 0,
    firstInvalidSequence: extra.firstInvalidSequence ?? null,
    keyId: extra.keyId ?? null,
    anchor: extra.anchor ?? 'none',
    verifier: 'standalone-molt-v1',
  };
}

function pass(extra = {}) {
  return {
    valid: true,
    checkId: null,
    checkName: 'all checks',
    reason: null,
    count: extra.count ?? 0,
    firstInvalidSequence: null,
    keyId: extra.keyId ?? null,
    anchor: extra.anchor ?? 'none',
    verifier: 'standalone-molt-v1',
  };
}

async function readContainedArtifact(root, name) {
  if (
    !name ||
    isAbsolute(name) ||
    name.includes('\\') ||
    name.split('/').some(part => !part || part === '.' || part === '..')
  ) {
    throw new Error('Manifest contains an unsafe artifact path.');
  }

  let path = root;
  const parts = name.split('/');

  for (let index = 0; index < parts.length; index += 1) {
    path = resolve(path, parts[index]);
    const info = await lstat(path);
    if (info.isSymbolicLink() || (index < parts.length - 1 && !info.isDirectory())) {
      throw new Error('Manifest artifact path traverses a symlink or non-directory.');
    }
  }

  const relativeName = relative(root, path);
  if (!relativeName || relativeName === '..' || relativeName.startsWith(`..${sep}`)) {
    throw new Error('Manifest artifact path escapes the evidence package.');
  }

  const info = await lstat(path);
  if (!info.isFile()) throw new Error('Manifest artifact is not a regular file.');
  return readFile(path);
}

function checkEvent(line, index, previousRecomputedHash, publicKey, publicHex, agentKeys) {
  const failures = [];
  let parsed;

  try {
    parsed = JSON.parse(line);
  } catch {
    return { failures: ['invalid JSON'], recomputedHash: null, event: null };
  }

  let canonicalLine;
  try {
    canonicalLine = canonicalizeJsonText(line);
  } catch {
    failures.push('not canonical');
  }
  if (canonicalLine !== undefined && canonicalLine !== line) failures.push('not canonical');

  const event = isPlainObject(parsed) ? parsed : {};
  const keys = Object.keys(event);
  const fieldsAreExact =
    !Array.isArray(parsed) &&
    keys.length === FIELD_NAMES.length &&
    FIELD_NAMES.every(field => Object.hasOwn(event, field));
  if (!fieldsAreExact) failures.push('wrong fields');

  const formatsAreValid =
    Number.isInteger(event.seq) &&
    event.seq >= 0 &&
    Number.isInteger(event.ts) &&
    event.ts >= 0 &&
    typeof event.type === 'string' &&
    typeof event.actor === 'string' &&
    typeof event.prev_hash === 'string' &&
    HASH_FORMAT.test(event.prev_hash) &&
    typeof event.pub === 'string' &&
    HASH_FORMAT.test(event.pub) &&
    typeof event.sig === 'string' &&
    SIGNATURE_FORMAT.test(event.sig) &&
    typeof event.hash === 'string' &&
    HASH_FORMAT.test(event.hash);
  if (!formatsAreValid) failures.push('bad field format');

  if (
    typeof event.pub === 'string' &&
    typeof event.actor === 'string' &&
    (event.pub !== publicHex || agentKeys[event.actor] !== publicHex)
  ) {
    failures.push('actor key not bound');
  }

  if (event.seq !== index) failures.push('seq out of order');

  if (event.seq === 0) {
    if (event.prev_hash !== ZERO_HASH) failures.push('chain broken');
  } else if (Number.isInteger(event.seq) && event.seq > 0) {
    if (previousRecomputedHash === null || event.prev_hash !== previousRecomputedHash) {
      failures.push('chain broken');
    }
  } else {
    failures.push('chain broken');
  }

  // Camp 1: signed body is the five Foundry fields, not the seven-field event.
  let canonicalBody;
  if (isPlainObject(parsed)) {
    const signedBody = {
      seq: event.seq,
      ts: event.ts,
      type: event.type,
      payload: event.payload,
      actor: event.actor,
    };
    try {
      canonicalBody = canonicalizeJsonText(JSON.stringify(signedBody));
    } catch {
      canonicalBody = undefined;
    }
  }

  let recomputedHash = null;
  if (canonicalBody !== undefined && typeof event.prev_hash === 'string') {
    recomputedHash = createHash('sha256')
      .update(event.prev_hash + canonicalBody, 'utf8')
      .digest('hex');
  }
  if (recomputedHash === null || event.hash !== recomputedHash) failures.push('hash mismatch');

  // Camp 1: Ed25519 signs the 32 hash bytes, not the canonical body string.
  let signatureIsValid = false;
  if (
    recomputedHash !== null &&
    typeof event.pub === 'string' &&
    HASH_FORMAT.test(event.pub) &&
    typeof event.sig === 'string' &&
    SIGNATURE_FORMAT.test(event.sig)
  ) {
    try {
      signatureIsValid = verifySignature(
        null,
        Buffer.from(recomputedHash, 'hex'),
        publicKey,
        Buffer.from(event.sig, 'hex')
      );
    } catch {
      signatureIsValid = false;
    }
  }
  if (!signatureIsValid) failures.push('bad signature');

  return { failures, recomputedHash, event: isPlainObject(parsed) ? parsed : null };
}

export async function verifyMoltPackage(directory) {
  if (!isAbsolute(directory)) {
    return fail('V-01', 'Evidence path must be absolute.');
  }

  const root = resolve(directory);
  let rootInfo;

  try {
    rootInfo = await lstat(root);
  } catch (error) {
    return fail('V-01', `Cannot read package directory: ${error.message}`);
  }

  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    return fail('V-01', 'Evidence package is not a real directory.');
  }

  const manifestPath = resolve(root, 'manifest.json');
  const eventsPath = resolve(root, 'events.jsonl');
  const publicPath = resolve(root, 'ed25519-public.pem');

  let manifestStat;
  let eventsStat;

  try {
    for (const path of [manifestPath, eventsPath, publicPath]) {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink()) {
        return fail('V-02', 'Manifest, event ledger, or public key is missing or not a regular file.');
      }
    }
    [manifestStat, eventsStat] = await Promise.all([lstat(manifestPath), lstat(eventsPath)]);
  } catch {
    return fail('V-02', 'Manifest, event ledger, or public key is missing or not a regular file.');
  }

  if (manifestStat.size > MAX_MANIFEST_BYTES || eventsStat.size > MAX_LEDGER_BYTES) {
    return fail('V-03', 'Evidence package exceeds its size limit.');
  }

  let manifestBytes;
  let eventsBytes;
  let publicBytes;

  try {
    [manifestBytes, eventsBytes, publicBytes] = await Promise.all([
      readFile(manifestPath),
      readFile(eventsPath),
      readFile(publicPath),
    ]);
  } catch (error) {
    return fail('V-02', `Cannot read package control files: ${error.message}`);
  }

  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let manifestText;
  let eventsText;
  let publicPem;

  try {
    manifestText = decoder.decode(manifestBytes);
    eventsText = decoder.decode(eventsBytes);
    publicPem = decoder.decode(publicBytes);
  } catch {
    return fail('V-04', 'Package contains invalid UTF-8 or a truncated multi-byte sequence.');
  }

  let manifestValue;
  try {
    manifestValue = JSON.parse(manifestText);
  } catch {
    return fail('V-05', 'Manifest JSON is invalid or truncated.');
  }

  if (!isPlainObject(manifestValue)) {
    return fail('V-05', 'Manifest root is not a JSON object.');
  }

  const manifest = manifestValue;
  const artifacts = manifest.artifacts;
  const artifactBytes = manifest.artifact_bytes;
  const agentKeys = manifest.agent_pubkeys;
  const ledgerBytes = manifest.ledger_bytes;

  if (
    !isPlainObject(artifacts) ||
    !isPlainObject(artifactBytes) ||
    !isPlainObject(agentKeys) ||
    !Number.isSafeInteger(ledgerBytes) ||
    ledgerBytes < 0
  ) {
    return fail('V-06', 'Manifest must contain artifacts, artifact_bytes, agent_pubkeys, and ledger_bytes.');
  }

  if (Object.keys(artifacts).length !== Object.keys(artifactBytes).length) {
    return fail('V-06', 'Manifest artifact_bytes must cover every artifact.');
  }

  if (eventsText.length > 0 && !eventsText.endsWith('\n')) {
    return fail('V-04', 'events.jsonl is truncated: final line has no newline.');
  }

  if (Buffer.byteLength(eventsText, 'utf8') !== ledgerBytes) {
    return fail('V-04', 'events.jsonl byte count does not match manifest.ledger_bytes.');
  }

  let publicKey;
  let publicHex;
  let keyId;

  try {
    publicKey = createPublicKey(publicPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      return fail('V-07', 'Manifest verifier key is not Ed25519.');
    }

    const der = Buffer.from(publicKey.export({ format: 'der', type: 'spki' }));
    const rawPublicKey = der.subarray(-32);
    if (rawPublicKey.length !== 32) {
      return fail('V-07', 'Manifest verifier key encoding is invalid.');
    }

    publicHex = rawPublicKey.toString('hex');
    keyId = sha256(rawPublicKey);
  } catch (error) {
    return fail('V-07', `Cannot parse Ed25519 public key: ${error.message}`);
  }

  for (const [name, digest] of Object.entries(artifacts)) {
    if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/i.test(digest)) {
      return fail('V-08', `Manifest contains an invalid artifact digest for '${name}'.`, { keyId });
    }

    const expectedBytes = artifactBytes[name];
    if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 0) {
      return fail('V-08', `Manifest contains an invalid byte count for '${name}'.`, { keyId });
    }

    let bytes;
    try {
      bytes = await readContainedArtifact(root, name);
    } catch (error) {
      return fail('V-08', error.message, { keyId });
    }

    if (bytes.length !== expectedBytes) {
      return fail('V-08', `Artifact byte count mismatch for '${name}'.`, { keyId });
    }

    if (sha256(bytes) !== digest.toLowerCase()) {
      return fail('V-08', `Artifact digest mismatch for '${name}'.`, { keyId });
    }
  }

  const rows = eventsText ? eventsText.split('\n') : [];
  if (rows.at(-1) === '') rows.pop();

  let previousRecomputedHash = null;
  const recomputedHashes = [];
  const parsedEvents = [];

  for (let index = 0; index < rows.length; index += 1) {
    const line = rows[index];

    if (!line || Buffer.byteLength(line) > MAX_EVENT_BYTES) {
      return fail('V-09', 'invalid JSON', {
        count: rows.length,
        firstInvalidSequence: index,
        keyId,
      });
    }

    const result = checkEvent(line, index, previousRecomputedHash, publicKey, publicHex, agentKeys);

    if (result.failures.length > 0) {
      return fail('V-09', result.failures[0], {
        count: rows.length,
        firstInvalidSequence: index,
        keyId,
      });
    }

    previousRecomputedHash = result.recomputedHash;
    recomputedHashes[index] = result.recomputedHash;
    parsedEvents[index] = result.event;
  }

  let anchor = 'none';

  if (Object.hasOwn(manifest, 'anchor')) {
    const anchorValue = manifest.anchor;

    if (
      !isPlainObject(anchorValue) ||
      !Number.isInteger(anchorValue.seq) ||
      anchorValue.seq < 0 ||
      typeof anchorValue.hash !== 'string' ||
      !HASH_FORMAT.test(anchorValue.hash)
    ) {
      return fail('V-10', 'Manifest anchor is malformed.', {
        count: rows.length,
        keyId,
        anchor: 'none',
      });
    }

    const anchoredEvent = parsedEvents[anchorValue.seq];
    const anchoredRecomputedHash = recomputedHashes[anchorValue.seq];

    if (!anchoredEvent) {
      return fail('V-10', 'Anchored event sequence is not present.', {
        count: rows.length,
        keyId,
        anchor: 'none',
      });
    }

    if (
      anchoredEvent.hash !== anchorValue.hash ||
      anchoredRecomputedHash !== anchorValue.hash
    ) {
      return fail('V-10', 'Anchor hash mismatch.', {
        count: rows.length,
        keyId,
        anchor: 'none',
      });
    }

    anchor = 'verified';
  }

  return pass({ count: rows.length, keyId, anchor });
}
