#!/usr/bin/env node
import {
  bootstrapPackage,
  emergencyRotatePackage,
  generateIdentityFile,
  inspectIdentityFile,
  reissuePackage,
  revokeKey,
  rotatePackage,
  verifyPackage,
} from "../src/key-management.mjs";

function usage() {
  return [
    "molt-keyctl commands:",
    "  generate-identity --out FILE [--purpose TEST-ONLY|manifest-signer|recovery]",
    "  inspect-identity --identity FILE (prints public metadata only)",
    "  bootstrap --package DIR --manifest-note FILE --current-identity FILE --recovery-identity FILE --out DIR --trust-out FILE",
    "  rotate --package DIR --trust FILE --old-identity FILE --new-identity FILE --out DIR --trust-out FILE",
    "  revoke --package DIR --trust FILE --recovery-identity FILE --key-id HEX --out DIR --trust-out FILE",
    "  emergency --package DIR --trust FILE --recovery-identity FILE --new-identity FILE --out DIR --trust-out FILE",
    "  reissue --package DIR --trust FILE --new-identity FILE --out DIR --reviewed",
    "  verify --package DIR --trust FILE",
  ].join("\n");
}

function parseArgs(argv) {
  const command = argv[0];
  const values = {};
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--reviewed") {
      values[token.slice(2)] = true;
      continue;
    }
    if (!token?.startsWith("--") || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error("Invalid command arguments.");
    values[token.slice(2)] = argv[index + 1];
    index += 1;
  }
  return { command, values };
}

function required(values, names) {
  const missing = names.filter((name) => !values[name]);
  if (missing.length) throw new Error(`Missing required options: ${missing.map((name) => `--${name}`).join(", ")}`);
}

async function main() {
  const { command, values } = parseArgs(process.argv.slice(2));
  if (!command || command === "--help" || command === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  let result;
  if (command === "generate-identity") {
    required(values, ["out"]);
    result = await generateIdentityFile(values.out, values.purpose || "manifest-signer");
  } else if (command === "inspect-identity") {
    required(values, ["identity"]);
    result = await inspectIdentityFile(values.identity);
  } else if (command === "bootstrap") {
    required(values, ["package", "manifest-note", "current-identity", "recovery-identity", "out", "trust-out"]);
    result = await bootstrapPackage({ packageDir: values.package, manifestNotePath: values["manifest-note"], currentIdentityPath: values["current-identity"], recoveryIdentityPath: values["recovery-identity"], outDir: values.out, trustOutPath: values["trust-out"] });
  } else if (command === "rotate") {
    required(values, ["package", "trust", "old-identity", "new-identity", "out", "trust-out"]);
    result = await rotatePackage({ packageDir: values.package, trustPath: values.trust, oldIdentityPath: values["old-identity"], newIdentityPath: values["new-identity"], outDir: values.out, trustOutPath: values["trust-out"] });
  } else if (command === "revoke") {
    required(values, ["package", "trust", "recovery-identity", "key-id", "out", "trust-out"]);
    result = await revokeKey({ packageDir: values.package, trustPath: values.trust, recoveryIdentityPath: values["recovery-identity"], keyId: values["key-id"], outDir: values.out, trustOutPath: values["trust-out"] });
  } else if (command === "emergency") {
    required(values, ["package", "trust", "recovery-identity", "new-identity", "out", "trust-out"]);
    result = await emergencyRotatePackage({ packageDir: values.package, trustPath: values.trust, recoveryIdentityPath: values["recovery-identity"], newIdentityPath: values["new-identity"], outDir: values.out, trustOutPath: values["trust-out"] });
  } else if (command === "reissue") {
    required(values, ["package", "trust", "new-identity", "out"]);
    if (!values.reviewed) throw new Error("Re-issue requires --reviewed after owner review of the artifact contents.");
    result = await reissuePackage({ packageDir: values.package, trustPath: values.trust, newIdentityPath: values["new-identity"], outDir: values.out, reviewed: true });
  } else if (command === "verify") {
    required(values, ["package", "trust"]);
    result = await verifyPackage(values.package, values.trust);
  } else {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 2;
    return;
  }
  if (command === "verify") process.stdout.write(`PASS check: KEY_HISTORY_CURRENT + ${result.verifier}; count=${result.count}; keyId=${result.keyId}\n`);
  else process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

main().catch((error) => {
  const check = error?.check || "COMMAND_FAILED";
  process.stderr.write(`FAIL check: ${check}; ${error instanceof Error ? error.message : "Unknown failure."}\n`);
  process.exitCode = 1;
});
