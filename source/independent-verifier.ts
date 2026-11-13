import { verifyMoltPackage } from "./molt-verify.mjs";
import type { IndependentVerificationReport } from "./types";

export async function independentlyVerifyMoltPackage(directory: string): Promise<IndependentVerificationReport> {
  const result = await verifyMoltPackage(directory);
  return {
    valid: result.valid,
    count: result.count,
    firstInvalidSequence: result.firstInvalidSequence,
    reason: result.valid ? null : `${result.checkId}: ${result.reason}`,
    keyId: result.keyId,
    anchoring: "local-only",
    verifier: "standalone-molt-v1",
  };
}
