import { createFoundryService } from "./runtime";
import { EVALUATION_SUITES, AGENT_PROFILES, type RunInput } from "./types";

const usage = `Run one pinned model evaluation request through the configured backend.

Usage:
  bun run foundry:run -- --mission TEXT --model OWNER/REPOSITORY --revision SHA40 [options]

Options:
  --mission TEXT       Evaluation objective (required)
  --model OWNER/NAME   Model repository identifier (required)
  --revision SHA40     Immutable 40-character model revision (required)
  --suite ID           Evaluation suite (default: ${EVALUATION_SUITES[0]!.id})
  --profile ID         Read-only agent profile (default: ${AGENT_PROFILES[0]!.id})
  --trials N           Number of trials, 1–10 (default: 1)
  --timeout N          Backend timeout in seconds, 60–300 (default: 60)
  --help               Show this help

The default backend is the fail-closed stub. It records a signed blocked result and never runs model or repository code on this host.`;

function parseArgs(args: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (key === "--help") return { help: "true" };
    if (!key?.startsWith("--") || !args[index + 1] || args[index + 1]!.startsWith("--")) {
      throw new Error(`Invalid command arguments near '${key ?? ""}'.`);
    }
    const name = key.slice(2);
    if (!["mission", "model", "revision", "suite", "profile", "trials", "timeout"].includes(name)) {
      throw new Error(`Unknown option '${key}'.`);
    }
    if (result[name] !== undefined) throw new Error(`Option '${key}' may only be provided once.`);
    result[name] = args[index + 1]!;
    index += 1;
  }
  return result;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage);
    return;
  }
  if (!args.mission || !args.model || !args.revision) throw new Error("--mission, --model, and --revision are required.");
  const input: RunInput = {
    mission: args.mission,
    modelRepository: args.model,
    modelRevision: args.revision,
    suiteId: args.suite ?? EVALUATION_SUITES[0]!.id,
    agentProfileId: args.profile ?? AGENT_PROFILES[0]!.id,
    trials: args.trials === undefined ? 1 : Number(args.trials),
    timeoutSeconds: args.timeout === undefined ? 60 : Number(args.timeout),
  };
  const service = createFoundryService();
  const result = await service.createRun(input);
  if (!result.verification.valid || !result.verification.independent.valid) {
    throw new Error("The MOLT evidence record failed independent verification.");
  }
  console.log(JSON.stringify({
    run: result.run,
    evidence: result.evidence,
    verification: result.verification,
  }, null, 2));
  if (result.run.status === "blocked") {
    console.error(`BLOCKED: ${result.run.reason ?? "No isolated execution backend is configured."}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Foundry run failed.");
  console.error("\n" + usage);
  process.exitCode = 1;
});
