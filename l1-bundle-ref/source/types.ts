export type ExecutionState = "blocked" | "queued" | "running" | "succeeded" | "failed" | "stopped";

export type RunInput = {
  mission: string;
  modelRepository: string;
  modelRevision: string;
  suiteId: string;
  agentProfileId: string;
  trials: number;
  timeoutSeconds: number;
};

export type AgentProfile = {
  id: string;
  name: string;
  description: string;
  tools: string[];
  writesAllowed: false;
  networkAllowed: false;
};

export type EvaluationSuite = {
  id: string;
  name: string;
  description: string;
  checks: string[];
  version: string;
};

export type ModelTarget = { repository: string; revision: string };

export type BackendJobRequest = {
  runId: string;
  command: string[];
  timeoutSeconds: number;
  networkPolicy: "none";
};

export type BackendJobOutput = {
  summary: string;
  stdout: string | null;
  exitCode: number | null;
};

export type BackendOutcome = {
  status: ExecutionState;
  jobId: string | null;
  reason: string | null;
  output: BackendJobOutput | null;
  verified?: boolean;
};

export type ExecutionBackendStatus = {
  name: string;
  configured: boolean;
  ready: boolean;
  reason: string | null;
  isolation: string;
};

export interface ExecutionBackend {
  readonly name: string;
  statusSummary(): ExecutionBackendStatus;
  run(request: BackendJobRequest): Promise<BackendOutcome>;
  status(jobId: string): Promise<BackendOutcome>;
  stop(jobId: string): Promise<BackendOutcome>;
}

export type ModelCandidate = {
  repository: string;
  revision: string;
  source: "mock" | "metadata-only";
  license: string | null;
  parameters: string | null;
};

export type EvaluationScore = {
  model: ModelTarget;
  suiteId: string;
  agentProfileId: string;
  score: number;
  passed: number;
  total: number;
  variance: number;
  evidenceHash: string;
  note: string;
};

export type ModelOperationResult<T> = {
  status: "blocked" | "completed";
  backend: string;
  reason: string | null;
  data: T | null;
};

export interface ModelBackend {
  readonly name: string;
  statusSummary(): { name: string; configured: boolean; ready: boolean; reason: string | null; operations: string[] };
  discover(input: { task: string; limit: number }): Promise<ModelOperationResult<ModelCandidate[]>>;
  evaluate(input: { model: ModelTarget; suiteId: string; agentProfileId: string; trials: number }): Promise<ModelOperationResult<EvaluationScore>>;
  isolate(input: { model: ModelTarget; profileId: string }): Promise<ModelOperationResult<{ isolated: boolean; network: "none"; writes: false }>>;
  improve(input: { agentProfileId: string; evidenceHash: string }): Promise<ModelOperationResult<{ proposals: string[]; promotion: "not-authorized" }>>;
}

export type MOLTEventBody = {
  seq: number;
  ts: number;
  type: string;
  payload: Record<string, unknown>;
  actor: string;
};

export type MOLTEvent = MOLTEventBody & {
  prev_hash: string;
  hash: string;
  pub: string;
  sig: string;
};

export type VerificationReport = {
  valid: boolean;
  count: number;
  firstInvalidSequence: number | null;
  reason: string | null;
  keyId: string | null;
  anchoring: "local-only";
};

export type IndependentVerificationReport = VerificationReport & {
  verifier: "standalone-molt-v1";
};

export type FoundryVerification = {
  valid: boolean;
  count: number;
  firstInvalidSequence: number | null;
  reason: string | null;
  keyId: string | null;
  anchoring: "local-only";
  independent: IndependentVerificationReport;
};

export type FoundryRun = {
  id: string;
  mission: string;
  target: ModelTarget;
  suiteId: string;
  agentProfileId: string;
  trials: number;
  timeoutSeconds: number;
  status: ExecutionState;
  backend: string;
  backendJobId: string | null;
  reason: string | null;
  output: BackendJobOutput | null;
  createdAt: string;
  updatedAt: string;
};

export type MOLTEventEvidence = {
  schema: "molt.evidence.v1";
  event: MOLTEvent;
  eventId: string;
  sequence: number;
  hash: string;
  signature: string;
  keyId: string;
  publicKey: string;
  anchoring: "local-only";
};

export type FoundryRunView = FoundryRun & {
  evidence: MOLTEventEvidence;
};

export const AGENT_PROFILES: AgentProfile[] = [
  {
    id: "read-only-research-v1",
    name: "Read-only researcher",
    description: "Answers from the bundled task context using a tiny, explicit read-only tool set.",
    tools: ["search_task_context", "read_task_document"],
    writesAllowed: false,
    networkAllowed: false,
  },
  {
    id: "read-only-code-review-v1",
    name: "Read-only code reviewer",
    description: "Reviews a pinned source snapshot with bounded search and file-read tools; cannot edit or execute it.",
    tools: ["list_snapshot_files", "search_snapshot", "read_snapshot_file"],
    writesAllowed: false,
    networkAllowed: false,
  },
];

export const EVALUATION_SUITES: EvaluationSuite[] = [
  {
    id: "tool-boundary-v1",
    name: "Tool boundary and injection",
    description: "Checks that untrusted task content cannot expand tool authority or escape the read-only profile.",
    checks: ["allowlisted-tool-use", "prompt-injection-resistance", "no-write-attempt", "no-network-request"],
    version: "1.0.0",
  },
  {
    id: "task-quality-v1",
    name: "Task quality and evidence",
    description: "Scores answer usefulness, citation to supplied context, and consistent handling of uncertainty.",
    checks: ["task-completion", "evidence-grounding", "uncertainty-calibration", "repeatability"],
    version: "1.0.0",
  },
  {
    id: "recovery-v1",
    name: "Failure recovery",
    description: "Checks bounded retries, honest failure reporting, and safe stop behavior under injected faults.",
    checks: ["bounded-retry", "stop-respected", "failure-reporting", "no-partial-success-claim"],
    version: "1.0.0",
  },
];

const MODEL_REPOSITORY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA40 = /^[a-f0-9]{40}$/i;

export function validateRunInput(input: RunInput): RunInput {
  if (!input || typeof input !== "object") throw new TypeError("A run request is required.");
  const mission = typeof input.mission === "string" ? input.mission.trim() : "";
  if (mission.length < 12 || mission.length > 1_500 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(mission)) throw new TypeError("Mission must be 12–1,500 printable characters.");
  if (typeof input.modelRepository !== "string" || !MODEL_REPOSITORY.test(input.modelRepository)) throw new TypeError("Model target must use the owner/model form.");
  const modelRevision = typeof input.modelRevision === "string" ? input.modelRevision.trim() : "";
  if (!SHA40.test(modelRevision)) throw new TypeError("Model revision must be a full 40-character commit SHA before evaluation.");
  if (!EVALUATION_SUITES.some((suite) => suite.id === input.suiteId)) throw new TypeError("Unknown evaluation suite.");
  if (!AGENT_PROFILES.some((profile) => profile.id === input.agentProfileId)) throw new TypeError("Unknown constrained agent profile.");
  if (!Number.isInteger(input.trials) || input.trials < 1 || input.trials > 10) throw new TypeError("Trial count must be an integer from 1 to 10.");
  if (!Number.isInteger(input.timeoutSeconds) || input.timeoutSeconds < 60 || input.timeoutSeconds > 300) throw new TypeError("Timeout must be an integer from 60 to 300 seconds.");
  return { mission, modelRepository: input.modelRepository, modelRevision, suiteId: input.suiteId, agentProfileId: input.agentProfileId, trials: input.trials, timeoutSeconds: input.timeoutSeconds };
}
