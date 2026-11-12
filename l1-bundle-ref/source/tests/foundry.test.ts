import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { transitionAgentbookEntry, type AgentbookEntry } from "../foundry/agentbook";
import { DockerMiddlewareBackend } from "../foundry/docker-middleware";
import { StubExecutionBackend, MockExecutionBackend } from "../foundry/execution-backend";
import { MoltLedger } from "../foundry/ledger";
import { independentlyVerifyMoltPackage } from "../foundry/independent-verifier";
import { MockModelBackend, StubModelBackend } from "../foundry/model-backend";import { createFoundryApi } from "../foundry/api";
import { FoundryService } from "../foundry/service";
import type { BackendJobRequest, ExecutionBackend, ModelBackend, RunInput } from "../foundry/types";

const temporaryDirectories: string[] = [];

async function makeDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "agent-llm-foundry-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

function runInput(overrides: Partial<RunInput> = {}): RunInput {
  return {
    mission: "Compare this pinned model on a constrained task suite.",
    modelRepository: "fixture/tiny-instruct",
    modelRevision: "a".repeat(40),
    suiteId: "tool-boundary-v1",
    agentProfileId: "read-only-research-v1",
    trials: 3,
    timeoutSeconds: 60,
    ...overrides,
  };
}

function serviceAt(directory: string, backend: ExecutionBackend = new StubExecutionBackend(), model: ModelBackend = new StubModelBackend()) {
  return new FoundryService(backend, model, new MoltLedger(join(directory, "evidence")));
}

const safeJob: BackendJobRequest = {
  runId: "01234567-89ab-4cde-8f01-23456789abcd",
  command: ["foundry-runner", "evaluate", "--mission", "test a safe argument"],
  timeoutSeconds: 60,
  networkPolicy: "none",
};

describe("Agent & LLM Foundry", () => {
  test("stub execution returns a precise blocked report and signs a Forge-compatible MOLT record", async () => {
    const directory = await makeDirectory();
    const service = serviceAt(directory);
    const result = await service.createRun(runInput());

    expect(result.run.status).toBe("blocked");
    expect(result.run.backend).toBe("stub");
    expect(result.run.backendJobId).toBeNull();
    expect(result.run.output).toBeNull();
    expect(result.run.reason).toContain("No job was created");
    expect(result.evidence.event.type).toBe("foundry.run.blocked");
    expect(result.evidence.signature).toMatch(/^[a-f0-9]{128}$/);
    expect(result.evidence.event.seq).toBe(1);
    expect(result.verification.valid).toBe(true);
    expect(result.verification.independent.verifier).toBe("standalone-molt-v1");
    expect(result.verification.independent.count).toBe(2);

    const ledger = await readFile(join(directory, "evidence", "events.jsonl"), "utf8");
    expect(ledger.trim().split("\n")).toHaveLength(2);
    expect(await readFile(join(directory, "evidence", "manifest.json"), "utf8")).toContain("foundry-control");
    expect(await readFile(join(directory, "evidence", "ed25519-public.pem"), "utf8")).toContain("PUBLIC KEY");
    expect(await Bun.file(join(directory, "evidence", "ed25519-private.pem")).exists()).toBe(false);
  });

  test("mock execution completes without running a model or claiming real isolation", async () => {
    const directory = await makeDirectory();
    const backend = new MockExecutionBackend();
    const result = await serviceAt(directory, backend).createRun(runInput());

    expect(result.run.status).toBe("succeeded");
    expect(result.run.backend).toBe("mock-test-only");
    expect(result.run.backendJobId).toBe("mock-job-1");
    expect((await backend.status("mock-job-1")).status).toBe("succeeded");
    expect((await backend.statusSummary()).isolation).toBe("simulated-test-only");
    expect(result.verification.valid).toBe(true);
  });

  test("mock model scores are labeled synthetic and all model operations remain replaceable behind one interface", async () => {
    const modelBackend = new MockModelBackend();
    const candidates = await modelBackend.discover({ task: "tiny-instruct", limit: 10 });
    expect(candidates.status).toBe("completed");
    expect(candidates.backend).toBe("mock");
    expect(candidates.data?.[0]?.source).toBe("mock");
    const score = await modelBackend.evaluate({
      model: { repository: "fixture/tiny-instruct", revision: "a".repeat(40) },
      suiteId: "tool-boundary-v1",
      agentProfileId: "read-only-research-v1",
      trials: 7,
    });
    expect(score.data?.total).toBe(7);
    expect(score.data?.note).toContain("not a model evaluation");
    expect((await modelBackend.isolate({ model: { repository: "fixture/tiny-instruct", revision: "a".repeat(40) }, profileId: "read-only-research-v1" })).data?.isolated).toBe(false);
    expect((await new StubModelBackend().discover({ task: "research", limit: 5 })).status).toBe("blocked");
  });

  test("invalid model revisions and invalid run limits fail closed", async () => {
    const directory = await makeDirectory();
    const service = serviceAt(directory);
    await expect(service.createRun(runInput({ modelRevision: "main" }))).rejects.toThrow("full 40-character commit SHA");
    await expect(service.createRun(runInput({ timeoutSeconds: 301 }))).rejects.toThrow("60 to 300 seconds");
    await expect(service.createRun(runInput({ trials: 0 }))).rejects.toThrow("1 to 10");
  });

  test("T340 adapter sends only an argv array to an allowlisted image with network and host access disabled", async () => {
    let receivedUrl = "";
    let receivedInit: RequestInit | undefined;
    const backend = new DockerMiddlewareBackend({
      baseUrl: "https://middleware.example.test",
      token: "test-token-that-is-long-enough",
      image: "registry.example.test/foundry-runner:1",
      allowedImages: ["registry.example.test/foundry-runner:1"],
      fetcher: async (input, init) => {
        receivedUrl = String(input);
        receivedInit = init;
        return new Response(JSON.stringify({ job_id: "job-1", state: "queued" }), { status: 202, headers: { "content-type": "application/json" } });
      },
    });
    const outcome = await backend.run(safeJob);
    const body = JSON.parse(String(receivedInit?.body));

    expect(outcome.status).toBe("queued");
    expect(outcome.jobId).toBe("job-1");
    expect(receivedUrl).toBe("https://middleware.example.test/job");
    expect(receivedInit?.method).toBe("POST");
    expect((receivedInit?.headers as Record<string, string>).authorization).toBe("Bearer test-token-that-is-long-enough");
    expect(body.command).toEqual(safeJob.command);
    expect(Array.isArray(body.command)).toBe(true);
    expect(body.network_policy).toBe("none");
    expect(body.privileged).toBe(false);
    expect(body.mounts).toEqual([]);
    expect(body.volumes).toEqual([]);
    expect(body.timeout).toBe(60);
  });

  test("T340 refuses images outside the exact allowlist and refuses non-loopback HTTP", async () => {
    let fetchCount = 0;
    const fetcher = async () => {
      fetchCount += 1;
      return new Response("{}", { status: 200 });
    };
    const wrongImage = new DockerMiddlewareBackend({
      baseUrl: "https://middleware.example.test",
      token: "test-token-that-is-long-enough",
      image: "untrusted/image:latest",
      allowedImages: ["registry.example.test/foundry-runner:1"],
      fetcher,
    });
    const insecureUrl = new DockerMiddlewareBackend({
      baseUrl: "http://middleware.example.test",
      token: "test-token-that-is-long-enough",
      image: "registry.example.test/foundry-runner:1",
      allowedImages: ["registry.example.test/foundry-runner:1"],
      fetcher,
    });

    expect((await wrongImage.run(safeJob)).status).toBe("blocked");
    expect((await insecureUrl.run(safeJob)).status).toBe("blocked");
    expect(fetchCount).toBe(0);
  });

  test("T340 stop remains unconfirmed unless the middleware reports stopped", async () => {
    const directory = await makeDirectory();
    const calls: string[] = [];
    const backend = new DockerMiddlewareBackend({
      baseUrl: "https://middleware.example.test",
      token: "test-token-that-is-long-enough",
      image: "registry.example.test/foundry-runner:1",
      allowedImages: ["registry.example.test/foundry-runner:1"],
      fetcher: async (input, init) => {
        const url = String(input);
        calls.push(`${init?.method} ${url}`);
        if (init?.method === "GET") return new Response(JSON.stringify({ job_id: "job-1", state: "running" }), { status: 200 });
        if (url.endsWith("/stop")) return new Response(JSON.stringify({ job_id: "job-1", state: "running" }), { status: 200 });
        return new Response(JSON.stringify({ job_id: "job-1", state: "queued" }), { status: 202 });
      },
    });
    const service = serviceAt(directory, backend);
    const created = await service.createRun(runInput());
    const running = await service.getRun(created.run.id, true);
    expect(running?.run.status).toBe("running");
    await expect(service.stopRun(created.run.id)).rejects.toThrow("did not confirm a stopped state");
    expect((await service.getRun(created.run.id, false))?.run.status).toBe("running");
    expect(calls).toContain("POST https://middleware.example.test/job/job-1/stop");
  });

  test("independent MOLT verification detects a changed signed payload", async () => {
    const directory = await makeDirectory();
    const ledger = new MoltLedger(join(directory, "evidence"));
    const event = await ledger.append({ type: "foundry.test", actor: "foundry-control", payload: { score: 1 } });
    expect((await ledger.verify()).valid).toBe(true);
    expect((await independentlyVerifyMoltPackage(ledger.directory)).valid).toBe(true);

    const eventsPath = join(ledger.directory, "events.jsonl");
    const lines = (await readFile(eventsPath, "utf8")).trim().split("\n");
    const record = JSON.parse(lines[0]!);
    record.payload.score = 2;
    await writeFile(eventsPath, `${JSON.stringify(record)}\n`);

    const primary = await ledger.verify();
    const independent = await independentlyVerifyMoltPackage(ledger.directory);
    expect(primary.valid).toBe(false);
    expect(independent.valid).toBe(false);
    expect(event.hash).not.toBe(createHash("sha256").update(JSON.stringify(record.payload)).digest("hex"));
  });

  test("HTTP control plane is locked without a strong bearer secret and records authorized blocked runs", async () => {
    const directory = await makeDirectory();
    const service = serviceAt(directory);
    const token = "foundry-control-test-token-0123456789abcdef";
    const locked = createFoundryApi(service, undefined);
    const unconfigured = await locked.request("/runs");
    expect(unconfigured.status).toBe(503);

    const api = createFoundryApi(service, token);
    expect((await api.request("/status")).status).toBe(200);
    expect((await api.request("/runs")).status).toBe(401);
    const rejected = await api.request("/runs", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer wrong-token" },
      body: JSON.stringify(runInput()),
    });
    expect(rejected.status).toBe(401);

    const response = await api.request("/runs", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(runInput()),
    });
    expect(response.status).toBe(201);
    const result = await response.json() as { run: { status: string }; verification: { valid: boolean; independent: { valid: boolean } } };
    expect(result.run.status).toBe("blocked");
    expect(result.verification.valid).toBe(true);
    expect(result.verification.independent.valid).toBe(true);
    expect((await api.request("/runs", { headers: { authorization: `Bearer ${token}` } })).status).toBe(200);
  });

  test("MOLT initialization refuses to recreate missing trust files", async () => {
    const directory = await makeDirectory();
    const ledger = new MoltLedger(join(directory, "evidence"));
    await ledger.append({ type: "foundry.test", actor: "foundry-control", payload: { durable: true } });
    await rm(ledger.eventsPath);
    await expect(ledger.verify()).rejects.toThrow("incomplete");
  });

  test("Agentbook promotion needs signed evidence, independent review, and passing security gates", () => {
    const initial: AgentbookEntry = {
      id: "read-only-research-v1",
      label: "Read-only researcher",
      state: "discovered",
      createdAt: new Date(0).toISOString(),
      updatedAt: new Date(0).toISOString(),
      evidenceHashes: [],
      lastScore: null,
    };
    const trial = transitionAgentbookEntry(initial, "trial");
    expect(() => transitionAgentbookEntry(trial, "validated", {
      score: 0.95,
      evidenceHashes: ["a".repeat(64)],
      independentReviewVerified: false,
      securityChecksPassed: true,
    })).toThrow("independently verified review");
    const validated = transitionAgentbookEntry(trial, "validated", {
      score: 0.95,
      evidenceHashes: ["a".repeat(64)],
      independentReviewVerified: true,
      securityChecksPassed: true,
    });
    expect(transitionAgentbookEntry(validated, "standard", {
      score: 0.95,
      evidenceHashes: ["b".repeat(64)],
      independentReviewVerified: true,
      securityChecksPassed: true,
    }).state).toBe("standard");
  });
});
