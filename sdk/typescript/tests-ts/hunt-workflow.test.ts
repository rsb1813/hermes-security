// Verifies the experimental Hunt workflow helper.

import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";

const pluginRoot = join(import.meta.dir, "..", "_bundled_plugin");
const huntScript = join(pluginRoot, "scripts", "hunt_workflow.py");
const temporaryRoots: string[] = [];

function pythonExecutable(): string {
  const python =
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py");
  expect(python).not.toBeNull();
  return python!;
}

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "hermes-hunt-test-"));
  temporaryRoots.push(root);
  return root;
}

function writeJsonl(path: string, rows: object[]): void {
  writeFileSync(path, rows.map((row) => JSON.stringify(row)).join("\n") + "\n");
}

function readJsonl<T>(path: string): T[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as T);
}

function runHunt(...args: string[]) {
  const [command, ...commandArgs] = args;
  const boundedArgs = args.includes("--work-dir")
    ? args
    : [
        command!,
        "--work-dir",
        tmpdir(),
        "--repository",
        pluginRoot,
        ...commandArgs,
      ];
  return Bun.spawnSync([pythonExecutable(), "-B", huntScript, ...boundedArgs], {
    cwd: pluginRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

const rankInput = [
  {
    path: "src/api/route.py",
    area: "api",
    preview: "def handle(request): return service(request)",
  },
  {
    path: "src/api/util.py",
    area: "api",
    preview: "def helper(value): return value",
  },
  {
    path: "src/storage/db.py",
    area: "storage",
    preview: "cursor.execute(query)",
  },
  {
    path: "src/storage/low.py",
    area: "storage",
    preview: "def low_priority_helper(): pass",
  },
];

const rankOutput = [
  {
    path: "src/api/route.py",
    area: "api",
    score: 10,
    include: true,
    reason: "reachable request handler",
  },
  {
    path: "src/api/util.py",
    area: "api",
    score: 9,
    include: true,
    reason: "shared helper",
  },
  {
    path: "src/storage/db.py",
    area: "storage",
    score: 8,
    include: true,
    reason: "query sink",
  },
  {
    path: "src/storage/low.py",
    area: "storage",
    score: 1,
    include: false,
    reason: "low initial risk",
  },
];

type FrontierRow = {
  work_id: string;
  path: string;
  component: string;
  passes: string[];
  rank_include: boolean;
};

type ClosureRow = {
  work_id: string;
  status: "reviewed" | "no_candidate" | "deferred";
  candidate_ids: string[];
  notes: string;
};

function makeFrontier(profile: "hunt-balanced" | "hunt-max") {
  const root = temporaryRoot();
  const input = join(root, "rank-input.jsonl");
  const ranked = join(root, "rank-output.jsonl");
  const frontier = join(root, "frontier.jsonl");
  const receipt = join(root, "receipt.json");
  writeJsonl(input, rankInput);
  writeJsonl(ranked, rankOutput);
  const result = runHunt(
    "make-frontier",
    "--rank-input",
    input,
    "--rank-output",
    ranked,
    "--profile",
    profile,
    "--out",
    frontier,
    "--receipt",
    receipt,
  );
  return { result, frontier, receipt };
}

test("rejects Hunt outputs outside the declared work directory", () => {
  const root = temporaryRoot();
  const work = join(root, "work");
  const repository = join(root, "repository");
  mkdirSync(work);
  mkdirSync(repository);
  const input = join(work, "rank-input.jsonl");
  const victim = join(repository, "source.py");
  writeJsonl(input, rankInput);
  writeFileSync(victim, "original source\n");

  const result = runHunt(
    "make-frontier",
    "--work-dir",
    work,
    "--repository",
    repository,
    "--rank-input",
    input,
    "--profile",
    "hunt-balanced",
    "--out",
    victim,
    "--receipt",
    join(work, "receipt.json"),
  );

  expect(result.exitCode).toBe(2);
  expect(result.stderr.toString()).toContain("outside Hunt work directory");
  expect(readFileSync(victim, "utf8")).toBe("original source\n");
});

test("retains every ranked path and starts with a component coverage round", () => {
  const { result, frontier } = makeFrontier("hunt-balanced");
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  const rows = readJsonl<FrontierRow>(frontier);
  expect(rows.map((row) => row.path).sort()).toEqual(
    rankInput.map((row) => row.path).sort(),
  );
  expect(rows.find((row) => row.path.endsWith("low.py"))?.rank_include).toBe(
    false,
  );
  expect(new Set(rows.slice(0, 2).map((row) => row.component)).size).toBe(2);
});

test("assigns targeted balanced passes without losing general review", () => {
  const { result, frontier } = makeFrontier("hunt-balanced");
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  const rows = readJsonl<FrontierRow>(frontier);
  expect(rows.find((row) => row.path.endsWith("route.py"))?.passes).toContain(
    "forward",
  );
  expect(rows.find((row) => row.path.endsWith("db.py"))?.passes).toContain(
    "backward",
  );
  expect(rows.every((row) => row.passes.length > 0)).toBe(true);
});

test("assigns both directions to every hunt-max frontier row", () => {
  const { result, frontier } = makeFrontier("hunt-max");
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  const rows = readJsonl<FrontierRow>(frontier);
  expect(rows.every((row) => row.passes.includes("forward"))).toBe(true);
  expect(rows.every((row) => row.passes.includes("backward"))).toBe(true);
});

test("writes stable frontier bytes and cache identity", () => {
  const first = makeFrontier("hunt-balanced");
  const second = makeFrontier("hunt-balanced");
  expect(first.result.exitCode, first.result.stderr.toString()).toBe(0);
  expect(second.result.exitCode, second.result.stderr.toString()).toBe(0);
  expect(readFileSync(first.frontier)).toEqual(readFileSync(second.frontier));
  const firstReceipt = JSON.parse(readFileSync(first.receipt, "utf8")) as {
    cache_key: string;
  };
  const secondReceipt = JSON.parse(readFileSync(second.receipt, "utf8")) as {
    cache_key: string;
  };
  expect(firstReceipt.cache_key).toBe(secondReceipt.cache_key);
});

function completeClosures(rows: FrontierRow[]): ClosureRow[] {
  return rows.map((row, index) => ({
    work_id: row.work_id,
    status: index === 0 ? "reviewed" : "no_candidate",
    candidate_ids: index === 0 ? ["candidate-a"] : [],
    notes: index === 0 ? "candidate recorded" : "reviewed without candidates",
  }));
}

function closeFrontier(frontier: string, closures: ClosureRow[]) {
  const root = temporaryRoot();
  const closurePath = join(root, "closures.jsonl");
  const receipt = join(root, "coverage-receipt.json");
  writeJsonl(closurePath, closures);
  const result = runHunt(
    "close-frontier",
    "--frontier",
    frontier,
    "--closures",
    closurePath,
    "--out",
    receipt,
  );
  return { result, receipt };
}

test("requires and records one terminal closure for every frontier row", () => {
  const made = makeFrontier("hunt-balanced");
  expect(made.result.exitCode, made.result.stderr.toString()).toBe(0);
  const frontier = readJsonl<FrontierRow>(made.frontier);
  const closed = closeFrontier(made.frontier, completeClosures(frontier));
  expect(closed.result.exitCode, closed.result.stderr.toString()).toBe(0);
  const receipt = JSON.parse(readFileSync(closed.receipt, "utf8")) as {
    total_items: number;
    reviewed: number;
    no_candidate: number;
    coverage_debt: object[];
  };
  expect(receipt).toMatchObject({
    total_items: 4,
    reviewed: 1,
    no_candidate: 3,
    coverage_debt: [],
  });
});

test("rejects a frontier with any missing closure", () => {
  const made = makeFrontier("hunt-balanced");
  expect(made.result.exitCode, made.result.stderr.toString()).toBe(0);
  const frontier = readJsonl<FrontierRow>(made.frontier);
  const closures = completeClosures(frontier).slice(0, -1);
  const closed = closeFrontier(made.frontier, closures);
  expect(closed.result.exitCode).toBe(2);
  expect(closed.result.stderr.toString()).toContain(frontier.at(-1)!.work_id);
});

test("keeps deferred review visible as coverage debt", () => {
  const made = makeFrontier("hunt-balanced");
  expect(made.result.exitCode, made.result.stderr.toString()).toBe(0);
  const frontier = readJsonl<FrontierRow>(made.frontier);
  const closures = completeClosures(frontier);
  closures[1] = {
    work_id: frontier[1]!.work_id,
    status: "deferred",
    candidate_ids: [],
    notes: "budget ended before the backward pass",
  };
  const closed = closeFrontier(made.frontier, closures);
  expect(closed.result.exitCode, closed.result.stderr.toString()).toBe(0);
  const receipt = JSON.parse(readFileSync(closed.receipt, "utf8")) as {
    deferred: number;
    coverage_debt: {
      work_id: string;
      path: string;
      component: string;
      passes: string[];
      notes: string;
    }[];
  };
  expect(receipt.deferred).toBe(1);
  expect(receipt.coverage_debt).toEqual([
    {
      work_id: frontier[1]!.work_id,
      path: frontier[1]!.path,
      component: frontier[1]!.component,
      passes: frontier[1]!.passes,
      notes: "budget ended before the backward pass",
    },
  ]);
});

test("rejects duplicate and unknown closure work ids", () => {
  const made = makeFrontier("hunt-balanced");
  expect(made.result.exitCode, made.result.stderr.toString()).toBe(0);
  const frontier = readJsonl<FrontierRow>(made.frontier);
  const closures = completeClosures(frontier);
  closures[1] = { ...closures[0]!, notes: "duplicate" };
  closures[2] = { ...closures[2]!, work_id: "hunt-unknown" };
  const closed = closeFrontier(made.frontier, closures);
  expect(closed.result.exitCode).toBe(2);
  expect(closed.result.stderr.toString()).toMatch(/duplicate|unknown/);
});

type CandidateRow = {
  candidate_id: string;
  cwe_ids: string[];
  locations: {
    path: string;
    start_line: number;
    end_line: number;
    role: string;
  }[];
  summary: string;
  evidence: string;
  context: string;
  instance: string;
};

function candidate(candidateId = "candidate-a"): CandidateRow {
  return {
    candidate_id: candidateId,
    cwe_ids: ["CWE-862"],
    locations: [
      {
        path: "src/api/route.py",
        start_line: 10,
        end_line: 10,
        role: "entrypoint",
      },
      {
        path: "src/policy.py",
        start_line: 20,
        end_line: 20,
        role: "root_control",
      },
      {
        path: "src/storage/db.py",
        start_line: 30,
        end_line: 30,
        role: "sink",
      },
    ],
    summary: "Missing object authorization reaches a protected update",
    evidence: "The route passes the requested object directly to save().",
    context: "The policy check covers the caller but not the requested object.",
    instance: `authorization:${candidateId}`,
  };
}

type ProofStatus = "proven" | "disproven" | "unknown";
type ValidationRow = {
  candidate_id: string;
  verifier_actor: string;
  disposition: "accepted" | "rejected" | "inconclusive";
  method: string;
  attacker_control: ProofStatus;
  reachability: ProofStatus;
  impact: ProofStatus;
  guard_failure: ProofStatus;
  evidence: string[];
  counterevidence: string[];
  proof_gaps: string[];
  preconditions: string[];
  impact_statement: string;
  remediation: string;
  uncertainty: string;
  confidence: "high" | "medium" | "low";
};

function acceptedValidation(candidateId = "candidate-a"): ValidationRow {
  return {
    candidate_id: candidateId,
    verifier_actor: "verifier-b",
    disposition: "accepted",
    method: "static_trace",
    attacker_control: "proven",
    reachability: "proven",
    impact: "proven",
    guard_failure: "proven",
    evidence: ["route.py:10 reaches db.py:30 without an object policy check"],
    counterevidence: [],
    proof_gaps: [],
    preconditions: ["The caller can select another object identifier."],
    impact_statement: "A caller can update another tenant's protected object.",
    remediation: "Authorize the selected object before the update.",
    uncertainty:
      "No runtime service was available; the complete static path was checked.",
    confidence: "high",
  };
}

function rejectedValidation(candidateId: string): ValidationRow {
  const validation = acceptedValidation(candidateId);
  validation.disposition = "rejected";
  validation.attacker_control = "disproven";
  validation.reachability = "unknown";
  validation.impact = "unknown";
  validation.guard_failure = "unknown";
  validation.counterevidence = [
    "The object identifier is replaced with the authenticated tenant ID.",
  ];
  validation.confidence = "high";
  validation.remediation = "";
  return validation;
}

function inconclusiveValidation(candidateId: string): ValidationRow {
  const validation = acceptedValidation(candidateId);
  validation.disposition = "inconclusive";
  validation.attacker_control = "unknown";
  validation.reachability = "unknown";
  validation.impact = "unknown";
  validation.guard_failure = "unknown";
  validation.proof_gaps = ["The generated route binding is unavailable."];
  validation.confidence = "low";
  validation.remediation = "";
  return validation;
}

function prepareValidation(candidates: CandidateRow[]) {
  const root = temporaryRoot();
  const candidatesPath = join(root, "candidates.jsonl");
  const output = join(root, "validation-input.jsonl");
  writeJsonl(candidatesPath, candidates);
  const result = runHunt(
    "prepare-validation",
    "--candidates",
    candidatesPath,
    "--out",
    output,
  );
  return { result, output, candidatesPath };
}

function validateDecisions(
  candidatesPath: string,
  validations: ValidationRow[],
  discoveryActor = "discoverer-a",
) {
  const root = temporaryRoot();
  const validationsPath = join(root, "validations.jsonl");
  const output = join(root, "validated.jsonl");
  writeJsonl(validationsPath, validations);
  const result = runHunt(
    "validate-decisions",
    "--candidates",
    candidatesPath,
    "--validations",
    validationsPath,
    "--discovery-actor",
    discoveryActor,
    "--out",
    output,
  );
  return { result, output };
}

test("prepares validation as an unverified hypothesis without conclusions", () => {
  const prepared = prepareValidation([candidate()]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const row = readJsonl<Record<string, unknown>>(prepared.output)[0]!;
  expect(row).toMatchObject({
    candidate_id: "candidate-a",
    hypothesis_status: "unverified",
    hypothesis: candidate().summary,
  });
  expect(row).not.toHaveProperty("confidence");
  expect(row).not.toHaveProperty("state");
  expect(row).not.toHaveProperty("discovery_actor");
});

test("rejects a validation performed by the discovery actor", () => {
  const prepared = prepareValidation([candidate()]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validation = acceptedValidation();
  validation.verifier_actor = "discoverer-a";
  const validated = validateDecisions(prepared.candidatesPath, [validation]);
  expect(validated.result.exitCode).toBe(2);
  expect(validated.result.stderr.toString()).toContain("independent verifier");
});

test("rejects accepted decisions with incomplete proof or unsafe methods", () => {
  const prepared = prepareValidation([candidate()]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const incomplete = acceptedValidation();
  incomplete.guard_failure = "unknown";
  let validated = validateDecisions(prepared.candidatesPath, [incomplete]);
  expect(validated.result.exitCode).toBe(2);
  expect(validated.result.stderr.toString()).toContain(
    "all four claims proven",
  );

  const unsafe = acceptedValidation();
  unsafe.method = "poc";
  validated = validateDecisions(prepared.candidatesPath, [unsafe]);
  expect(validated.result.exitCode).toBe(2);
  expect(validated.result.stderr.toString()).toContain("validation method");
});

test("requires one validation decision for every candidate", () => {
  const prepared = prepareValidation([candidate(), candidate("candidate-b")]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validated = validateDecisions(prepared.candidatesPath, [
    acceptedValidation(),
  ]);
  expect(validated.result.exitCode).toBe(2);
  expect(validated.result.stderr.toString()).toContain("candidate-b");
});

test("records accepted rejected and inconclusive state histories", () => {
  const candidates = [
    candidate(),
    candidate("candidate-b"),
    candidate("candidate-c"),
  ];
  const prepared = prepareValidation(candidates);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validated = validateDecisions(prepared.candidatesPath, [
    acceptedValidation(),
    rejectedValidation("candidate-b"),
    inconclusiveValidation("candidate-c"),
  ]);
  expect(validated.result.exitCode, validated.result.stderr.toString()).toBe(0);
  const rows = readJsonl<{
    candidate_id: string;
    state_history: string[];
  }>(validated.output);
  expect(rows.map((row) => row.state_history.at(-1))).toEqual([
    "accepted",
    "rejected",
    "inconclusive",
  ]);
});

function finalize(validated: string) {
  const root = temporaryRoot();
  const findings = join(root, "accepted-findings.json");
  const report = join(root, "draft-report.md");
  const receipt = join(root, "finalization-receipt.json");
  const result = runHunt(
    "finalize",
    "--validated",
    validated,
    "--findings-out",
    findings,
    "--report-out",
    report,
    "--receipt",
    receipt,
  );
  return { result, findings, report, receipt };
}

test("deduplicates exact roots while retaining every accepted instance", () => {
  const first = candidate();
  const second = candidate("candidate-b");
  second.locations[0] = {
    path: "src/api/admin-route.py",
    start_line: 40,
    end_line: 40,
    role: "entrypoint",
  };
  const rejected = candidate("candidate-c");
  rejected.summary = "Rejected neighboring hypothesis";
  const inconclusive = candidate("candidate-d");
  inconclusive.summary = "Inconclusive neighboring hypothesis";
  const prepared = prepareValidation([first, second, rejected, inconclusive]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validated = validateDecisions(prepared.candidatesPath, [
    acceptedValidation(),
    acceptedValidation("candidate-b"),
    rejectedValidation("candidate-c"),
    inconclusiveValidation("candidate-d"),
  ]);
  expect(validated.result.exitCode, validated.result.stderr.toString()).toBe(0);
  const finalized = finalize(validated.output);
  expect(finalized.result.exitCode, finalized.result.stderr.toString()).toBe(0);
  const output = JSON.parse(readFileSync(finalized.findings, "utf8")) as {
    findings: {
      candidate_ids: string[];
      instances: string[];
      locations: { path: string }[];
    }[];
  };
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.candidate_ids).toEqual([
    "candidate-a",
    "candidate-b",
  ]);
  expect(output.findings[0]!.instances).toHaveLength(2);
  expect(output.findings[0]!.locations.map((item) => item.path)).toContain(
    "src/api/admin-route.py",
  );
  const report = readFileSync(finalized.report, "utf8");
  expect(report).toContain("Source-to-operation trace");
  expect(report).toContain("Validation evidence");
  expect(report).toContain("Remediation");
  expect(report).not.toContain("Rejected neighboring hypothesis");
  expect(report).not.toContain("Inconclusive neighboring hypothesis");
  expect(report).not.toMatch(/^## .*PoC|^## .*Exploit/im);
  const receipt = JSON.parse(readFileSync(finalized.receipt, "utf8")) as {
    accepted_candidates: number;
    rejected_candidates: number;
    inconclusive_candidates: number;
    finalized_findings: number;
  };
  expect(receipt).toMatchObject({
    accepted_candidates: 2,
    rejected_candidates: 1,
    inconclusive_candidates: 1,
    finalized_findings: 1,
  });
});

test("does not merge findings with different root controls", () => {
  const first = candidate();
  const second = candidate("candidate-b");
  second.locations[1] = {
    ...second.locations[1]!,
    start_line: 21,
    end_line: 21,
  };
  const prepared = prepareValidation([first, second]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validated = validateDecisions(prepared.candidatesPath, [
    acceptedValidation(),
    acceptedValidation("candidate-b"),
  ]);
  expect(validated.result.exitCode, validated.result.stderr.toString()).toBe(0);
  const finalized = finalize(validated.output);
  expect(finalized.result.exitCode, finalized.result.stderr.toString()).toBe(0);
  const output = JSON.parse(readFileSync(finalized.findings, "utf8")) as {
    findings: object[];
  };
  expect(output.findings).toHaveLength(2);
});

test("writes byte-stable finalized findings and drafts", () => {
  const prepared = prepareValidation([candidate()]);
  expect(prepared.result.exitCode, prepared.result.stderr.toString()).toBe(0);
  const validated = validateDecisions(prepared.candidatesPath, [
    acceptedValidation(),
  ]);
  expect(validated.result.exitCode, validated.result.stderr.toString()).toBe(0);
  const first = finalize(validated.output);
  const second = finalize(validated.output);
  expect(first.result.exitCode, first.result.stderr.toString()).toBe(0);
  expect(second.result.exitCode, second.result.stderr.toString()).toBe(0);
  expect(readFileSync(first.findings)).toEqual(readFileSync(second.findings));
  expect(readFileSync(first.report)).toEqual(readFileSync(second.report));
});

test("ships the explicit Hunt skill and its complete workflow contract", () => {
  const skillPath = join(
    pluginRoot,
    "skills",
    "hunt-security-scan",
    "SKILL.md",
  );
  const agentPath = join(
    pluginRoot,
    "skills",
    "hunt-security-scan",
    "agents",
    "openai.yaml",
  );
  const contractPath = join(
    pluginRoot,
    "skills",
    "hunt-security-scan",
    "references",
    "hunt-contract.md",
  );
  const skill = readFileSync(skillPath, "utf8");
  const agent = readFileSync(agentPath, "utf8");
  const contract = readFileSync(contractPath, "utf8");
  const pluginFiles = JSON.parse(
    readFileSync(join(import.meta.dir, "..", "plugin-files.json"), "utf8"),
  ) as { shippedExact: string[] };

  for (const profile of ["hunt-balanced", "hunt-max"]) {
    expect(skill).toContain(profile);
  }
  for (const command of [
    "make-repo-rank-input",
    "make-rank-shards",
    "merge-rank-outputs",
    "make-frontier",
    "close-frontier",
    "prepare-validation",
    "validate-decisions",
    "finalize",
  ]) {
    expect(skill).toContain(command);
  }
  expect(skill).toContain("Ranking controls order, not eligibility");
  expect(skill).toContain("Do not generate exploits");
  expect(skill).toContain("Standard remains unchanged");
  expect(skill).toContain("Do not run `select-deep-review-input`");
  expect(skill).toContain("Read the fixed precomputed priority packet exactly once");
  expect(contract).toContain("discovered -> evidence_built -> challenged");
  expect(contract).toContain("static_trace");
  expect(agent).toContain('display_name: "Hunt Security Scan"');

  for (const path of [
    "scripts/hunt_workflow.py",
    "skills/hunt-security-scan/SKILL.md",
    "skills/hunt-security-scan/agents/openai.yaml",
    "skills/hunt-security-scan/references/hunt-contract.md",
  ]) {
    expect(pluginFiles.shippedExact).toContain(path);
  }
});

test("ships the bounded host-managed Hunt phase skill", () => {
  const skillPath = join(
    pluginRoot,
    "skills",
    "hunt-security-scan-managed",
    "SKILL.md",
  );
  const skill = readFileSync(skillPath, "utf8");
  const standaloneSkill = readFileSync(
    join(pluginRoot, "skills", "hunt-security-scan", "SKILL.md"),
    "utf8",
  );
  const pluginFiles = JSON.parse(
    readFileSync(join(import.meta.dir, "..", "plugin-files.json"), "utf8"),
  ) as { shippedExact: string[] };

  for (const requirement of [
    "The host owns artifact preparation",
    "return at most 12 candidates",
    "terminate every supplied candidate",
    "Do not run the standalone Hunt workflow helpers",
    "Do not generate exploits",
  ]) {
    expect(skill).toContain(requirement);
  }
  for (const standaloneStep of [
    "make-repo-rank-input",
    "make-frontier",
    "close-frontier",
    "prepare-validation",
    "validate-decisions",
    "finalize",
  ]) {
    expect(skill).not.toContain(standaloneStep);
  }
  expect(pluginFiles.shippedExact).toContain(
    "skills/hunt-security-scan-managed/SKILL.md",
  );
  expect(skill).not.toContain("hunt-contract.md");
  expect(Buffer.byteLength(skill)).toBeLessThan(
    Buffer.byteLength(standaloneSkill),
  );
});
