// Verifies the experimental Hunt workflow helper.

import {
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
  writeFileSync(
    path,
    rows.map((row) => JSON.stringify(row)).join("\n") + "\n",
  );
}

function readJsonl<T>(path: string): T[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as T);
}

function runHunt(...args: string[]): ReturnType<typeof Bun.spawnSync> {
  return Bun.spawnSync([pythonExecutable(), "-B", huntScript, ...args], {
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
