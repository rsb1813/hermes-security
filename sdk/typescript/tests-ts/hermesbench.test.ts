// Verifies HermesBench through the repository's standard Bun suite.

import { join } from "node:path";
import { expect, test } from "bun:test";

const repositoryRoot = join(import.meta.dir, "..", "..", "..");

function pythonExecutable(): string | null {
  return (
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

test("runs the HermesBench Python suite and CLI", () => {
  const python = pythonExecutable();
  expect(python).not.toBeNull();

  const tests = Bun.spawnSync(
    [
      python!,
      "-m",
      "unittest",
      "discover",
      "-s",
      "benchmarks/hermesbench/tests",
      "-v",
    ],
    { cwd: repositoryRoot, stdout: "pipe", stderr: "pipe" },
  );
  expect(tests.exitCode, tests.stderr.toString()).toBe(0);

  const help = Bun.spawnSync(
    [python!, "-m", "benchmarks.hermesbench", "--help"],
    {
      cwd: repositoryRoot,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  expect(help.exitCode, help.stderr.toString()).toBe(0);
  expect(help.stdout.toString()).toContain("audit-bundle");
}, 60_000);
