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

async function runPythonSuite(python: string): Promise<void> {
  const testsRoot = join(repositoryRoot, "benchmarks", "hermesbench", "tests");
  const testFiles = [
    ...new Bun.Glob("test_*.py").scanSync({ cwd: testsRoot, onlyFiles: true }),
  ].sort();
  expect(testFiles.length).toBeGreaterThan(0);

  const shards = Array.from(
    { length: Math.min(4, testFiles.length) },
    () => [] as string[],
  );
  for (const [index, file] of testFiles.entries()) {
    const moduleName = file
      .replace(/\.py$/, "")
      .replaceAll("/", ".")
      .replaceAll("\\", ".");
    shards[index % shards.length]!.push(
      `benchmarks.hermesbench.tests.${moduleName}`,
    );
  }

  const results = await Promise.all(
    shards.map(async (modules, index) => {
      const child = Bun.spawn(
        [python, "-m", "unittest", ...modules, "-v"],
        { cwd: repositoryRoot, stdout: "pipe", stderr: "pipe" },
      );
      const [exitCode, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      return { index, exitCode, stdout, stderr };
    }),
  );
  for (const result of results) {
    expect(
      result.exitCode,
      `HermesBench shard ${result.index} failed.\n${result.stderr}\n${result.stdout}`,
    ).toBe(0);
  }
}

test("runs the HermesBench Python suite and CLI", async () => {
  const python = pythonExecutable();
  expect(python).not.toBeNull();
  await runPythonSuite(python!);

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
}, 90_000);
