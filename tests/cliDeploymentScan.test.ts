import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

test("CLI scans pip install commands in Dockerfiles, shell scripts, and CI YAML", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-cli-deployment-scan-"));
  await Promise.all([
    fs.writeFile(path.join(directory, "Dockerfile"), "RUN pip install torch-vision-utils\n", "utf8"),
    fs.writeFile(path.join(directory, "bootstrap.sh"), "python -m pip install django-secure-auth\n", "utf8"),
    fs.writeFile(path.join(directory, "workflow.yml"), "- run: pip install fastapi-limiter-middleware\n", "utf8")
  ]);

  const { stdout } = await execFileAsync(process.execPath, [
    path.resolve(process.cwd(), "out", "src", "cli.js"),
    "scan",
    directory,
    "--format",
    "json",
    "--package-verification",
    "seed",
    "--fail-on",
    "none",
    "--no-l2",
    "--no-store-findings",
    "--no-config"
  ]);
  const report = JSON.parse(stdout) as { findings: Array<{ file: string; detection_rule: string }> };

  assert.deepEqual(
    report.findings.map((finding) => path.basename(finding.file)).sort(),
    ["Dockerfile", "bootstrap.sh", "workflow.yml"]
  );
  assert.equal(report.findings.every((finding) => finding.detection_rule === "hallucinated_package_pypi"), true);
});
