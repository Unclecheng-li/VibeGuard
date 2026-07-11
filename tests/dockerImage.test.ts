import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "../..");

test("Docker image builds the bundled CLI and keeps git available for AI scans", async () => {
  const [dockerfile, dockerignore, entrypoint] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, "Dockerfile"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".dockerignore"), "utf8"),
    fs.readFile(path.join(repositoryRoot, "scripts", "docker-entrypoint.sh"), "utf8")
  ]);

  assert.match(dockerfile, /^FROM node:22-bookworm-slim AS build/m);
  assert.match(dockerfile, /RUN npm ci/);
  assert.match(dockerfile, /RUN npm run build/);
  assert.match(dockerfile, /apt-get install --yes --no-install-recommends git/);
  assert.match(dockerfile, /COPY --from=build \/opt\/vibeguard\/dist \/opt\/vibeguard\/dist/);
  assert.match(dockerfile, /COPY scripts\/docker-entrypoint\.sh \/usr\/local\/bin\/vibeguard-entrypoint/);
  assert.match(dockerfile, /RUN chmod 755 \/usr\/local\/bin\/vibeguard-entrypoint/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/local\/bin\/vibeguard-entrypoint"\]/);
  assert.match(entrypoint, /\[ "\$\{1:-\}" = "findings" \] && \[ "\$\{2:-\}" = "serve" \]/);
  assert.match(entrypoint, /VIBEGUARD_TELEMETRY_COLLECTION/);
  assert.match(entrypoint, /--telemetry-collection/);
  assert.match(entrypoint, /VIBEGUARD_TELEMETRY_MAX_EVENTS_PER_MINUTE/);
  assert.match(dockerignore, /^node_modules\/$/m);
  assert.match(dockerignore, /^dist\/$/m);
});

test("development and release workflows pin Node.js 22 LTS", async () => {
  const [nvmrc, ci, release, packageRaw] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, ".nvmrc"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "release.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, "package.json"), "utf8")
  ]);
  const packageJson = JSON.parse(packageRaw) as { scripts?: Record<string, string> };

  assert.equal(nvmrc.trim(), "22");
  assert.doesNotMatch(ci, /node-version:\s*24/);
  assert.match(ci, /node-version:\s*22/);
  assert.doesNotMatch(release, /node-version:\s*24/);
  assert.match(release, /node-version:\s*22/);
  assert.match(packageJson.scripts?.test ?? "", /assert-node-lts/);
});

test("CI uses Node 24-compatible actions and leaves actionable diagnostics on failure", async () => {
  const [ci, release] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".github", "workflows", "release.yml"), "utf8")
  ]);

  for (const workflow of [ci, release]) {
    assert.doesNotMatch(workflow, /actions\/(?:checkout|setup-node|setup-java|upload-artifact)@v4/);
    assert.match(workflow, /actions\/checkout@v5/);
    assert.match(workflow, /actions\/setup-node@v5/);
  }
  assert.match(ci, /actions\/setup-java@v5/);
  assert.match(release, /actions\/setup-java@v5/);
  assert.match(ci, /chmod \+x \.\/gradlew/);
  assert.match(release, /chmod \+x \.\/gradlew/);
  assert.match(ci, /vibeguard-node-test-log/);
  assert.match(ci, /request_dashboard \/healthz/);
  assert.match(ci, /--retry-all-errors/);
  assert.match(ci, /docker logs vibeguard-dashboard/);
});
