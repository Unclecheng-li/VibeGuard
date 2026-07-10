import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "../..");

test("Docker image builds the bundled CLI and keeps git available for AI scans", async () => {
  const [dockerfile, dockerignore] = await Promise.all([
    fs.readFile(path.join(repositoryRoot, "Dockerfile"), "utf8"),
    fs.readFile(path.join(repositoryRoot, ".dockerignore"), "utf8")
  ]);

  assert.match(dockerfile, /^FROM node:24-bookworm-slim AS build/m);
  assert.match(dockerfile, /RUN npm ci/);
  assert.match(dockerfile, /RUN npm run build/);
  assert.match(dockerfile, /apt-get install --yes --no-install-recommends git/);
  assert.match(dockerfile, /COPY --from=build \/opt\/vibeguard\/dist \/opt\/vibeguard\/dist/);
  assert.match(dockerfile, /ENTRYPOINT \["node", "\/opt\/vibeguard\/dist\/cli\.js"\]/);
  assert.match(dockerignore, /^node_modules\/$/m);
  assert.match(dockerignore, /^dist\/$/m);
});
