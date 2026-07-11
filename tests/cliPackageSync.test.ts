import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

test("CLI npm package sync records a change snapshot for later incremental refreshes", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-cli-package-sync-"));
  const indexPath = path.join(directory, "package-index.json");
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ update_seq: 42 }));
      return;
    }
    if (url.pathname === "/_all_docs") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ total_rows: 2, rows: [{ id: "react" }, { id: "vite" }] }));
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");

  try {
    const { stdout } = await execFileAsync(process.execPath, [
      path.resolve(process.cwd(), "out", "src", "cli.js"),
      "packages",
      "sync",
      "npm",
      "--url",
      `http://127.0.0.1:${address.port}/_all_docs`,
      "--limit",
      "2",
      "--storage",
      "json",
      "--index",
      indexPath,
      "--json"
    ]);
    const payload = JSON.parse(stdout) as { syncMetadata?: Record<string, unknown> };
    assert.deepEqual(payload.syncMetadata, {
      sourceUrl: `http://127.0.0.1:${address.port}/_all_docs?limit=2`,
      changeSourceUrl: `http://127.0.0.1:${address.port}/_changes`,
      changeSequence: "42"
    });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});
