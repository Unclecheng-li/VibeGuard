import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

interface JsonRpcMessage {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
}

test("LSP publishes L1 immediately and defers L2 diagnostics after document edits", { timeout: 10000 }, async (context) => {
  const temporaryHome = await import("node:fs/promises").then((fs) => fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-")));
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: null,
    capabilities: {}
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "vibeguard-lsp-debounce.java")).toString();
  const startedAt = Date.now();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "java",
      version: 1,
      text: "statement.execute(request.getParameter(\"sql\"));"
    }
  });

  const immediate = await client.nextDiagnostic(uri);
  assert.deepEqual(immediate.diagnostics, []);

  const deferred = await client.nextDiagnostic(uri);
  assert.ok(Date.now() - startedAt >= 400);
  assert.equal(
    deferred.diagnostics.some((item) => item.code === "sast_sql_user_input_execute"),
    true,
    JSON.stringify(deferred.diagnostics)
  );
});

test("LSP runs local L3 immediately when a document is saved", { timeout: 10000 }, async (context) => {
  const temporaryHome = await import("node:fs/promises").then((fs) => fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-")));
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: null,
    capabilities: {}
  });
  client.notify("workspace/didChangeConfiguration", {
    settings: {
      vibeguard: {
        enableL3: true
      }
    }
  });

  const uri = pathToFileURL(path.join(temporaryHome, "lsp-save.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "java",
      version: 1,
      text: `@RestController
@RequestMapping("/api/admin")
public class AdminController {
  @PostMapping("/users")
  public ResponseEntity<User> createUser(@RequestBody User input) {
    return ResponseEntity.ok(input);
  }
}`
    }
  });
  await client.nextDiagnostic(uri);

  const savedAt = Date.now();
  client.notify("textDocument/didSave", {
    textDocument: { uri }
  });
  const saved = await client.nextDiagnostic(uri);

  assert.ok(Date.now() - savedAt < 1000);
  assert.equal(saved.diagnostics.some((item) => item.code === "l3_missing_authentication"), true);
});

class LspTestClient {
  private buffer = "";
  private readonly messages: JsonRpcMessage[] = [];
  private readonly stderr: string[] = [];
  private nextId = 1;
  private cursor = 0;

  constructor(private readonly server: ChildProcessWithoutNullStreams) {
    server.stdout.setEncoding("utf8");
    server.stdout.on("data", (chunk: string) => this.consume(chunk));
    server.stderr.setEncoding("utf8");
    server.stderr.on("data", (chunk: string) => this.stderr.push(chunk));
  }

  async request(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = this.nextId;
    this.nextId += 1;
    this.send({ jsonrpc: "2.0", id, method, params });
    const message = await this.waitFor((item) => item.id === id);
    return message.result;
  }

  notify(method: string, params: Record<string, unknown>): void {
    this.send({ jsonrpc: "2.0", method, params });
  }

  async nextDiagnostic(uri: string): Promise<{ diagnostics: Array<{ code?: unknown }> }> {
    const message = await this.waitFor(
      (item) => item.method === "textDocument/publishDiagnostics" && item.params?.uri === uri
    );
    return message.params as { diagnostics: Array<{ code?: unknown }> };
  }

  async stop(): Promise<void> {
    if (this.server.exitCode !== null) {
      return;
    }
    await new Promise<void>((resolve) => {
      const fallback = setTimeout(resolve, 1000);
      fallback.unref();
      this.server.once("exit", () => {
        clearTimeout(fallback);
        resolve();
      });
      this.server.kill();
    });
  }

  private send(message: Record<string, unknown>): void {
    const body = JSON.stringify(message);
    this.server.stdin.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  }

  private consume(chunk: string): void {
    this.buffer += chunk;
    while (true) {
      const separator = this.buffer.indexOf("\r\n\r\n");
      if (separator < 0) {
        return;
      }
      const header = this.buffer.slice(0, separator);
      const length = Number(header.match(/Content-Length:\s*(\d+)/i)?.[1]);
      const start = separator + 4;
      if (!Number.isFinite(length) || this.buffer.length < start + length) {
        return;
      }
      const body = this.buffer.slice(start, start + length);
      this.buffer = this.buffer.slice(start + length);
      this.messages.push(JSON.parse(body) as JsonRpcMessage);
    }
  }

  private async waitFor(predicate: (message: JsonRpcMessage) => boolean): Promise<JsonRpcMessage> {
    const timeoutAt = Date.now() + 8000;
    while (Date.now() < timeoutAt) {
      while (this.cursor < this.messages.length) {
        const message = this.messages[this.cursor];
        this.cursor += 1;
        if (predicate(message)) {
          return message;
        }
      }
      if (this.server.exitCode !== null) {
        assert.fail(`VibeGuard LSP exited unexpectedly: ${this.stderr.join("")}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail(`Timed out waiting for LSP message. stderr: ${this.stderr.join("")}`);
  }
}
