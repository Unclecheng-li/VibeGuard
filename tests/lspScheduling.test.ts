import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import fs from "node:fs/promises";
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

interface WorkDoneProgressValue {
  kind: "begin" | "report" | "end";
  title?: string;
  percentage?: number;
  message?: string;
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
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false
      }
    }
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

test("LSP defaults to deferred remote verification for unknown package imports", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-remote-package-"));
  const fetchHook = await writeMockMissingPackageFetchHook(temporaryHome);
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome,
      NODE_OPTIONS: `--require=${fetchHook}`
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: null,
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        enableL2: false
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "remote-package.ts")).toString();
  const startedAt = Date.now();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import missing from "vibeguard-missing-package";'
    }
  });

  const local = await client.nextDiagnostic(uri);
  assert.deepEqual(local.diagnostics, []);

  const remote = await client.nextDiagnostic(uri);
  assert.ok(Date.now() - startedAt >= 500);
  assert.equal(remote.diagnostics.some((item) => item.code === "hallucinated_package_npm"), true);
});

test("LSP critical alerts offer verified package replacements and scoped ignores", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-critical-alert-"));
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
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        packageVerification: "seed",
        enableL2: false
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "critical-alert.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import AutoSizer from "react-virtualized-auto-sizer";'
    }
  });

  const initial = await client.nextDiagnostic(uri);
  assert.equal(initial.diagnostics.some((item) => item.code === "hallucinated_package_npm"), true);

  const alert = await client.nextCriticalAlert();
  assert.match(alert.params.message ?? "", /does not exist in npm/);
  assert.match(alert.params.message ?? "", /slopsquatting risk/i);
  const actionTitles = (alert.params.actions ?? []).map((action) => action.title);
  assert.deepEqual(actionTitles.slice(0, 2), [
    "Apply fix: Replace with react-virtualized",
    "Apply fix: Replace with react-window"
  ]);
  assert.deepEqual(actionTitles.slice(-4), [
    "Ignore this VibeGuard finding",
    "Ignore this VibeGuard rule in this file",
    "Ignore this VibeGuard rule globally",
    "Ignore package react-virtualized-auto-sizer"
  ]);

  client.respond(alert.id, { title: "Ignore this VibeGuard rule in this file" });
  const afterIgnore = await client.nextDiagnostic(uri);
  assert.deepEqual(afterIgnore.diagnostics, []);
  const savedRules = await fs.readFile(path.join(temporaryHome, ".vibeguard", "ignore-rules.yml"), "utf8");
  assert.match(savedRules, /rule: "hallucinated_package_npm"/);
  assert.match(savedRules, /path: ".*critical-alert\.ts"/);
});

test("LSP critical alerts apply the selected verified package replacement", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-critical-replacement-"));
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
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        packageVerification: "seed",
        enableL2: false
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "critical-replacement.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import AutoSizer from "react-virtualized-auto-sizer";'
    }
  });

  await client.nextDiagnostic(uri);
  const alert = await client.nextCriticalAlert();
  client.respond(alert.id, { title: "Apply fix: Replace with react-window" });

  const edit = await client.nextWorkspaceEdit();
  assert.equal(edit.params.edit.changes?.[uri]?.[0]?.newText, "react-window");
  client.respond(edit.id, { applied: true });
});

test("LSP critical alerts open the shared ignore rules file when the client supports showDocument", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-manage-ignores-"));
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
    capabilities: {
      window: {
        showDocument: {
          support: true
        }
      }
    },
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        packageVerification: "seed",
        enableL2: false
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "manage-ignores.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import AutoSizer from "react-virtualized-auto-sizer";'
    }
  });

  await client.nextDiagnostic(uri);
  const alert = await client.nextCriticalAlert();
  assert.equal((alert.params.actions ?? []).some((action) => action.title === "Manage Ignore Rules"), true);

  client.respond(alert.id, { title: "Manage Ignore Rules" });
  const showDocument = await client.nextShowDocument();
  assert.equal(
    showDocument.params.uri,
    pathToFileURL(path.join(temporaryHome, ".vibeguard", "ignore-rules.yml")).toString()
  );
  assert.equal(showDocument.params.takeFocus, true);
  client.respond(showDocument.id, { success: true });
  assert.equal(await fs.readFile(path.join(temporaryHome, ".vibeguard", "ignore-rules.yml"), "utf8"), "ignore:\n");
});

test("LSP ignore code actions persist a local rule and clear the matching diagnostic", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-ignore-"));
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

  const initialized = (await client.request("initialize", {
    processId: null,
    rootUri: null,
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        packageVerification: "seed",
        enableL2: false
      }
    }
  })) as { capabilities?: { executeCommandProvider?: { commands?: string[] } } };
  assert.equal(initialized.capabilities?.executeCommandProvider?.commands?.includes("vibeguard.ignoreFinding"), true);
  assert.equal(initialized.capabilities?.executeCommandProvider?.commands?.includes("vibeguard.applyFix"), true);
  assert.equal(initialized.capabilities?.executeCommandProvider?.commands?.includes("vibeguard.applyL3Fix"), true);
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "ignored-package.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import AutoSizer from "react-virtualized-auto-sizer";'
    }
  });
  const initial = await client.nextDiagnostic(uri);
  assert.equal(initial.diagnostics.some((item) => item.code === "hallucinated_package_npm"), true);

  const range = {
    start: { line: 0, character: 0 },
    end: { line: 0, character: 52 }
  };
  const actions = (await client.request("textDocument/codeAction", {
    textDocument: { uri },
    range,
    context: {
      diagnostics: [
        {
          range,
          source: "VibeGuard",
          code: "hallucinated_package_npm",
          message: "Package is missing"
        }
      ]
    }
  })) as Array<{ title?: string; command?: { command?: string; arguments?: unknown[] } }>;
  const fix = actions.find((action) => action.title === "Apply VibeGuard fix: Replace with react-virtualized");
  const ignore = actions.find((action) => action.title === "Ignore this VibeGuard finding");
  assert.equal(fix?.command?.command, "vibeguard.applyFix");
  assert.equal(ignore?.command?.command, "vibeguard.ignoreFinding");
  assert.ok(ignore?.command?.arguments);

  const fixExecution = client.startRequest("workspace/executeCommand", {
    command: fix?.command?.command,
    arguments: fix?.command?.arguments
  });
  const edit = await client.nextWorkspaceEdit();
  assert.equal(edit.params.edit.changes?.[uri]?.[0]?.newText, "react-virtualized");
  client.respond(edit.id, { applied: true });
  await client.waitForResponse(fixExecution);

  await client.request("workspace/executeCommand", {
    command: ignore?.command?.command,
    arguments: ignore?.command?.arguments
  });

  const afterIgnore = await client.nextDiagnostic(uri);
  assert.deepEqual(afterIgnore.diagnostics, []);
  const savedRules = await fs.readFile(path.join(temporaryHome, ".vibeguard", "ignore-rules.yml"), "utf8");
  assert.match(savedRules, /rule: "hallucinated_package_npm"/);
  assert.match(savedRules, /line: 1/);
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
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false
      }
    }
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

test("LSP requires confirmation before applying an L3 generated replacement", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-l3-replacement-"));
  const fetchHook = await writeMockL3ReplacementFetchHook(temporaryHome);
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome,
      NODE_OPTIONS: `--require=${fetchHook}`
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: null,
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: false,
        packageVerification: "off",
        enableL2: false,
        enableL3: true,
        llmProvider: "local",
        llmBaseUrl: "http://localhost:11434"
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "l3-replacement.ts")).toString();
  const range = {
    start: { line: 0, character: 0 },
    end: { line: 0, character: 30 }
  };
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: "const value = unsafeInput;"
    }
  });
  await client.nextDiagnostic(uri);
  client.notify("textDocument/didSave", { textDocument: { uri } });
  const l3 = await client.nextDiagnostic(uri);
  assert.equal(l3.diagnostics.some((item) => item.code === "l3_llm_reviewed_replacement"), true);

  const actions = (await client.request("textDocument/codeAction", {
    textDocument: { uri },
    range,
    context: {
      diagnostics: [
        {
          range,
          source: "VibeGuard",
          code: "l3_llm_reviewed_replacement",
          message: "Generated replacement"
        }
      ]
    }
  })) as Array<{ title?: string; edit?: unknown; command?: { command?: string; arguments?: unknown[] } }>;
  const fix = actions.find((action) => action.title === "Apply VibeGuard fix: Review LLM-generated replacement");
  assert.equal(fix?.edit, undefined);
  assert.equal(fix?.command?.command, "vibeguard.applyL3Fix");

  const executionId = client.startRequest("workspace/executeCommand", {
    command: fix?.command?.command,
    arguments: fix?.command?.arguments
  });
  const review = await client.nextCriticalAlert();
  assert.match(review.params.message ?? "", /received this replacement from an LLM/);
  client.respond(review.id, { title: "Apply replacement" });

  const edit = await client.nextWorkspaceEdit();
  assert.equal(edit.params.edit.changes?.[uri]?.[0]?.newText, "const value = sanitize(unsafeInput);");
  client.respond(edit.id, { applied: true });
  await client.waitForResponse(executionId);
});

test("LSP refreshes open package diagnostics after its background cache sync", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-package-sync-"));
  const fetchHook = await writeMockNpmSyncFetchHook(temporaryHome);
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome,
      NODE_OPTIONS: `--require=${fetchHook}`
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: pathToFileURL(temporaryHome).toString(),
    capabilities: {},
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: true,
        enableL2: false,
        packageCacheLanguages: ["npm"],
        packageCacheBackgroundFullSync: false
      }
    }
  });
  client.notify("initialized", {});

  const uri = pathToFileURL(path.join(temporaryHome, "cache-refresh.ts")).toString();
  client.notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: "typescript",
      version: 1,
      text: 'import AutoSizer from "react-virtualized-auto-sizer";'
    }
  });

  const beforeSync = await client.nextDiagnostic(uri);
  assert.equal(beforeSync.diagnostics.some((item) => item.code === "hallucinated_package_npm"), true);

  const afterSync = await client.nextDiagnostic(uri);
  assert.equal(afterSync.diagnostics.some((item) => item.code === "hallucinated_package_npm"), false);
  assert.equal(client.receivedMethod("window/workDoneProgress/create"), false);
});

test("LSP reports package-cache progress when the client supports standard work progress", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-package-progress-"));
  const fetchHook = await writeMockNpmSyncFetchHook(temporaryHome);
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome,
      NODE_OPTIONS: `--require=${fetchHook}`
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: pathToFileURL(temporaryHome).toString(),
    capabilities: {
      window: {
        workDoneProgress: true
      }
    },
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: true,
        packageCacheLanguages: ["npm"],
        packageCacheBackgroundFullSync: false
      }
    }
  });
  client.notify("initialized", {});

  const begin = await client.nextWorkDoneProgress("begin");
  assert.equal(begin.value.title, "VibeGuard package cache");
  assert.equal(begin.value.percentage, 0);

  const tierStarted = await client.nextWorkDoneProgress("report");
  assert.match(tierStarted.value.message ?? "", /Tier 1 quick index started/);

  const starting = await client.nextWorkDoneProgress("report");
  assert.equal(starting.value.percentage, 0);
  assert.match(starting.value.message ?? "", /Tier 1 quick index: syncing npm package names/);

  const end = await client.nextWorkDoneProgress("end");
  assert.equal(end.value.kind, "end");
});

test("LSP schedules the full package index after the quick tier", { timeout: 10000 }, async (context) => {
  const temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-lsp-package-tier-two-"));
  const fetchHook = await writeMockNpmSyncFetchHook(temporaryHome);
  const server = spawn(process.execPath, [path.resolve("out/src/lspServer.js"), "--stdio"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HOME: temporaryHome,
      USERPROFILE: temporaryHome,
      NODE_OPTIONS: `--require=${fetchHook}`
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const client = new LspTestClient(server);
  context.after(async () => client.stop());

  await client.request("initialize", {
    processId: null,
    rootUri: pathToFileURL(temporaryHome).toString(),
    capabilities: {
      window: {
        workDoneProgress: true
      }
    },
    initializationOptions: {
      vibeguard: {
        autoSyncPackageCache: true,
        packageCacheLanguages: ["npm"],
        packageCacheBackgroundFullSync: true
      }
    }
  });
  client.notify("initialized", {});

  await client.nextWorkDoneProgress("begin");
  const fullTier = await client.nextWorkDoneProgressReportMatching(/Tier 2 full index started/);
  assert.equal(fullTier.value.percentage, 50);
  await client.nextWorkDoneProgress("end");
});

async function writeMockNpmSyncFetchHook(temporaryHome: string): Promise<string> {
  const fetchHook = path.join(temporaryHome, "mock-package-sync-fetch.cjs");
  await fs.writeFile(
    fetchHook,
    `globalThis.fetch = async (input) => {
  await new Promise((resolve) => setTimeout(resolve, 150));
  const url = String(input);
  if (url.includes("/_all_docs")) {
    return new Response(JSON.stringify({ total_rows: 1, rows: [{ id: "react-virtualized-auto-sizer" }] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }
  return new Response(JSON.stringify({ update_seq: "1-g" }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
};
`,
    "utf8"
  );
  return fetchHook;
}

async function writeMockMissingPackageFetchHook(temporaryHome: string): Promise<string> {
  const fetchHook = path.join(temporaryHome, "mock-missing-package-fetch.cjs");
  await fs.writeFile(
    fetchHook,
    `globalThis.fetch = async () => new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
`,
    "utf8"
  );
  return fetchHook;
}

async function writeMockL3ReplacementFetchHook(temporaryHome: string): Promise<string> {
  const fetchHook = path.join(temporaryHome, "mock-l3-replacement-fetch.cjs");
  const response = JSON.stringify({
    message: {
      content: JSON.stringify({
        findings: [
          {
            ruleId: "l3_llm_reviewed_replacement",
            severity: "high",
            message: "Input must be sanitized before use.",
            evidence: "const value = unsafeInput;",
            suggestion: "Sanitize the input before using it.",
            replacement: "const value = sanitize(unsafeInput);",
            line: 1,
            column: 1
          }
        ]
      })
    }
  });
  await fs.writeFile(
    fetchHook,
    `globalThis.fetch = async () => new Response(${JSON.stringify(response)}, { status: 200, headers: { "content-type": "application/json" } });\n`,
    "utf8"
  );
  return fetchHook;
}

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
    return this.waitForResponse(this.startRequest(method, params));
  }

  startRequest(method: string, params: Record<string, unknown>): number {
    const id = this.nextId;
    this.nextId += 1;
    this.send({ jsonrpc: "2.0", id, method, params });
    return id;
  }

  async waitForResponse(id: number): Promise<unknown> {
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

  async nextWorkDoneProgress(kind: "begin" | "report" | "end"): Promise<{ value: WorkDoneProgressValue }> {
    const message = await this.waitFor((item) => {
      const value = item.params?.value;
      return (
        item.method === "$/progress" &&
        Boolean(value) &&
        typeof value === "object" &&
        (value as { kind?: unknown }).kind === kind
      );
    });
    return message.params as { value: WorkDoneProgressValue };
  }

  async nextWorkDoneProgressReportMatching(expression: RegExp): Promise<{ value: WorkDoneProgressValue }> {
    const message = await this.waitFor((item) => {
      const value = item.params?.value;
      return (
        item.method === "$/progress" &&
        Boolean(value) &&
        typeof value === "object" &&
        (value as { kind?: unknown }).kind === "report" &&
        expression.test(String((value as { message?: unknown }).message ?? ""))
      );
    });
    return message.params as { value: WorkDoneProgressValue };
  }

  async nextCriticalAlert(): Promise<{ id: number; params: { message?: string; actions?: Array<{ title: string }> } }> {
    const message = await this.waitFor((item) => item.method === "window/showMessageRequest" && typeof item.id === "number");
    return {
      id: message.id as number,
      params: message.params as { message?: string; actions?: Array<{ title: string }> }
    };
  }

  async nextWorkspaceEdit(): Promise<{
    id: number;
    params: { edit: { changes?: Record<string, Array<{ newText?: string }>> } };
  }> {
    const message = await this.waitFor((item) => item.method === "workspace/applyEdit" && typeof item.id === "number");
    return {
      id: message.id as number,
      params: message.params as { edit: { changes?: Record<string, Array<{ newText?: string }>> } }
    };
  }

  async nextShowDocument(): Promise<{ id: number; params: { uri: string; takeFocus?: boolean } }> {
    const message = await this.waitFor((item) => item.method === "window/showDocument" && typeof item.id === "number");
    return {
      id: message.id as number,
      params: message.params as { uri: string; takeFocus?: boolean }
    };
  }

  respond(id: number, result: unknown): void {
    this.send({ jsonrpc: "2.0", id, result });
  }

  receivedMethod(method: string): boolean {
    return this.messages.some((message) => message.method === method);
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
      const message = JSON.parse(body) as JsonRpcMessage;
      this.messages.push(message);
      if (message.method === "window/workDoneProgress/create" && message.id !== undefined) {
        this.send({ jsonrpc: "2.0", id: message.id, result: null });
      }
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
