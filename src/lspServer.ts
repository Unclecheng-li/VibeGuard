#!/usr/bin/env node
import { fileURLToPath } from "url";
import {
  CodeActionKind,
  createConnection,
  DiagnosticSeverity,
  ProposedFeatures,
  TextDocumentSyncKind,
  TextDocuments,
  type CodeAction,
  type CodeActionParams,
  type Diagnostic,
  type InitializeParams,
  type InitializeResult
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { loadCustomRules } from "./customRules";
import { defaultIgnoreRulesPath, loadIgnoreRules } from "./ignore";
import { getLlmApiKeyFromEnv, LlmSemanticAnalyzer, type LlmProvider } from "./l3/llm";
import { createCodeActionsForFindings } from "./lspActions";
import { PackageVerifier } from "./package/packageVerifier";
import { createPackageStorage } from "./package/storage";
import { scanSourceFile } from "./scanner";
import type { Finding, Severity } from "./types";

interface LspSettings {
  enabled: boolean;
  packageVerification: "off" | "seed" | "remote";
  enableL2: boolean;
  enableL3: boolean;
  dedupWithExistingTools: boolean;
  customRules?: string[];
  ignoredFindings?: string[];
  ignoreRulesPath?: string;
  llmProvider?: LlmProvider;
  llmModel?: string;
  llmBaseUrl?: string;
  llmApiKeyEnv?: string;
}

const defaultSettings: LspSettings = {
  enabled: true,
  packageVerification: "seed",
  enableL2: true,
  enableL3: false,
  llmProvider: "deepseek",
  dedupWithExistingTools: true
};

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);
const storage = createPackageStorage({ kind: "auto" });
const verifier = new PackageVerifier({
  cache: storage.cache,
  packageIndex: storage.packageIndex
});
let settings = defaultSettings;
const findingsByUri = new Map<string, Finding[]>();

connection.onInitialize((_params: InitializeParams): InitializeResult => ({
  capabilities: {
    textDocumentSync: TextDocumentSyncKind.Incremental,
    codeActionProvider: {
      codeActionKinds: [CodeActionKind.QuickFix]
    }
  },
  serverInfo: {
    name: "VibeGuard LSP",
    version: "0.1.0"
  }
}));

connection.onDidChangeConfiguration((change) => {
  const incoming = (change.settings?.vibeguard ?? {}) as Partial<LspSettings>;
  settings = {
    ...defaultSettings,
    ...incoming
  };
  for (const document of documents.all()) {
    void validateDocument(document);
  }
});

documents.onDidOpen((event) => {
  void validateDocument(event.document);
});

documents.onDidChangeContent((event) => {
  void validateDocument(event.document);
});

documents.onDidClose((event) => {
  findingsByUri.delete(event.document.uri);
  connection.sendDiagnostics({
    uri: event.document.uri,
    diagnostics: []
  });
});

connection.onCodeAction((params: CodeActionParams): CodeAction[] => {
  const findings = findingsByUri.get(params.textDocument.uri) ?? [];
  return createCodeActionsForFindings(params.textDocument.uri, findings, params.context.diagnostics);
});

async function validateDocument(document: TextDocument): Promise<void> {
  if (!settings.enabled) {
    findingsByUri.set(document.uri, []);
    connection.sendDiagnostics({
      uri: document.uri,
      diagnostics: []
    });
    return;
  }

  const result = await scanSourceFile(
    {
      filePath: filePathFromUri(document.uri),
      text: document.getText(),
      languageId: document.languageId
    },
    {
      packageVerification: settings.packageVerification,
      includeSast: settings.enableL2,
      includeL3: settings.enableL3,
      l3Analyzer: createLspL3Analyzer(),
      packageVerifier: verifier,
      customRules: await loadConfiguredCustomRules(),
      ignoreRules: await loadIgnoreRules(settings.ignoreRulesPath?.trim() || defaultIgnoreRulesPath()),
      ignoredFindingIds: settings.ignoredFindings,
      dedupWithExistingTools: settings.dedupWithExistingTools
    }
  );
  if (result.performance.budgetExceeded) {
    const warning = result.performance.budgets.find((check) => check.exceeded);
    if (warning) {
      connection.console.warn(
        `VibeGuard performance budget warning: ${warning.layer} ${filePathFromUri(document.uri)} ${formatMs(
          warning.elapsedMs
        )} > ${formatMs(warning.budgetMs)}`
      );
    }
  }

  findingsByUri.set(document.uri, result.findings);
  connection.sendDiagnostics({
    uri: document.uri,
    diagnostics: result.findings.filter((finding) => !finding.dismissed).map(toDiagnostic)
  });
}

function formatMs(value: number): string {
  if (value < 1000) {
    return `${value.toFixed(value < 10 ? 1 : 0)}ms`;
  }
  return `${(value / 1000).toFixed(2)}s`;
}

async function loadConfiguredCustomRules() {
  try {
    return await loadCustomRules(settings.customRules ?? []);
  } catch (error) {
    connection.console.warn(`VibeGuard custom rules error: ${error instanceof Error ? error.message : String(error)}`);
    return [];
  }
}

function createLspL3Analyzer(): LlmSemanticAnalyzer | undefined {
  if (!settings.enableL3) {
    return undefined;
  }
  const provider = settings.llmProvider ?? "deepseek";
  const apiKey = getLlmApiKeyFromEnv(provider, settings.llmApiKeyEnv);
  if (provider !== "local" && !apiKey) {
    return undefined;
  }
  return new LlmSemanticAnalyzer({
    provider,
    apiKey,
    model: settings.llmModel,
    // LSP settings may come from a workspace; keep a Pro credential on its configured service origin.
    baseUrl: provider === "vibeguard" ? undefined : settings.llmBaseUrl
  });
}

function toDiagnostic(finding: Finding): Diagnostic {
  return {
    range: {
      start: {
        line: Math.max(0, finding.line - 1),
        character: Math.max(0, finding.column - 1)
      },
      end: {
        line: Math.max(0, (finding.endLine ?? finding.line) - 1),
        character: Math.max(1, (finding.endColumn ?? finding.column + finding.evidence.length) - 1)
      }
    },
    severity: toLspSeverity(finding.severity),
    code: finding.detection_rule,
    source: "VibeGuard",
    message: finding.suggestion ? `${finding.message} ${finding.suggestion}` : finding.message
  };
}

function toLspSeverity(severity: Severity): DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return DiagnosticSeverity.Error;
    case "medium":
      return DiagnosticSeverity.Warning;
    case "low":
      return DiagnosticSeverity.Information;
    case "info":
    default:
      return DiagnosticSeverity.Hint;
  }
}

function filePathFromUri(uri: string): string {
  if (uri.startsWith("file://")) {
    return fileURLToPath(uri);
  }
  return uri;
}

documents.listen(connection);
connection.listen();
