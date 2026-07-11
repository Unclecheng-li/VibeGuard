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
import { mergeFindingsForExecutedLayers, type ExecutedLayers } from "./layers";
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
  l2DebounceMs?: number;
  l3DebounceMs?: number;
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
const l2DebounceMs = 500;
const l3DebounceMs = 2000;
const realtimeRemoteVerificationDelayMs = 600;

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);
const storage = createPackageStorage({ kind: "auto" });
const verifier = new PackageVerifier({
  cache: storage.cache,
  packageIndex: storage.packageIndex
});
let settings = defaultSettings;
const findingsByUri = new Map<string, Finding[]>();
const l2Timers = new Map<string, NodeJS.Timeout>();
const l3Timers = new Map<string, NodeJS.Timeout>();
const remotePackageTimers = new Map<string, NodeJS.Timeout>();
const documentRevisions = new Map<string, number>();

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
    scheduleImmediateValidation(document, true);
  }
});

documents.onDidOpen((event) => {
  scheduleRealtimeValidation(event.document);
});

documents.onDidChangeContent((event) => {
  scheduleRealtimeValidation(event.document);
});

documents.onDidSave((event) => {
  scheduleImmediateValidation(event.document, true);
});

documents.onDidClose((event) => {
  clearDocumentTimers(event.document.uri);
  documentRevisions.delete(event.document.uri);
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

interface LspValidationOptions {
  layers: ExecutedLayers;
  packageVerification?: LspSettings["packageVerification"];
  replaceAll?: boolean;
}

function scheduleRealtimeValidation(document: TextDocument): void {
  const revision = nextDocumentRevision(document.uri);
  clearDocumentTimers(document.uri);
  const packageVerification = settings.packageVerification === "remote" ? "seed" : settings.packageVerification;
  void validateDocument(document, revision, {
    layers: { l1: true },
    packageVerification
  });

  if (settings.enableL2) {
    scheduleLayerValidation(document, revision, "l2");
  }
  if (settings.enableL3) {
    scheduleLayerValidation(document, revision, "l3");
  }
  if (settings.packageVerification === "remote") {
    scheduleRemotePackageValidation(document, revision);
  }
}

function scheduleImmediateValidation(document: TextDocument, replaceAll: boolean): void {
  const revision = nextDocumentRevision(document.uri);
  clearDocumentTimers(document.uri);
  void validateDocument(document, revision, {
    layers: { l1: true, l2: settings.enableL2, l3: settings.enableL3 },
    replaceAll
  });
}

function scheduleLayerValidation(document: TextDocument, revision: number, layer: "l2" | "l3"): void {
  const timers = layer === "l2" ? l2Timers : l3Timers;
  const delay = layer === "l2" ? configuredL2DebounceMs() : configuredL3DebounceMs();
  const uri = document.uri;
  timers.set(
    uri,
    setTimeout(() => {
      timers.delete(uri);
      if (documentRevisions.get(uri) !== revision) {
        return;
      }
      void validateDocument(document, revision, {
        layers: layer === "l2" ? { l2: true } : { l2: settings.enableL2, l3: true }
      });
    }, delay)
  );
}

function scheduleRemotePackageValidation(document: TextDocument, revision: number): void {
  const uri = document.uri;
  remotePackageTimers.set(
    uri,
    setTimeout(() => {
      remotePackageTimers.delete(uri);
      if (documentRevisions.get(uri) !== revision) {
        return;
      }
      void validateDocument(document, revision, {
        layers: { l1: true },
        packageVerification: "remote"
      });
    }, realtimeRemoteVerificationDelayMs)
  );
}

function nextDocumentRevision(uri: string): number {
  const revision = (documentRevisions.get(uri) ?? 0) + 1;
  documentRevisions.set(uri, revision);
  return revision;
}

function clearDocumentTimers(uri: string): void {
  clearDocumentTimer(l2Timers, uri);
  clearDocumentTimer(l3Timers, uri);
  clearDocumentTimer(remotePackageTimers, uri);
}

function clearDocumentTimer(timers: Map<string, NodeJS.Timeout>, uri: string): void {
  const timer = timers.get(uri);
  if (timer) {
    clearTimeout(timer);
    timers.delete(uri);
  }
}

function configuredL2DebounceMs(): number {
  return normalizeDebounceMs(settings.l2DebounceMs, l2DebounceMs);
}

function configuredL3DebounceMs(): number {
  return normalizeDebounceMs(settings.l3DebounceMs, l3DebounceMs);
}

function normalizeDebounceMs(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(30000, Math.max(0, Math.round(value)));
}

async function validateDocument(document: TextDocument, revision: number, options: LspValidationOptions): Promise<void> {
  if (!settings.enabled) {
    findingsByUri.set(document.uri, []);
    connection.sendDiagnostics({
      uri: document.uri,
      diagnostics: []
    });
    return;
  }

  const documentVersion = document.version;
  const layers = {
    l1: Boolean(options.layers.l1),
    l2: Boolean(options.layers.l2 && settings.enableL2),
    l3: Boolean(options.layers.l3 && settings.enableL3)
  };
  const result = await scanSourceFile(
    {
      filePath: filePathFromUri(document.uri),
      text: document.getText(),
      languageId: document.languageId
    },
    {
      packageVerification: options.packageVerification ?? settings.packageVerification,
      detectionLayers: layers,
      l3Analyzer: layers.l3 ? createLspL3Analyzer() : undefined,
      packageVerifier: verifier,
      customRules: await loadConfiguredCustomRules(),
      ignoreRules: await loadIgnoreRules(settings.ignoreRulesPath?.trim() || defaultIgnoreRulesPath()),
      ignoredFindingIds: settings.ignoredFindings,
      dedupWithExistingTools: settings.dedupWithExistingTools
    }
  );
  if (!isCurrentDocumentRevision(document, documentVersion, revision)) {
    return;
  }
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

  const existing = findingsByUri.get(document.uri) ?? [];
  const findings = mergeFindingsForExecutedLayers(existing, result.findings, layers, options.replaceAll);
  findingsByUri.set(document.uri, findings);
  connection.sendDiagnostics({
    uri: document.uri,
    diagnostics: findings.filter((finding) => !finding.dismissed).map(toDiagnostic)
  });
}

function isCurrentDocumentRevision(document: TextDocument, version: number, revision: number): boolean {
  return documents.get(document.uri)?.version === version && documentRevisions.get(document.uri) === revision;
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
