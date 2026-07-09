#!/usr/bin/env node
import { fileURLToPath } from "url";
import {
  createConnection,
  DiagnosticSeverity,
  ProposedFeatures,
  TextDocumentSyncKind,
  TextDocuments,
  type Diagnostic,
  type InitializeParams,
  type InitializeResult
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { defaultIgnoreRulesPath, loadIgnoreRules } from "./ignore";
import { JsonPackageCache, defaultCachePath } from "./package/cache";
import { PackageVerifier } from "./package/packageVerifier";
import { scanSourceFile } from "./scanner";
import type { Finding, Severity } from "./types";

interface LspSettings {
  enabled: boolean;
  packageVerification: "off" | "seed" | "remote";
  enableL2: boolean;
  ignoreRulesPath?: string;
}

const defaultSettings: LspSettings = {
  enabled: true,
  packageVerification: "seed",
  enableL2: true
};

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);
const verifier = new PackageVerifier({
  cache: new JsonPackageCache(defaultCachePath())
});
let settings = defaultSettings;

connection.onInitialize((_params: InitializeParams): InitializeResult => ({
  capabilities: {
    textDocumentSync: TextDocumentSyncKind.Incremental
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
  connection.sendDiagnostics({
    uri: event.document.uri,
    diagnostics: []
  });
});

async function validateDocument(document: TextDocument): Promise<void> {
  if (!settings.enabled) {
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
      packageVerifier: verifier,
      ignoreRules: await loadIgnoreRules(settings.ignoreRulesPath?.trim() || defaultIgnoreRulesPath())
    }
  );

  connection.sendDiagnostics({
    uri: document.uri,
    diagnostics: result.findings.filter((finding) => !finding.dismissed).map(toDiagnostic)
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
