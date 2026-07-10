import fs from "fs/promises";
import path from "path";
import * as vscode from "vscode";
import {
  cloneDefaultConfig,
  defaultConfigPath,
  loadConfig,
  resolveConfigCustomRulePaths,
  updateLlmApiKeyStored,
  type LoadedVibeGuardConfig
} from "./config";
import { loadCustomRules } from "./customRules";
import { formatFindingsDashboard } from "./findings/dashboard";
import { defaultFindingsDbPath, SqliteFindingStore, type FindingAuthor } from "./findings/storage";
import { gitAuthorsForFiles, normalizeAuthorFilePath } from "./gitAuthors";
import {
  appendIgnoreRule,
  defaultIgnoreRulesPath,
  ensureIgnoreRulesFile,
  expandHome,
  loadIgnoreRules,
  scopedIgnoreReason,
  standardIgnoreReasons
} from "./ignore";
import { PackageVerifier } from "./package/packageVerifier";
import {
  selectConfiguredPackageSyncRegistries,
  syncConfiguredPackageIndexes,
  type ConfiguredPackageSyncResult
} from "./package/configSync";
import { getLlmApiKeyFromEnv, LlmSemanticAnalyzer, type LlmProvider } from "./l3/llm";
import { mergeFindingsForExecutedLayers, type ExecutedLayers } from "./layers";
import { createPackageStorage, type PackageStorage } from "./package/storage";
import { scanSourceFile } from "./scanner";
import type { Finding, PackageRegistry, ScanPerformance, Severity, VibeGuardConfig } from "./types";

const packageRegistries: PackageRegistry[] = ["npm", "pypi", "cargo", "gomod", "maven"];
const llmProviders: LlmProvider[] = ["deepseek", "claude", "openai", "local"];

const supportedLanguageIds = new Set([
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "python",
  "rust",
  "go",
  "java",
  "kotlin",
  "xml",
  "groovy",
  "json",
  "toml"
]);

let diagnostics: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let packageVerifier: PackageVerifier;
let packageStorage: PackageStorage;
let findingStore: SqliteFindingStore | undefined;
let packageSyncInFlight = false;
let extensionContext: vscode.ExtensionContext;
const l1Timers = new Map<string, NodeJS.Timeout>();
const l2Timers = new Map<string, NodeJS.Timeout>();
const l3Timers = new Map<string, NodeJS.Timeout>();
const findingsByUri = new Map<string, Finding[]>();
const performanceByUri = new Map<string, ScanPerformance>();
const popupSeen = new Set<string>();
const codeActionSelector: vscode.DocumentSelector = [
  { scheme: "file", language: "javascript" },
  { scheme: "file", language: "javascriptreact" },
  { scheme: "file", language: "typescript" },
  { scheme: "file", language: "typescriptreact" },
  { scheme: "file", language: "python" },
  { scheme: "file", language: "rust" },
  { scheme: "file", language: "go" },
  { scheme: "file", language: "java" },
  { scheme: "file", language: "kotlin" },
  { scheme: "file", language: "xml" },
  { scheme: "file", language: "groovy" },
  { scheme: "file", language: "json" },
  { scheme: "file", language: "toml" }
];

export function activate(context: vscode.ExtensionContext): void {
  extensionContext = context;
  diagnostics = vscode.languages.createDiagnosticCollection("vibeguard");
  output = vscode.window.createOutputChannel("VibeGuard");
  findingsProvider = new FindingsProvider(findingsByUri);
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 92);
  statusBar.command = "vibeguard.openReport";
  statusBar.text = "VibeGuard";
  statusBar.tooltip = "VibeGuard security findings";
  statusBar.show();

  const cachePath = path.join(context.globalStorageUri.fsPath, "package-cache.json");
  packageStorage = createPackageStorage({
    kind: "auto",
    cachePath
  });
  packageVerifier = new PackageVerifier({
    cache: packageStorage.cache,
    packageIndex: packageStorage.packageIndex
  });
  findingStore = createFindingStore();

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,
    vscode.window.registerTreeDataProvider("vibeguardFindings", findingsProvider),
    vscode.commands.registerCommand("vibeguard.scanCurrentFile", () => scanCurrentFile()),
    vscode.commands.registerCommand("vibeguard.scanWorkspace", () => scanWorkspace()),
    vscode.commands.registerCommand("vibeguard.clearFindings", () => clearFindings()),
    vscode.commands.registerCommand("vibeguard.openReport", () => openReport()),
    vscode.commands.registerCommand("vibeguard.exportDashboard", () => exportFindingsDashboard()),
    vscode.commands.registerCommand("vibeguard.openIgnoreRules", () => openIgnoreRules()),
    vscode.commands.registerCommand("vibeguard.syncPackageCache", () => syncPackageCache(true)),
    vscode.commands.registerCommand("vibeguard.setLlmApiKey", () => setLlmApiKey()),
    vscode.commands.registerCommand("vibeguard.deleteLlmApiKey", () => deleteLlmApiKey()),
    vscode.commands.registerCommand("vibeguard.showLlmStatus", () => showLlmStatus()),
    vscode.commands.registerCommand("vibeguard.openFinding", (finding: Finding) => openFinding(finding)),
    vscode.commands.registerCommand("vibeguard.ignoreFinding", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "line")
    ),
    vscode.commands.registerCommand("vibeguard.ignoreRuleInFile", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "file")
    ),
    vscode.commands.registerCommand("vibeguard.ignoreRuleGlobally", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "global")
    ),
    vscode.commands.registerCommand("vibeguard.ignorePackage", (nodeOrFinding: TreeNode | Finding) =>
      ignorePackage(resolveFindingArgument(nodeOrFinding))
    ),
    vscode.commands.registerCommand("vibeguard.applyFix", (finding: Finding) => applyFindingFix(finding)),
    vscode.languages.registerCodeActionsProvider(codeActionSelector, new VibeGuardCodeActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    }),
    vscode.workspace.onDidOpenTextDocument((document) => scheduleRealtimeScan(document, 0)),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (configuration().get<boolean>("scanOnChange", true)) {
        scheduleRealtimeScan(event.document, 0);
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (configuration().get<boolean>("scanOnSave", true)) {
        scheduleScan(document, 0, { includeL2: true, includeL3: true, cancelPendingL2: true, cancelPendingL3: true, replaceAll: true });
      }
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        scheduleRealtimeScan(editor.document, 0);
      }
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    scheduleRealtimeScan(document, 0);
  }
  void syncPackageCache(false);
}

export function deactivate(): void {
  clearAllTimers(l1Timers);
  clearAllTimers(l2Timers);
  clearAllTimers(l3Timers);
  findingStore?.close();
}

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage("VibeGuard: no active editor to scan.");
    return;
  }
  await scanDocument(editor.document, { includeL2: true, includeL3: true, replaceAll: true });
}

async function scanWorkspace(): Promise<void> {
  const files = await vscode.workspace.findFiles(
    "**/*.{js,jsx,ts,tsx,mjs,cjs,py,rs,go,java,kt,kts,json,toml,xml,gradle,txt}",
    "**/{node_modules,.git,out,dist,build,coverage}/**",
    500
  );

  statusBar.text = "$(shield) VibeGuard scanning...";
  let scanned = 0;
  for (const uri of files) {
    const document = await vscode.workspace.openTextDocument(uri);
    await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
    scanned += 1;
  }
  updateStatus();
  void vscode.window.showInformationMessage(`VibeGuard scanned ${scanned} files.`);
}

function clearFindings(): void {
  clearAllTimers(l1Timers);
  clearAllTimers(l2Timers);
  clearAllTimers(l3Timers);
  findingsByUri.clear();
  performanceByUri.clear();
  diagnostics.clear();
  findingsProvider.refresh();
  popupSeen.clear();
  updateStatus();
}

async function openReport(): Promise<void> {
  const allFindings = allCurrentFindings();
  output.clear();
  output.appendLine("VibeGuard Findings");
  output.appendLine("==================");
  if (allFindings.length === 0) {
    output.appendLine("No findings.");
  } else {
    for (const finding of allFindings) {
      output.appendLine(
        `${finding.severity.toUpperCase()} ${finding.file}:${finding.line}:${finding.column} ${finding.message}`
      );
      output.appendLine(`  Rule: ${finding.detection_rule} (${finding.detection_layer})`);
      output.appendLine(`  Evidence: ${finding.evidence}`);
      if (finding.suggestion) {
        output.appendLine(`  Suggestion: ${finding.suggestion}`);
      }
      output.appendLine("");
    }
  }
  appendPerformanceReport(output, allCurrentPerformances());
  output.show();
}

async function exportFindingsDashboard(): Promise<void> {
  const windowChoice = await vscode.window.showQuickPick(
    [
      { label: "Last 30 days", days: 30 },
      { label: "Last 90 days", days: 90 },
      { label: "All stored history", days: undefined }
    ],
    {
      placeHolder: "Select the findings history window for the dashboard"
    }
  );
  if (!windowChoice) {
    return;
  }

  const defaultUri = vscode.Uri.file(path.join(workspaceRootPath(), "vibeguard-dashboard.html"));
  const outputUri = await vscode.window.showSaveDialog({
    defaultUri,
    filters: {
      HTML: ["html"]
    },
    saveLabel: "Export Dashboard"
  });
  if (!outputUri) {
    return;
  }

  const dbPath = configuredFindingsDbPath();
  if (!configuration().get<boolean>("storeFindings", true)) {
    void vscode.window.showWarningMessage("VibeGuard findings storage is disabled. The exported dashboard may be empty.");
  }

  let store: SqliteFindingStore | undefined;
  try {
    store = new SqliteFindingStore(dbPath);
    const since = windowChoice.days === undefined ? undefined : Date.now() - windowChoice.days * 24 * 60 * 60 * 1000;
    const summary = store.summary({ since, topLimit: 10 });
    const html = formatFindingsDashboard(summary, {
      dbPath,
      generatedAt: Date.now()
    });
    await fs.mkdir(path.dirname(outputUri.fsPath), { recursive: true });
    await fs.writeFile(outputUri.fsPath, html, "utf8");
  } catch (error) {
    void vscode.window.showErrorMessage(`VibeGuard dashboard export failed: ${error instanceof Error ? error.message : String(error)}`);
    return;
  } finally {
    store?.close();
  }

  const choice = await vscode.window.showInformationMessage(
    `VibeGuard dashboard exported to ${outputUri.fsPath}`,
    "Open",
    "Reveal"
  );
  if (choice === "Open") {
    await vscode.env.openExternal(outputUri);
  } else if (choice === "Reveal") {
    await vscode.commands.executeCommand("revealFileInOS", outputUri);
  }
}

async function openIgnoreRules(): Promise<void> {
  const filePath = await ensureIgnoreRulesFile(ignoreRulesPath());
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
  await vscode.window.showTextDocument(document);
}

async function setLlmApiKey(): Promise<void> {
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  const provider = await pickLlmProvider(loadedConfig.config);
  if (!provider) {
    return;
  }
  if (provider === "local") {
    void vscode.window.showInformationMessage("VibeGuard local LLM mode uses Ollama and does not require an API key.");
    return;
  }

  const apiKey = await vscode.window.showInputBox({
    prompt: `Enter ${provider} API key for VibeGuard L3 analysis`,
    password: true,
    ignoreFocusOut: true,
    validateInput: (value) => (value.trim() ? undefined : "API key must not be empty.")
  });
  if (!apiKey) {
    return;
  }

  await extensionContext.secrets.store(llmSecretKey(provider), apiKey.trim());
  await updateConfiguredLlmKeyStored(true, provider);
  void vscode.window.showInformationMessage(`VibeGuard ${provider} API key stored securely.`);
}

async function deleteLlmApiKey(): Promise<void> {
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  const provider = await pickLlmProvider(loadedConfig.config);
  if (!provider) {
    return;
  }
  await extensionContext.secrets.delete(llmSecretKey(provider));
  await updateConfiguredLlmKeyStored(false, provider);
  void vscode.window.showInformationMessage(`VibeGuard ${provider} API key removed.`);
}

async function showLlmStatus(): Promise<void> {
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  const provider = configuredLlmProvider(loadedConfig.config);
  const secret = provider === "local" ? undefined : await extensionContext.secrets.get(llmSecretKey(provider));
  const envKey = getLlmApiKeyFromEnv(provider);
  const source =
    provider === "local" ? "local Ollama (no API key)" : secret ? "VSCode SecretStorage" : envKey ? "environment variable" : "missing";
  output.appendLine("LLM Status");
  output.appendLine("==========");
  output.appendLine(`Provider: ${provider}`);
  output.appendLine(`Credential source: ${source}`);
  output.appendLine(`Config marker llm_api_key_stored: ${loadedConfig.config.llm_api_key_stored ? "true" : "false"}`);
  output.appendLine(`Config path: ${loadedConfig.path}`);
  output.appendLine("");
  output.show();
  void vscode.window.showInformationMessage(`VibeGuard L3 provider: ${provider}; credential: ${source}.`);
}

async function openFinding(finding: Finding): Promise<void> {
  const uri = vscode.Uri.file(finding.file);
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document);
  const range = findingRange(finding);
  editor.selection = new vscode.Selection(range.start, range.end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

interface ScheduleScanOptions {
  includeL2: boolean;
  includeL3: boolean;
  scheduleL2?: boolean;
  scheduleL3?: boolean;
  cancelPendingL2?: boolean;
  cancelPendingL3?: boolean;
  replaceAll?: boolean;
}

function scheduleRealtimeScan(document: vscode.TextDocument, delayMs: number): void {
  scheduleScan(document, delayMs, {
    includeL2: false,
    includeL3: false,
    scheduleL2: true,
    scheduleL3: true
  });
}

function scheduleScan(
  document: vscode.TextDocument,
  delayMs: number,
  options: ScheduleScanOptions = { includeL2: true, includeL3: true, replaceAll: true }
): void {
  if (!isSupportedDocument(document)) {
    return;
  }
  const key = document.uri.toString();
  if (options.cancelPendingL2 || options.includeL2) {
    clearTimer(l2Timers, key);
  }
  if (options.cancelPendingL3 || options.includeL3) {
    clearTimer(l3Timers, key);
  }
  if (options.scheduleL2) {
    scheduleL2Scan(document);
  }
  if (options.scheduleL3) {
    scheduleL3Scan(document);
  }
  const existing = l1Timers.get(key);
  if (existing) {
    clearTimeout(existing);
  }
  l1Timers.set(
    key,
    setTimeout(() => {
      l1Timers.delete(key);
      void scanDocument(document, {
        includeL2: options.includeL2,
        includeL3: options.includeL3,
        replaceAll: options.replaceAll
      });
    }, delayMs)
  );
}

function scheduleL2Scan(document: vscode.TextDocument): void {
  if (!isSupportedDocument(document)) {
    return;
  }
  const delayMs = configuredL2DebounceMs();
  const key = document.uri.toString();
  clearTimer(l2Timers, key);
  l2Timers.set(
    key,
    setTimeout(() => {
      l2Timers.delete(key);
      void scanDocument(document, { includeL2: true, includeL3: false });
    }, delayMs)
  );
}

function scheduleL3Scan(document: vscode.TextDocument): void {
  if (!isSupportedDocument(document)) {
    return;
  }
  const delayMs = configuredL3DebounceMs();
  const key = document.uri.toString();
  clearTimer(l3Timers, key);
  l3Timers.set(
    key,
    setTimeout(() => {
      l3Timers.delete(key);
      void scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
    }, delayMs)
  );
}

function clearTimer(store: Map<string, NodeJS.Timeout>, key: string): void {
  const existing = store.get(key);
  if (existing) {
    clearTimeout(existing);
    store.delete(key);
  }
}

function clearAllTimers(store: Map<string, NodeJS.Timeout>): void {
  for (const timer of store.values()) {
    clearTimeout(timer);
  }
  store.clear();
}

export function normalizeDebounceMs(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(30000, Math.max(0, Math.round(value)));
}

export function normalizeL3DebounceMs(value: unknown, fallback = 2000): number {
  return normalizeDebounceMs(value, fallback);
}

function configuredL2DebounceMs(): number {
  return normalizeDebounceMs(configuredSettingOr("l2DebounceMs", 500), 500);
}

function configuredL3DebounceMs(): number {
  return normalizeL3DebounceMs(configuredSettingOr("l3DebounceMs", 2000));
}

async function scanDocument(
  document: vscode.TextDocument,
  options: { includeL2?: boolean; includeL3?: boolean; replaceAll?: boolean } = {}
): Promise<void> {
  if (!isSupportedDocument(document)) {
    return;
  }
  const scanStartedAt = Date.now();

  const loadedConfig = await loadConfiguredVibeGuardConfig(document);
  const enabled = configuredSettingOr("enabled", loadedConfig.config.enabled);
  if (!enabled) {
    findingsByUri.delete(document.uri.toString());
    performanceByUri.delete(document.uri.toString());
    diagnostics.delete(document.uri);
    findingsProvider.refresh();
    updateStatus();
    return;
  }

  const packageVerification = configuredSettingOr<"off" | "seed" | "remote">(
    "packageVerification",
    loadedConfig.config.package_verification
  );
  const enableL2 = Boolean(options.includeL2 ?? true) && configuredSettingOr("enableL2", loadedConfig.config.detection_layers.l2);
  const enableL3 = Boolean(options.includeL3 ?? true) && configuredSettingOr("enableL3", loadedConfig.config.detection_layers.l3);
  const l3Analyzer = enableL3 ? await createConfiguredL3Analyzer(loadedConfig.config) : undefined;
  const dedupWithExistingTools = configuredSettingOr(
    "dedupWithExistingTools",
    loadedConfig.config.dedup_with_existing_tools
  );
  const ignoredFindingIds = [
    ...loadedConfig.config.ignored_findings,
    ...configuredSettingOr<string[]>("ignoredFindings", [])
  ];
  const ignoreRules = await loadIgnoreRules(ignoreRulesPath());
  const customRules = await loadConfiguredCustomRules(document, loadedConfig);
  const executedLayers: ExecutedLayers = {
    l1: loadedConfig.config.detection_layers.l1,
    l2: enableL2,
    l3: enableL3
  };
  const result = await scanSourceFile(
    {
      filePath: document.uri.fsPath,
      text: document.getText(),
      languageId: document.languageId
    },
    {
      packageVerification,
      detectionLayers: {
        l1: executedLayers.l1,
        l2: enableL2,
        l3: enableL3
      },
      packageVerifier,
      l3Analyzer,
      customRules,
      ignoreRules,
      ignoredFindingIds,
      dedupWithExistingTools
    }
  );

  const key = document.uri.toString();
  const existing = findingsByUri.get(key) ?? [];
  const mergedFindings = mergeFindingsForExecutedLayers(existing, result.findings, executedLayers, Boolean(options.replaceAll));
  findingsByUri.set(key, mergedFindings);
  performanceByUri.set(document.uri.toString(), result.performance);
  diagnostics.set(document.uri, mergedFindings.filter((finding) => !finding.dismissed).map(findingToDiagnostic));
  findingsProvider.refresh();
  updateStatus();
  void persistDocumentFindings(document, mergedFindings, scanStartedAt);
  maybeShowCriticalPopup(document, mergedFindings);
}

function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(findingRange(finding), finding.message, toDiagnosticSeverity(finding.severity));
  diagnostic.code = finding.detection_rule;
  diagnostic.source = "VibeGuard";
  if (finding.suggestion) {
    diagnostic.message = `${finding.message} ${finding.suggestion}`;
  }
  return diagnostic;
}

function findingRange(finding: Finding): vscode.Range {
  const startLine = Math.max(0, finding.line - 1);
  const startColumn = Math.max(0, finding.column - 1);
  const endLine = Math.max(startLine, (finding.endLine ?? finding.line) - 1);
  const endColumn = Math.max(startColumn + 1, (finding.endColumn ?? finding.column + finding.evidence.length) - 1);
  return new vscode.Range(startLine, startColumn, endLine, endColumn);
}

function toDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    case "info":
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function maybeShowCriticalPopup(document: vscode.TextDocument, findings: Finding[]): void {
  if (!configuration().get<boolean>("showCriticalPopups", true)) {
    return;
  }
  const critical = findings.find((finding) => finding.severity === "critical" && !finding.dismissed && !popupSeen.has(finding.id));
  if (!critical) {
    return;
  }
  popupSeen.add(critical.id);
  const replace = critical.fix?.description;
  const actions = replace ? [replace, "Ignore", "Manage Ignore Rules"] : ["Ignore", "Manage Ignore Rules"];
  void vscode.window.showWarningMessage(`VibeGuard: ${critical.message}`, ...actions).then(async (choice) => {
    if (choice === replace && critical.fix) {
      await applyFindingFix(critical);
    } else if (choice === "Ignore") {
      await ignoreFinding(critical, "line");
      await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
    } else if (choice === "Manage Ignore Rules") {
      await openIgnoreRules();
    }
  });
}

async function applyFindingFix(finding: Finding | undefined): Promise<void> {
  if (!finding?.fix) {
    return;
  }
  const uri = vscode.Uri.file(finding.file);
  await vscode.workspace.applyEdit(workspaceEditForFix(uri, finding));
  const document = await vscode.workspace.openTextDocument(uri);
  await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
}

function updateStatus(): void {
  const findings = allCurrentFindings().filter((finding) => !finding.dismissed);
  const performanceSummary = currentPerformanceSummary();
  const performanceMarker = performanceSummary.warningCount > 0 ? " $(watch)" : "";
  if (findings.length === 0) {
    statusBar.text = `$(shield) VibeGuard: clean${performanceMarker}`;
    statusBar.tooltip = performanceSummary.tooltip ? `No VibeGuard findings\n${performanceSummary.tooltip}` : "No VibeGuard findings";
    return;
  }

  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const high = findings.filter((finding) => finding.severity === "high").length;
  statusBar.text = `$(shield) VibeGuard: ${findings.length}${performanceMarker}`;
  statusBar.tooltip = `${findings.length} finding(s), ${critical} critical, ${high} high${
    performanceSummary.tooltip ? `\n${performanceSummary.tooltip}` : ""
  }`;
}

function allCurrentFindings(): Finding[] {
  return [...findingsByUri.values()].flat().sort((a, b) => {
    const severityOrder: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    return severityOrder[a.severity] - severityOrder[b.severity] || a.file.localeCompare(b.file) || a.line - b.line;
  });
}

function allCurrentPerformances(): ScanPerformance[] {
  return [...performanceByUri.values()].sort((a, b) => b.timings.totalMs - a.timings.totalMs);
}

function currentPerformanceSummary(): { warningCount: number; tooltip?: string } {
  const performances = allCurrentPerformances();
  if (performances.length === 0) {
    return { warningCount: 0 };
  }
  const slowest = performances[0];
  const warnings = performances.flatMap((item) =>
    item.budgets.filter((check) => check.exceeded).map((check) => ({ ...check, file: item.file }))
  );
  const lines = [
    `Last scan performance: ${formatMs(slowest.timings.totalMs)} slowest (${path.basename(slowest.file)})`,
    `Layer totals: L1 ${formatMs(sumPerformance(performances, "l1Ms"))}, L2 ${formatMs(sumPerformance(performances, "l2Ms"))}, L3 ${formatMs(sumPerformance(performances, "l3Ms"))}`
  ];
  if (warnings.length > 0) {
    const warning = warnings[0];
    lines.push(
      `Performance budget warning: ${warning.layer} ${path.basename(warning.file)} ${formatMs(warning.elapsedMs)} > ${formatMs(warning.budgetMs)}`
    );
  }
  return {
    warningCount: warnings.length,
    tooltip: lines.join("\n")
  };
}

function appendPerformanceReport(channel: vscode.OutputChannel, performances: ScanPerformance[]): void {
  if (performances.length === 0) {
    return;
  }
  const total = sumPerformance(performances, "totalMs");
  const warnings = performances.flatMap((item) =>
    item.budgets.filter((check) => check.exceeded).map((check) => ({ ...check, file: item.file }))
  );
  channel.appendLine("Performance");
  channel.appendLine("===========");
  channel.appendLine(`Scanned performance records: ${performances.length}`);
  channel.appendLine(`Total: ${formatMs(total)}, avg/file: ${formatMs(total / performances.length)}`);
  channel.appendLine(
    `Layer totals: L1 ${formatMs(sumPerformance(performances, "l1Ms"))}, L2 ${formatMs(
      sumPerformance(performances, "l2Ms")
    )}, L3 ${formatMs(sumPerformance(performances, "l3Ms"))}`
  );
  if (warnings.length > 0) {
    channel.appendLine(`Budget warnings: ${warnings.length}`);
    for (const warning of warnings.slice(0, 5)) {
      channel.appendLine(
        `  ${warning.layer} ${warning.file}: ${formatMs(warning.elapsedMs)} > ${formatMs(warning.budgetMs)}`
      );
    }
  } else {
    channel.appendLine("Budget warnings: 0");
  }
  channel.appendLine("");
}

function sumPerformance(performances: ScanPerformance[], key: keyof ScanPerformance["timings"]): number {
  return performances.reduce((sum, item) => sum + item.timings[key], 0);
}

function formatMs(value: number): string {
  if (value < 1000) {
    return `${value.toFixed(value < 10 ? 1 : 0)}ms`;
  }
  return `${(value / 1000).toFixed(2)}s`;
}

function findingsForDocument(document: vscode.TextDocument): Finding[] {
  return findingsByUri.get(document.uri.toString()) ?? [];
}

function findMatchingFinding(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): Finding | undefined {
  const diagnosticCode = typeof diagnostic.code === "string" ? diagnostic.code : String(diagnostic.code ?? "");
  return findingsForDocument(document).find((finding) => {
    if (finding.dismissed || finding.detection_rule !== diagnosticCode) {
      return false;
    }
    return findingRange(finding).intersection(diagnostic.range) !== undefined;
  });
}

function workspaceEditForFix(uri: vscode.Uri, finding: Finding): vscode.WorkspaceEdit {
  const edit = new vscode.WorkspaceEdit();
  for (const textEdit of finding.fix?.edits ?? []) {
    edit.replace(
      uri,
      new vscode.Range(
        textEdit.startLine - 1,
        textEdit.startColumn - 1,
        textEdit.endLine - 1,
        textEdit.endColumn - 1
      ),
      textEdit.newText
    );
  }
  return edit;
}

async function ignoreFinding(finding: Finding | undefined, scope: "line" | "file" | "global"): Promise<void> {
  if (!finding) {
    return;
  }
  const reason = await pickIgnoreReason(scope);
  if (reason === null) {
    return;
  }

  await appendIgnoreRule(
    {
      rule: finding.detection_rule,
      path: scope === "global" ? undefined : finding.file,
      line: scope === "line" ? finding.line : undefined,
      reason
    },
    ignoreRulesPath()
  );
  await refreshOpenDocuments();
  void vscode.window.showInformationMessage("VibeGuard ignore rule added.");
}

async function ignorePackage(finding: Finding | undefined): Promise<void> {
  if (!finding || finding.type !== "hallucinated_package") {
    void vscode.window.showInformationMessage("VibeGuard: this finding is not a package finding.");
    return;
  }
  const reason = await pickIgnoreReason("package");
  if (reason === null) {
    return;
  }
  const registry = finding.detection_rule.replace(/^hallucinated_package_/, "") as PackageRegistry;
  await appendIgnoreRule(
    {
      package: finding.evidence,
      registry,
      reason
    },
    ignoreRulesPath()
  );
  await refreshOpenDocuments();
  void vscode.window.showInformationMessage(`VibeGuard will ignore package "${finding.evidence}".`);
}

async function pickIgnoreReason(scope: "line" | "file" | "global" | "package"): Promise<string | undefined | null> {
  const ordered =
    scope === "package"
      ? [
          ...standardIgnoreReasons.filter((option) => option.id === "internal_package"),
          ...standardIgnoreReasons.filter((option) => option.id !== "internal_package")
        ]
      : standardIgnoreReasons;
  const picked = await vscode.window.showQuickPick(
    [
      ...ordered.map((option) => ({
        label: option.label,
        description: option.reason,
        value: option.reason
      })),
      {
        label: "Custom reason...",
        description: "Write a short reason for this ignore rule",
        value: "__custom__"
      },
      {
        label: "No reason",
        description: "Add the ignore rule without a reason",
        value: undefined
      }
    ],
    {
      placeHolder: "Why should VibeGuard ignore this finding?"
    }
  );
  if (!picked) {
    return null;
  }
  if (picked.value === "__custom__") {
    const custom = await vscode.window.showInputBox({
      prompt: "Reason for ignoring this VibeGuard finding",
      ignoreFocusOut: true,
      validateInput: (value) => (value.trim() ? undefined : "Reason must not be empty.")
    });
    return custom ? scopedIgnoreReason(custom, scope) : null;
  }
  return scopedIgnoreReason(picked.value, scope);
}

async function refreshOpenDocuments(): Promise<void> {
  for (const document of vscode.workspace.textDocuments) {
    if (isSupportedDocument(document)) {
      await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
    }
  }
}

async function syncPackageCache(manual: boolean): Promise<void> {
  if (packageSyncInFlight) {
    if (manual) {
      void vscode.window.showInformationMessage("VibeGuard package cache sync is already running.");
    }
    return;
  }
  if (!manual && !configuredSettingOr("autoSyncPackageCache", true)) {
    return;
  }

  packageSyncInFlight = true;
  statusBar.text = "$(sync~spin) VibeGuard: package sync";
  statusBar.tooltip = "VibeGuard package name cache is syncing";
  try {
    const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
    const configured = applyPackageCacheSettings(loadedConfig.config);
    const detectedRegistries = manual ? [] : await detectWorkspacePackageRegistries();
    const selectedRegistries = selectConfiguredPackageSyncRegistries(
      configured.package_cache.languages,
      detectedRegistries
    );
    const syncConfig = withPackageCacheLanguages(configured, selectedRegistries);
    const result = await syncConfiguredPackageIndexes({
      config: syncConfig,
      storage: packageStorage,
      force: manual,
      continueOnError: true
    });

    logPackageSyncResult(result, loadedConfig.path, loadedConfig.exists, detectedRegistries);
    const syncedCount = result.results.filter((entry) => entry.status === "synced").length;
    const failedCount = result.results.filter((entry) => entry.status === "failed").length;
    if (syncedCount > 0) {
      await refreshOpenDocuments();
    }
    if (manual) {
      const skippedCount = result.results.filter((entry) => entry.status === "skipped").length;
      void vscode.window.showInformationMessage(
        `VibeGuard package cache sync finished: ${syncedCount} synced, ${skippedCount} skipped, ${failedCount} failed.`
      );
    } else if (failedCount > 0 && syncedCount === 0) {
      void vscode.window.showWarningMessage(
        "VibeGuard package cache sync did not complete. Hallucinated package detection will keep using the existing local cache and seed catalog."
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`Package cache sync error: ${message}`);
    if (manual) {
      void vscode.window.showWarningMessage(`VibeGuard package cache sync failed: ${message}`);
    }
  } finally {
    packageSyncInFlight = false;
    updateStatus();
  }
}

function createFindingStore(): SqliteFindingStore | undefined {
  if (!configuration().get<boolean>("storeFindings", true)) {
    return undefined;
  }
  try {
    return new SqliteFindingStore(configuredFindingsDbPath());
  } catch (error) {
    output.appendLine(`Findings storage error: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

function configuredFindingsDbPath(): string {
  const configured = configuration().get<string>("findingsDbPath", "").trim();
  return configured ? expandHome(configured) : defaultFindingsDbPath();
}

function workspaceRootPath(): string {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? extensionContext.globalStorageUri.fsPath;
}

async function persistDocumentFindings(document: vscode.TextDocument, findings: Finding[], startedAt: number): Promise<void> {
  if (!configuration().get<boolean>("storeFindings", true)) {
    return;
  }
  if (!findingStore) {
    findingStore = createFindingStore();
  }
  const store = findingStore;
  if (!store) {
    return;
  }
  try {
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    const cwd = folder?.uri.fsPath ?? path.dirname(document.uri.fsPath);
    const findingAuthors = await resolveDocumentFindingAuthors(document, findings, cwd);
    store.recordScanRun({
      startedAt,
      completedAt: Date.now(),
      cwd,
      targetPaths: [document.uri.fsPath],
      fileCount: 1,
      findings,
      findingAuthors
    });
  } catch (error) {
    output.appendLine(`Findings storage error: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function resolveDocumentFindingAuthors(
  document: vscode.TextDocument,
  findings: Finding[],
  cwd: string
): Promise<Record<string, FindingAuthor>> {
  const authorByFindingId: Record<string, FindingAuthor> = {};
  if (findings.length === 0 || document.uri.scheme !== "file") {
    return authorByFindingId;
  }
  const authors = await gitAuthorsForFiles([document.uri.fsPath], cwd);
  const author = authors.get(normalizeAuthorFilePath(document.uri.fsPath));
  if (!author) {
    return authorByFindingId;
  }
  for (const finding of findings) {
    authorByFindingId[finding.id] = author;
  }
  return authorByFindingId;
}

function resolveFindingArgument(nodeOrFinding: TreeNode | Finding | undefined): Finding | undefined {
  if (!nodeOrFinding) {
    return undefined;
  }
  if ("kind" in nodeOrFinding) {
    return nodeOrFinding.kind === "finding" ? nodeOrFinding.finding : undefined;
  }
  return nodeOrFinding;
}

function ignoreRulesPath(): string {
  const configured = configuration().get<string>("ignoreRulesPath", "").trim();
  return configured ? expandHome(configured) : defaultIgnoreRulesPath();
}

async function loadConfiguredVibeGuardConfig(document: vscode.TextDocument): Promise<LoadedVibeGuardConfig> {
  const configuredPath = configuredSettingOr("configPath", "").trim();
  const configPath = configuredPath ? resolveWorkspacePath(configuredPath, document) : undefined;
  try {
    const loaded = await loadConfig(configPath);
    if (configuredPath && !loaded.exists) {
      output.appendLine(`Config file not found: ${loaded.path}`);
    }
    return loaded;
  } catch (error) {
    output.appendLine(`Config error: ${error instanceof Error ? error.message : String(error)}`);
    return {
      config: cloneDefaultConfig(),
      path: configPath ?? defaultConfigPath(),
      exists: false
    };
  }
}

async function loadConfiguredVibeGuardConfigForWorkspace(): Promise<LoadedVibeGuardConfig> {
  const configuredPath = configuredSettingOr("configPath", "").trim();
  const configPath = configuredPath ? resolveWorkspaceSettingPath(configuredPath) : undefined;
  try {
    const loaded = await loadConfig(configPath);
    if (configuredPath && !loaded.exists) {
      output.appendLine(`Config file not found: ${loaded.path}`);
    }
    return loaded;
  } catch (error) {
    output.appendLine(`Config error: ${error instanceof Error ? error.message : String(error)}`);
    return {
      config: cloneDefaultConfig(),
      path: configPath ?? defaultConfigPath(),
      exists: false
    };
  }
}

async function createConfiguredL3Analyzer(config: VibeGuardConfig): Promise<LlmSemanticAnalyzer | undefined> {
  const provider = configuredLlmProvider(config);
  const secret = provider === "local" ? undefined : await extensionContext.secrets.get(llmSecretKey(provider));
  const apiKey = secret ?? getLlmApiKeyFromEnv(provider);
  if (provider !== "local" && !apiKey) {
    return undefined;
  }
  return new LlmSemanticAnalyzer({
    provider,
    apiKey,
    model: configuredOptionalString("llmModel"),
    baseUrl: configuredOptionalString("llmBaseUrl")
  });
}

function configuredLlmProvider(config: VibeGuardConfig): LlmProvider {
  const configured = configuredSettingOr<string>("llmProvider", config.llm_provider ?? "deepseek");
  return isLlmProvider(configured) ? configured : config.llm_provider ?? "deepseek";
}

async function pickLlmProvider(config: VibeGuardConfig): Promise<LlmProvider | undefined> {
  const current = configuredLlmProvider(config);
  const picked = await vscode.window.showQuickPick(
    llmProviders.map((provider) => ({
      label: provider,
      description: provider === current ? "current" : undefined
    })),
    {
      placeHolder: "Select LLM provider for VibeGuard L3 analysis"
    }
  );
  return picked?.label as LlmProvider | undefined;
}

async function updateConfiguredLlmKeyStored(stored: boolean, provider: LlmProvider): Promise<void> {
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  try {
    await updateLlmApiKeyStored(stored, loadedConfig.path, provider);
  } catch (error) {
    output.appendLine(`Config update error: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function llmSecretKey(provider: LlmProvider): string {
  return `llm_api_key.${provider}`;
}

function isLlmProvider(value: string): value is LlmProvider {
  return llmProviders.includes(value as LlmProvider);
}

function configuredOptionalString(key: string): string | undefined {
  const configured = configuredSettingOr<string>(key, "").trim();
  return configured || undefined;
}

async function loadConfiguredCustomRules(
  document: vscode.TextDocument,
  loadedConfig: LoadedVibeGuardConfig
): Promise<Awaited<ReturnType<typeof loadCustomRules>>> {
  const configured = configuredSettingOr<string[]>("customRules", []);
  const rulePaths = [
    ...resolveConfigCustomRulePaths(loadedConfig.config, loadedConfig.path),
    ...configured.map((item) => resolveWorkspacePath(item, document))
  ];
  if (rulePaths.length === 0) {
    return [];
  }
  try {
    return await loadCustomRules(rulePaths);
  } catch (error) {
    output.appendLine(`Custom rules error: ${error instanceof Error ? error.message : String(error)}`);
    return [];
  }
}

function resolveWorkspacePath(inputPath: string, document: vscode.TextDocument): string {
  const expanded = expandHome(inputPath);
  if (path.isAbsolute(expanded)) {
    return expanded;
  }
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  return path.resolve(folder?.uri.fsPath ?? path.dirname(document.uri.fsPath), expanded);
}

function resolveWorkspaceSettingPath(inputPath: string): string {
  const expanded = expandHome(inputPath);
  if (path.isAbsolute(expanded)) {
    return expanded;
  }
  const folder = vscode.workspace.workspaceFolders?.[0];
  return path.resolve(folder?.uri.fsPath ?? process.cwd(), expanded);
}

function applyPackageCacheSettings(config: VibeGuardConfig): VibeGuardConfig {
  const languages = configuredPackageCacheLanguages(config.package_cache.languages);
  return {
    ...config,
    detection_layers: { ...config.detection_layers },
    custom_rules: [...config.custom_rules],
    ignored_findings: [...config.ignored_findings],
    package_cache: {
      languages,
      update_interval: configuredPackageCacheUpdateInterval(config.package_cache.update_interval),
      lightweight_mode: configuredSettingOr("packageCacheLightweightMode", config.package_cache.lightweight_mode)
    }
  };
}

function withPackageCacheLanguages(config: VibeGuardConfig, languages: PackageRegistry[]): VibeGuardConfig {
  return {
    ...config,
    detection_layers: { ...config.detection_layers },
    custom_rules: [...config.custom_rules],
    ignored_findings: [...config.ignored_findings],
    package_cache: {
      ...config.package_cache,
      languages
    }
  };
}

function configuredPackageCacheLanguages(fallback: PackageRegistry[]): PackageRegistry[] {
  const configured = configuredSettingOr<string[]>("packageCacheLanguages", fallback);
  const languages: PackageRegistry[] = [];
  const invalid: string[] = [];
  for (const item of configured) {
    if (isPackageRegistry(item)) {
      languages.push(item);
    } else {
      invalid.push(item);
    }
  }
  if (invalid.length > 0) {
    output.appendLine(`Ignored unsupported package cache language(s): ${invalid.join(", ")}`);
  }
  return [...new Set(languages)];
}

function configuredPackageCacheUpdateInterval(
  fallback: VibeGuardConfig["package_cache"]["update_interval"]
): VibeGuardConfig["package_cache"]["update_interval"] {
  const configured = configuredSettingOr<string>("packageCacheUpdateInterval", fallback);
  if (configured === "daily" || configured === "weekly") {
    return configured;
  }
  output.appendLine(`Ignored unsupported package cache update interval: ${configured}`);
  return fallback;
}

async function detectWorkspacePackageRegistries(): Promise<PackageRegistry[]> {
  const checks: Array<[PackageRegistry, string]> = [
    ["npm", "**/package.json"],
    ["pypi", "**/{requirements.txt,pyproject.toml}"],
    ["cargo", "**/Cargo.toml"],
    ["gomod", "**/go.mod"],
    ["maven", "**/{pom.xml,build.gradle,build.gradle.kts}"]
  ];
  const found = await Promise.all(
    checks.map(async ([registry, glob]) => ({
      registry,
      matches: await vscode.workspace.findFiles(glob, "**/{node_modules,.git,out,dist,build,coverage,.vscode-test}/**", 1)
    }))
  );
  return found.filter((entry) => entry.matches.length > 0).map((entry) => entry.registry);
}

function logPackageSyncResult(
  result: ConfiguredPackageSyncResult,
  configPath: string,
  configExists: boolean,
  detectedRegistries: PackageRegistry[]
): void {
  output.appendLine("Package Cache Sync");
  output.appendLine("==================");
  output.appendLine(`Config: ${configPath}${configExists ? "" : " (defaults; file not found)"}`);
  output.appendLine(`Storage: ${result.storage} ${result.path ?? ""}`.trimEnd());
  output.appendLine(`Mode: ${result.lightweightMode ? "lightweight" : "full"}, interval: ${result.updateInterval}`);
  if (detectedRegistries.length > 0) {
    output.appendLine(`Detected workspace package managers: ${detectedRegistries.join(", ")}`);
  }
  if (result.results.length === 0) {
    output.appendLine("No package registries selected for sync.");
  }
  for (const entry of result.results) {
    if (entry.status === "synced") {
      output.appendLine(
        `${entry.registry}: synced ${entry.imported ?? 0} package name(s), ${entry.coverage ?? "partial"} coverage (${entry.reason})`
      );
      if (entry.pagesFetched && entry.pagesFetched > 1) {
        output.appendLine(`${entry.registry}: fetched ${entry.pagesFetched} page(s).`);
      }
    } else if (entry.status === "skipped") {
      output.appendLine(
        `${entry.registry}: skipped (${entry.reason}), ${entry.packageCount ?? 0} package(s), ${entry.coverage ?? "unknown"} coverage`
      );
    } else {
      output.appendLine(`${entry.registry}: failed (${entry.reason}): ${entry.error}`);
    }
  }
  output.appendLine("");
}

function isPackageRegistry(value: string): value is PackageRegistry {
  return packageRegistries.includes(value as PackageRegistry);
}

function isSupportedDocument(document: vscode.TextDocument): boolean {
  if (document.uri.scheme !== "file" && document.uri.scheme !== "untitled") {
    return false;
  }
  if (supportedLanguageIds.has(document.languageId)) {
    return true;
  }
  return /(?:package\.json|requirements\.txt|pyproject\.toml|cargo\.toml|go\.mod|pom\.xml|build\.gradle|build\.gradle\.kts)$/i.test(document.fileName);
}

function configuration(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("vibeguard");
}

function configuredSettingOr<T>(key: string, fallback: T): T {
  const inspected = configuration().inspect<T>(key);
  if (!inspected) {
    return fallback;
  }
  return (
    inspected.workspaceFolderLanguageValue ??
    inspected.workspaceFolderValue ??
    inspected.workspaceLanguageValue ??
    inspected.workspaceValue ??
    inspected.globalLanguageValue ??
    inspected.globalValue ??
    fallback
  );
}

class FindingsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly emitter = new vscode.EventEmitter<TreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly store: Map<string, Finding[]>) {}

  refresh(): void {
    this.emitter.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element.kind === "group") {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.Expanded);
      item.contextValue = "vibeguardSeverityGroup";
      return item;
    }

    const item = new vscode.TreeItem(`${element.finding.message} (${path.basename(element.finding.file)}:${element.finding.line})`);
    item.description = element.finding.dismissed ? `${element.finding.severity} dismissed` : element.finding.severity;
    item.tooltip = element.finding.dismissed
      ? `${element.finding.dismissed_reason ?? "Dismissed"}\n${element.finding.suggestion ?? element.finding.evidence}`
      : element.finding.suggestion ?? element.finding.evidence;
    item.command = {
      command: "vibeguard.openFinding",
      title: "Open Finding",
      arguments: [element.finding]
    };
    item.contextValue = "vibeguardFinding";
    item.iconPath = element.finding.dismissed ? new vscode.ThemeIcon("pass") : severityIcon(element.finding.severity);
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    const findings = [...this.store.values()].flat();
    if (!element) {
      return (["critical", "high", "medium", "low", "info"] as Severity[])
        .map((severity) => ({
          kind: "group" as const,
          severity,
          label: `${capitalize(severity)} (${findings.filter((finding) => finding.severity === severity).length})`
        }))
        .filter((group) => !group.label.endsWith("(0)"));
    }
    if (element.kind === "group") {
      return findings
        .filter((finding) => finding.severity === element.severity)
        .map((finding) => ({
          kind: "finding" as const,
          finding
        }));
    }
    return [];
  }
}

type TreeNode =
  | {
      kind: "group";
      severity: Severity;
      label: string;
    }
  | {
      kind: "finding";
      finding: Finding;
    };

function severityIcon(severity: Severity): vscode.ThemeIcon {
  if (severity === "critical" || severity === "high") {
    return new vscode.ThemeIcon("error");
  }
  if (severity === "medium") {
    return new vscode.ThemeIcon("warning");
  }
  return new vscode.ThemeIcon("info");
}

function capitalize(value: string): string {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics.filter((item) => item.source === "VibeGuard")) {
      const finding = findMatchingFinding(document, diagnostic);
      if (!finding) {
        continue;
      }

      if (finding.fix) {
        const action = new vscode.CodeAction(`Apply VibeGuard fix: ${finding.fix.description}`, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        action.edit = workspaceEditForFix(document.uri, finding);
        actions.push(action);
      }

      actions.push(commandAction("Ignore this VibeGuard finding", "vibeguard.ignoreFinding", finding, diagnostic));
      actions.push(commandAction("Ignore this rule in this file", "vibeguard.ignoreRuleInFile", finding, diagnostic));
      actions.push(commandAction("Ignore this rule globally", "vibeguard.ignoreRuleGlobally", finding, diagnostic));
      if (finding.type === "hallucinated_package") {
        actions.push(commandAction(`Ignore package "${finding.evidence}"`, "vibeguard.ignorePackage", finding, diagnostic));
      }
    }
    return actions;
  }
}

function commandAction(title: string, command: string, finding: Finding, diagnostic: vscode.Diagnostic): vscode.CodeAction {
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  action.diagnostics = [diagnostic];
  action.command = {
    command,
    title,
    arguments: [finding]
  };
  return action;
}
