import fs from "fs/promises";
import path from "path";
import * as vscode from "vscode";
import { planProBatchFixes, planSafeBatchFixes } from "./batchFixes";
import {
  cloneDefaultConfig,
  defaultConfigPath,
  loadConfig,
  resolveConfigCustomRulePaths,
  updateLlmApiKeyStored,
  type LoadedVibeGuardConfig
} from "./config";
import { criticalAlertMessage } from "./criticalAlert";
import { loadCustomRules } from "./customRules";
import { redactedSecretFixStillMatchesSource } from "./fixValidation";
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
import { falsePositiveTelemetryEvent, isFalsePositiveDismissalReason, reportFalsePositiveTelemetry } from "./telemetry";
import { PackageVerifier } from "./package/packageVerifier";
import {
  selectConfiguredPackageSyncRegistries,
  syncConfiguredPackageIndexesInBackground,
  type ConfiguredPackageSyncProgress,
  type ConfiguredPackageSyncResult,
  type PackageCacheSyncTier
} from "./package/configSync";
import { isRequirementsManifestPath } from "./package/packageParser";
import { getLlmApiKeyFromEnv, LlmSemanticAnalyzer, type LlmProvider } from "./l3/llm";
import { mergeFindingsForExecutedLayers, type ExecutedLayers } from "./layers";
import { createPackageStorage, type PackageStorage } from "./package/storage";
import { scanSourceFile } from "./scanner";
import { getProSubscriptionStatus } from "./subscription";
import type { CodeFix, Finding, PackageRegistry, ScanPerformance, Severity, VibeGuardConfig } from "./types";

const packageRegistries: PackageRegistry[] = ["npm", "pypi", "cargo", "gomod", "maven"];
const llmProviders: LlmProvider[] = ["deepseek", "claude", "openai", "local", "vibeguard"];
const firstRunOnboardingKey = "vibeguard.firstRunOnboardingShown";
const realtimeRemoteVerificationDelayMs = 600;

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
  "toml",
  "shellscript",
  "powershell",
  "yaml",
  "dockerfile"
]);

let diagnostics: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let packageVerifier: PackageVerifier;
let packageStorage: PackageStorage;
let findingStore: SqliteFindingStore | undefined;
let packageSyncInFlight = false;
let packageSyncProgress: ConfiguredPackageSyncProgress | undefined;
let packageSyncTier: PackageCacheSyncTier | undefined;
let extensionContext: vscode.ExtensionContext;
const l1Timers = new Map<string, NodeJS.Timeout>();
const l2Timers = new Map<string, NodeJS.Timeout>();
const l3Timers = new Map<string, NodeJS.Timeout>();
const remotePackageTimers = new Map<string, NodeJS.Timeout>();
const findingsByUri = new Map<string, Finding[]>();
const performanceByUri = new Map<string, ScanPerformance>();
const popupSeenByUri = new Map<string, Set<string>>();
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
  { scheme: "file", language: "toml" },
  { scheme: "file", language: "shellscript" },
  { scheme: "file", language: "powershell" },
  { scheme: "file", language: "yaml" },
  { scheme: "file", language: "dockerfile" }
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
    vscode.commands.registerCommand("vibeguard.showSubscriptionStatus", () => showSubscriptionStatus()),
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
    vscode.commands.registerCommand("vibeguard.applyFindingFix", (nodeOrFinding: TreeNode | Finding) =>
      applyFindingFixFromSidebar(resolveFindingArgument(nodeOrFinding))
    ),
    vscode.commands.registerCommand("vibeguard.applyAllSafeFixes", () => applyAllSafeFixes()),
    vscode.commands.registerCommand("vibeguard.applyAllProFixes", () => applyAllProFixes()),
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
        scheduleScan(document, 0, {
          includeL2: true,
          includeL3: true,
          cancelPendingL2: true,
          cancelPendingL3: true,
          cancelPendingRemote: true,
          replaceAll: true
        });
      }
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      popupSeenByUri.delete(document.uri.toString());
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
  void maybeShowFirstRunOnboarding();
  void syncPackageCache(false);
}

export function deactivate(): void {
  clearAllTimers(l1Timers);
  clearAllTimers(l2Timers);
  clearAllTimers(l3Timers);
  clearAllTimers(remotePackageTimers);
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
  const exclude = "**/{node_modules,.git,out,dist,build,coverage}/**";
  const [extensionFiles, dockerfiles] = await Promise.all([
    vscode.workspace.findFiles("**/*.{js,jsx,ts,tsx,mjs,cjs,py,rs,go,java,kt,kts,json,toml,xml,gradle,sh,bash,zsh,ps1,yml,yaml,txt}", exclude, 500),
    vscode.workspace.findFiles("**/{Dockerfile,dockerfile}", exclude, 500)
  ]);
  const files = [...new Map([...extensionFiles, ...dockerfiles].map((uri) => [uri.toString(), uri])).values()];

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
  clearAllTimers(remotePackageTimers);
  findingsByUri.clear();
  performanceByUri.clear();
  diagnostics.clear();
  findingsProvider.refresh();
  popupSeenByUri.clear();
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
    prompt: provider === "vibeguard" ? "Enter VibeGuard Pro credential" : `Enter ${provider} API key for VibeGuard L3 analysis`,
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

async function showSubscriptionStatus(): Promise<void> {
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  const provider = configuredLlmProvider(loadedConfig.config);
  if (provider !== "vibeguard") {
    void vscode.window.showInformationMessage("Select the VibeGuard LLM provider to view Pro subscription usage.");
    return;
  }
  const apiKey = (await extensionContext.secrets.get(llmSecretKey(provider))) ?? getLlmApiKeyFromEnv(provider);
  try {
    const status = await getProSubscriptionStatus({ apiKey });
    output.appendLine("Pro Subscription Status");
    output.appendLine("=======================");
    output.appendLine(`Plan: ${status.plan}`);
    output.appendLine(`State: ${status.state}`);
    output.appendLine(`Active: ${status.active ? "yes" : "no"}`);
    output.appendLine(`Features: ${status.features.length > 0 ? status.features.join(", ") : "none"}`);
    if (status.l3Requests) {
      output.appendLine(`Official L3 requests: ${status.l3Requests.used}/${status.l3Requests.limit}`);
      if (status.l3Requests.resetAt) {
        output.appendLine(`Resets: ${status.l3Requests.resetAt}`);
      }
    }
    if (status.reason === "missing_credential") {
      output.appendLine("Credential: missing");
    }
    output.appendLine("");
    output.show();
  } catch (error) {
    output.appendLine(`Pro subscription status error: ${error instanceof Error ? error.message : String(error)}`);
    output.show();
    void vscode.window.showErrorMessage("VibeGuard could not retrieve the Pro subscription status.");
  }
}

async function maybeShowFirstRunOnboarding(): Promise<void> {
  if (extensionContext.globalState.get<boolean>(firstRunOnboardingKey, false)) {
    return;
  }
  await extensionContext.globalState.update(firstRunOnboardingKey, true);
  output.appendLine(
    "VibeGuard first run: L1 secret/config/AI-pattern checks are active now. Package-name cache sync runs in the background for hallucinated-package detection."
  );
  const choice = await vscode.window.showInformationMessage(
    "VibeGuard is active. Secret, config, and AI-pattern checks work immediately; package-name cache sync prepares hallucinated-package detection in the background.",
    "Sync Now",
    "Settings"
  );
  if (choice === "Sync Now") {
    await syncPackageCache(true);
  } else if (choice === "Settings") {
    await vscode.commands.executeCommand("workbench.action.openSettings", "vibeguard");
  }
}

async function openFinding(finding: Finding): Promise<void> {
  const uri = vscode.Uri.file(finding.file);
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document);
  const range = findingRange(finding);
  editor.selection = new vscode.Selection(range.start, range.end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

async function showFindingDetails(finding: Finding): Promise<void> {
  await openFinding(finding);
  output.appendLine("Finding Details");
  output.appendLine("===============");
  output.appendLine(`${finding.severity.toUpperCase()} ${finding.file}:${finding.line}:${finding.column}`);
  output.appendLine(`Rule: ${finding.detection_rule} (${finding.detection_layer})`);
  output.appendLine(`Message: ${finding.message}`);
  output.appendLine(`Evidence: ${finding.evidence}`);
  if (finding.suggestion) {
    output.appendLine(`Suggestion: ${finding.suggestion}`);
  }
  if (finding.fix) {
    output.appendLine(`Available fix: ${finding.fix.description}`);
  }
  output.appendLine("");
  output.show(true);
}

interface ScheduleScanOptions {
  includeL2: boolean;
  includeL3: boolean;
  scheduleL2?: boolean;
  scheduleL3?: boolean;
  cancelPendingL2?: boolean;
  cancelPendingL3?: boolean;
  cancelPendingRemote?: boolean;
  deferRemotePackageVerification?: boolean;
  scheduleRemotePackageVerification?: boolean;
  replaceAll?: boolean;
}

function scheduleRealtimeScan(document: vscode.TextDocument, delayMs: number): void {
  scheduleScan(document, delayMs, {
    includeL2: false,
    includeL3: false,
    scheduleL2: true,
    scheduleL3: true,
    cancelPendingRemote: true,
    deferRemotePackageVerification: true,
    scheduleRemotePackageVerification: true
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
  if (options.cancelPendingRemote) {
    clearTimer(remotePackageTimers, key);
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
        deferRemotePackageVerification: options.deferRemotePackageVerification,
        scheduleRemotePackageVerification: options.scheduleRemotePackageVerification,
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
      void scanDocument(document, {
        includeL2: true,
        includeL3: false,
        deferRemotePackageVerification: true,
        scheduleRemotePackageVerification: true
      });
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
      void scanDocument(document, {
        includeL2: true,
        includeL3: true,
        deferRemotePackageVerification: true,
        scheduleRemotePackageVerification: true,
        replaceAll: true
      });
    }, delayMs)
  );
}

function scheduleRemotePackageVerification(document: vscode.TextDocument): void {
  const key = document.uri.toString();
  clearTimer(remotePackageTimers, key);
  remotePackageTimers.set(
    key,
    setTimeout(() => {
      remotePackageTimers.delete(key);
      void scanDocument(document, { includeL2: false, includeL3: false, packageVerification: "remote" });
    }, realtimeRemoteVerificationDelayMs)
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

interface DocumentScanOptions {
  includeL2?: boolean;
  includeL3?: boolean;
  packageVerification?: "off" | "seed" | "remote";
  deferRemotePackageVerification?: boolean;
  scheduleRemotePackageVerification?: boolean;
  replaceAll?: boolean;
}

async function scanDocument(document: vscode.TextDocument, options: DocumentScanOptions = {}): Promise<void> {
  if (!isSupportedDocument(document)) {
    return;
  }
  const documentVersion = document.version;
  const scanStartedAt = Date.now();

  const loadedConfig = await loadConfiguredVibeGuardConfig(document);
  const enabled = configuredSettingOr("enabled", loadedConfig.config.enabled);
  if (!enabled) {
    findingsByUri.delete(document.uri.toString());
    performanceByUri.delete(document.uri.toString());
    popupSeenByUri.delete(document.uri.toString());
    diagnostics.delete(document.uri);
    findingsProvider.refresh();
    updateStatus();
    return;
  }

  const configuredPackageVerification = configuredSettingOr<"off" | "seed" | "remote">(
    "packageVerification",
    loadedConfig.config.package_verification
  );
  const requestedPackageVerification = options.packageVerification ?? configuredPackageVerification;
  const deferRemotePackageVerification =
    options.deferRemotePackageVerification === true && requestedPackageVerification === "remote";
  const packageVerification = deferRemotePackageVerification ? "seed" : requestedPackageVerification;
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

  if (document.version !== documentVersion) {
    return;
  }

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
  if (deferRemotePackageVerification && options.scheduleRemotePackageVerification && executedLayers.l1) {
    scheduleRemotePackageVerification(document);
  }
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
  const popupSeen = activeCriticalPopupIds(document.uri.toString(), findings);
  if (!configuration().get<boolean>("showCriticalPopups", true)) {
    return;
  }
  const critical = findings.find((finding) => finding.severity === "critical" && !finding.dismissed && !popupSeen.has(finding.id));
  if (!critical) {
    return;
  }
  popupSeen.add(critical.id);
  const replace = critical.detection_layer === "L3" ? undefined : critical.fix?.description;
  const chooseReplacement =
    critical.type === "hallucinated_package" && allEditorFixesForFinding(critical).length > 1
      ? "Choose replacement"
      : undefined;
  const actions = [replace, chooseReplacement, "Ignore", "Learn More", "Manage Ignore Rules"].filter(
    (action): action is string => action !== undefined
  );
  void vscode.window.showWarningMessage(criticalAlertMessage(critical), ...actions).then(async (choice) => {
    if (choice === replace && critical.fix) {
      await applyFindingFix(critical);
    } else if (choice === chooseReplacement) {
      await pickPackageReplacement(critical);
    } else if (choice === "Ignore") {
      await ignoreFinding(critical, "line");
      await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
    } else if (choice === "Learn More") {
      await showFindingDetails(critical);
    } else if (choice === "Manage Ignore Rules") {
      await openIgnoreRules();
    }
  });
}

function activeCriticalPopupIds(documentUri: string, findings: Finding[]): Set<string> {
  const activeIds = new Set(
    findings
      .filter((finding) => finding.severity === "critical" && !finding.dismissed)
      .map((finding) => finding.id)
  );
  const seen = popupSeenByUri.get(documentUri) ?? new Set<string>();
  for (const findingId of seen) {
    if (!activeIds.has(findingId)) {
      seen.delete(findingId);
    }
  }
  if (seen.size > 0 || activeIds.size > 0) {
    popupSeenByUri.set(documentUri, seen);
  } else {
    popupSeenByUri.delete(documentUri);
  }
  return seen;
}

async function applyFindingFix(finding: Finding | undefined): Promise<void> {
  if (!finding?.fix) {
    return;
  }
  await applyFindingCodeFix(finding, finding.fix);
}

async function applyFindingFixFromSidebar(finding: Finding | undefined): Promise<void> {
  if (!finding?.fix || finding.dismissed) {
    return;
  }
  if (finding.type === "hallucinated_package" && allEditorFixesForFinding(finding).length > 1) {
    await pickPackageReplacement(finding);
    return;
  }
  await applyFindingFix(finding);
}

async function pickPackageReplacement(finding: Finding): Promise<void> {
  const fixes = allEditorFixesForFinding(finding);
  if (fixes.length < 2) {
    await applyFindingFix(finding);
    return;
  }
  const selected = await vscode.window.showQuickPick(
    fixes.map((fix, index) => ({
      label: fix.description,
      detail: `Replace with: ${truncateInline(fix.edits[0]?.newText ?? "", 180)}`,
      picked: index === 0,
      fix
    })),
    {
      title: "Choose VibeGuard package replacement",
      placeHolder: "Select a verified package replacement"
    }
  );
  if (selected) {
    await applyFindingCodeFix(finding, selected.fix);
  }
}

async function applyFindingCodeFix(finding: Finding, fix: CodeFix): Promise<void> {
  const uri = vscode.Uri.file(finding.file);
  const document = await vscode.workspace.openTextDocument(uri);
  if (!findingFixStillMatchesDocument(document, finding, fix)) {
    void vscode.window.showWarningMessage("VibeGuard did not apply this fix because the code changed after it was scanned.");
    return;
  }
  if (finding.detection_layer === "L3") {
    const choice = await vscode.window.showWarningMessage(
      "VibeGuard received this replacement from an LLM. Review the change before applying it.",
      "Apply replacement"
    );
    if (choice !== "Apply replacement") {
      return;
    }
  }
  const applied = await vscode.workspace.applyEdit(workspaceEditForEdits(uri, fix.edits));
  if (!applied) {
    void vscode.window.showErrorMessage("VibeGuard could not apply this fix.");
    return;
  }
  const updatedDocument = await vscode.workspace.openTextDocument(uri);
  await scanDocument(updatedDocument, { includeL2: true, includeL3: true, replaceAll: true });
}

async function applyAllSafeFixes(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage("VibeGuard: no active editor to fix.");
    return;
  }
  const plan = planSafeBatchFixes(findingsForDocument(editor.document));
  if (plan.findings.length === 0) {
    void vscode.window.showInformationMessage("VibeGuard: no non-overlapping mechanical fixes are available in this file.");
    return;
  }
  const detail = [
    `${plan.findings.length} safe fix${plan.findings.length === 1 ? "" : "es"} will be applied.`,
    plan.skipped.length > 0 ? `${plan.skipped.length} overlapping fix${plan.skipped.length === 1 ? "" : "es"} will be skipped.` : "",
    plan.excludedL3.length > 0 ? `${plan.excludedL3.length} LLM-generated replacement${plan.excludedL3.length === 1 ? " is" : "s are"} excluded for review.` : ""
  ].filter(Boolean).join(" ");
  const choice = await vscode.window.showWarningMessage(`VibeGuard: ${detail}`, "Apply safe fixes");
  if (choice !== "Apply safe fixes") {
    return;
  }
  const applied = await vscode.workspace.applyEdit(workspaceEditForFindings(editor.document.uri, plan.findings));
  if (!applied) {
    void vscode.window.showErrorMessage("VibeGuard could not apply all selected fixes.");
    return;
  }
  const document = await vscode.workspace.openTextDocument(editor.document.uri);
  await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
}

async function applyAllProFixes(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage("VibeGuard: no active editor to fix.");
    return;
  }
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  if (configuredLlmProvider(loadedConfig.config) !== "vibeguard") {
    void vscode.window.showWarningMessage("VibeGuard Pro batch fixes require the VibeGuard LLM provider.");
    return;
  }
  const proCredential =
    (await extensionContext.secrets.get(llmSecretKey("vibeguard"))) ?? getLlmApiKeyFromEnv("vibeguard");
  if (!proCredential) {
    void vscode.window.showWarningMessage("Set a VibeGuard Pro credential before applying Pro batch fixes.");
    return;
  }

  const plan = planProBatchFixes(findingsForDocument(editor.document));
  const currentL3Findings = plan.reviewableL3Findings.filter((finding) => l3FixStillMatchesDocument(editor.document, finding));
  const staleL3Count = plan.reviewableL3Findings.length - currentL3Findings.length;
  if (plan.safeFindings.length === 0 && currentL3Findings.length === 0) {
    void vscode.window.showInformationMessage("VibeGuard: no current non-overlapping fixes are available in this file.");
    return;
  }

  const reviewed = currentL3Findings.length > 0 ? await pickReviewedL3Fixes(currentL3Findings) : [];
  if (currentL3Findings.length > 0 && !reviewed) {
    return;
  }
  const selectedL3 = (reviewed ?? []).filter((finding) => l3FixStillMatchesDocument(editor.document, finding));
  const selected = [...plan.safeFindings, ...selectedL3];
  if (selected.length === 0) {
    return;
  }

  const detail = [
    `${plan.safeFindings.length} safe fix${plan.safeFindings.length === 1 ? "" : "es"}.`,
    `${selectedL3.length} reviewed LLM replacement${selectedL3.length === 1 ? "" : "s"}.`,
    plan.skipped.length > 0 ? `${plan.skipped.length} overlapping fix${plan.skipped.length === 1 ? "" : "es"} skipped.` : "",
    staleL3Count > 0 ? `${staleL3Count} stale LLM replacement${staleL3Count === 1 ? "" : "s"} excluded.` : ""
  ]
    .filter(Boolean)
    .join(" ");
  const choice = await vscode.window.showWarningMessage(`VibeGuard Pro: ${detail}`, "Apply reviewed fixes");
  if (choice !== "Apply reviewed fixes") {
    return;
  }
  const applied = await vscode.workspace.applyEdit(workspaceEditForFindings(editor.document.uri, selected));
  if (!applied) {
    void vscode.window.showErrorMessage("VibeGuard could not apply all selected Pro fixes.");
    return;
  }
  const document = await vscode.workspace.openTextDocument(editor.document.uri);
  await scanDocument(document, { includeL2: true, includeL3: true, replaceAll: true });
}

async function pickReviewedL3Fixes(findings: Finding[]): Promise<Finding[] | undefined> {
  const selected = await vscode.window.showQuickPick(
    findings.map((finding) => ({
      label: `Line ${finding.line}: ${finding.fix?.description ?? "LLM replacement"}`,
      description: truncateInline(finding.evidence, 100),
      detail: `Replace with: ${truncateInline(finding.fix?.edits[0]?.newText ?? "", 180)}`,
      picked: true,
      finding
    })),
    {
      canPickMany: true,
      title: "Review VibeGuard Pro LLM Fixes",
      placeHolder: "Select the reviewed LLM replacements to apply"
    }
  );
  return selected?.map((item) => item.finding);
}

function updateStatus(): void {
  if (packageSyncInFlight) {
    updatePackageSyncStatus();
    return;
  }
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

function updatePackageSyncStatus(): void {
  const progress = packageSyncProgress;
  const completed = progress?.completed ?? 0;
  const total = progress?.total ?? 0;
  const percent = total === 0 ? 0 : Math.round((completed / total) * 100);
  const registry = progress?.registry ? ` (${progress.registry})` : "";
  const tier = packageSyncTier === "full" ? "Tier 2 full index" : "Tier 1 quick index";
  statusBar.text = `$(sync~spin) VibeGuard: package sync ${percent}% (${tier})`;
  statusBar.tooltip = total === 0
    ? `VibeGuard package name cache is preparing ${tier}`
    : `VibeGuard package name cache (${tier}): ${completed}/${total} registries complete${registry}`;
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

function workspaceEditForEdits(uri: vscode.Uri, textEdits: CodeFix["edits"]): vscode.WorkspaceEdit {
  const edit = new vscode.WorkspaceEdit();
  for (const textEdit of textEdits) {
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

function workspaceEditForFindings(uri: vscode.Uri, findings: Finding[]): vscode.WorkspaceEdit {
  const edit = new vscode.WorkspaceEdit();
  for (const finding of findings) {
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
  }
  return edit;
}

function l3FixStillMatchesDocument(document: vscode.TextDocument, finding: Finding): boolean {
  if (finding.detection_layer !== "L3" || finding.fix?.edits.length !== 1) {
    return false;
  }
  const edit = finding.fix.edits[0];
  try {
    const range = new vscode.Range(edit.startLine - 1, edit.startColumn - 1, edit.endLine - 1, edit.endColumn - 1);
    return document.getText(range) === finding.evidence;
  } catch {
    return false;
  }
}

function findingFixStillMatchesDocument(document: vscode.TextDocument, finding: Finding, fix: CodeFix): boolean {
  if (finding.type === "hardcoded_secret") {
    return redactedSecretFixStillMatchesSource(finding, fix, document.getText());
  }
  if (finding.detection_layer === "L3") {
    return finding.fix === fix && l3FixStillMatchesDocument(document, finding);
  }
  try {
    return document.getText(findingRange(finding)) === finding.evidence;
  } catch {
    return false;
  }
}

function truncateInline(value: string, maximumLength: number): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= maximumLength ? normalized : `${normalized.slice(0, Math.max(1, maximumLength - 3))}...`;
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
  void reportIgnoredFalsePositive(finding, scope, reason);
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
  void reportIgnoredFalsePositive(finding, "package", reason);
  await refreshOpenDocuments();
  void vscode.window.showInformationMessage(`VibeGuard will ignore package "${finding.evidence}".`);
}

async function reportIgnoredFalsePositive(
  finding: Finding,
  scope: "line" | "file" | "global" | "package",
  reason: string | undefined
): Promise<void> {
  if (!isFalsePositiveDismissalReason(reason)) {
    return;
  }
  const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
  const delivery = await reportFalsePositiveTelemetry({
    enabled: loadedConfig.config.telemetry,
    event: falsePositiveTelemetryEvent(finding, "vscode", scope)
  });
  if (loadedConfig.config.telemetry && !delivery.sent) {
    output.appendLine("Anonymous false-positive feedback was not delivered; the ignore rule was saved locally.");
  }
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
  packageSyncProgress = undefined;
  packageSyncTier = undefined;
  updatePackageSyncStatus();
  try {
    const loadedConfig = await loadConfiguredVibeGuardConfigForWorkspace();
    const configured = applyPackageCacheSettings(loadedConfig.config);
    const detectedRegistries = manual ? [] : await detectWorkspacePackageRegistries();
    const selectedRegistries = selectConfiguredPackageSyncRegistries(
      configured.package_cache.languages,
      detectedRegistries
    );
    const syncConfig = withPackageCacheLanguages(configured, selectedRegistries);
    const staged = await syncConfiguredPackageIndexesInBackground({
      config: syncConfig,
      storage: packageStorage,
      force: manual,
      upgradeFull: !manual,
      continueOnError: true,
      onTierStart: (tier) => {
        packageSyncTier = tier;
        packageSyncProgress = undefined;
        updatePackageSyncStatus();
      },
      onProgress: (_tier, progress) => {
        packageSyncProgress = progress;
        updatePackageSyncStatus();
      },
      onTierComplete: async (tier, result) => {
        output.appendLine(`Package cache ${tier === "full" ? "Tier 2 full" : "Tier 1 quick"} sync completed.`);
        logPackageSyncResult(result, loadedConfig.path, loadedConfig.exists, detectedRegistries);
        if (result.results.some((entry) => entry.status === "synced")) {
          await refreshOpenDocuments();
        }
      }
    });

    const outcomes = staged.tiers.flatMap((entry) => entry.result.results);
    const syncedCount = outcomes.filter((entry) => entry.status === "synced").length;
    const failedCount = outcomes.filter((entry) => entry.status === "failed").length;
    if (manual) {
      const skippedCount = outcomes.filter((entry) => entry.status === "skipped").length;
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
    packageSyncProgress = undefined;
    packageSyncTier = undefined;
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
    // The Pro credential must never be redirected by untrusted workspace settings.
    baseUrl: provider === "vibeguard" ? undefined : configuredOptionalString("llmBaseUrl")
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
      lightweight_mode: configuredSettingOr("packageCacheLightweightMode", config.package_cache.lightweight_mode),
      background_full_sync: configuredSettingOr(
        "packageCacheBackgroundFullSync",
        config.package_cache.background_full_sync
      )
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
  const checks: Array<[PackageRegistry, string[]]> = [
    ["npm", ["**/package.json"]],
    ["pypi", ["**/pyproject.toml", "**/requirements*.txt", "**/requirements/**/*.txt"]],
    ["cargo", ["**/Cargo.toml"]],
    ["gomod", ["**/go.mod"]],
    ["maven", ["**/{pom.xml,build.gradle,build.gradle.kts}", "**/*.versions.toml"]]
  ];
  const found = await Promise.all(
    checks.map(async ([registry, globs]) => ({
      registry,
      matches: await Promise.all(
        globs.map((glob) => vscode.workspace.findFiles(glob, "**/{node_modules,.git,out,dist,build,coverage,.vscode-test}/**", 1))
      )
    }))
  );
  return found.filter((entry) => entry.matches.some((matches) => matches.length > 0)).map((entry) => entry.registry);
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
      if (entry.incremental) {
        output.appendLine(
          `${entry.registry}: applied ${entry.additions ?? 0} addition(s) and ${entry.removals ?? 0} removal(s) from ${entry.changesFetched ?? 0} incremental change(s), ${entry.coverage ?? "partial"} coverage (${entry.reason})`
        );
      } else {
        output.appendLine(
          `${entry.registry}: synced ${entry.imported ?? 0} package name(s), ${entry.coverage ?? "partial"} coverage (${entry.reason})`
        );
      }
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
  return (
    isRequirementsManifestPath(document.fileName) ||
    /(?:package\.json|pyproject\.toml|cargo\.toml|go\.mod|pom\.xml|build\.gradle|build\.gradle\.kts|dockerfile)$/i.test(document.fileName)
  );
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
    item.contextValue = element.finding.fix && !element.finding.dismissed ? "vibeguardFindingFixable" : "vibeguardFinding";
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

      for (const [index, fix] of allEditorFixesForFinding(finding).entries()) {
        const action = new vscode.CodeAction(`Apply VibeGuard fix: ${fix.description}`, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = index === 0 && finding.detection_layer !== "L3";
        if (finding.detection_layer === "L3") {
          action.command = {
            command: "vibeguard.applyFix",
            title: action.title,
            arguments: [finding]
          };
        } else {
          action.edit = workspaceEditForEdits(document.uri, fix.edits);
        }
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

function allEditorFixesForFinding(finding: Finding): CodeFix[] {
  if (!finding.fix) {
    return [];
  }
  // L3 replacements need explicit confirmation and therefore never receive alternatives here.
  return finding.detection_layer === "L3" ? [finding.fix] : [finding.fix, ...(finding.alternativeFixes ?? [])];
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
