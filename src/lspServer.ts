#!/usr/bin/env node
import fs from "fs/promises";
import path from "path";
import { fileURLToPath, pathToFileURL } from "url";
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
  type ExecuteCommandParams,
  type InitializeParams,
  type InitializeResult,
  type WorkDoneProgressReporter
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { cloneDefaultConfig, defaultConfigPath, loadConfig } from "./config";
import { criticalAlertMessage } from "./criticalAlert";
import { loadCustomRules } from "./customRules";
import { redactedSecretFixStillMatchesSource } from "./fixValidation";
import { appendIgnoreRule, defaultIgnoreRulesPath, ensureIgnoreRulesFile, loadIgnoreRules, scopedIgnoreReason } from "./ignore";
import { readStoredLlmCredential } from "./l3/credentials";
import { getLlmApiKeyFromEnv, LlmSemanticAnalyzer, type LlmProvider } from "./l3/llm";
import { mergeFindingsForExecutedLayers, type ExecutedLayers } from "./layers";
import {
  createCodeActionsForFindings,
  lspApplyFixCommand,
  lspApplyL3FixCommand,
  lspIgnoreFindingCommand,
  type LspApplyFixCommandArgument,
  type LspApplyL3FixCommandArgument,
  type LspIgnoreFindingCommandArgument,
  type LspIgnoreScope
} from "./lspActions";
import {
  selectConfiguredPackageSyncRegistries,
  shouldUpgradePackageCacheInBackground,
  syncConfiguredPackageIndexesInBackground,
  type PackageCacheSyncTier
} from "./package/configSync";
import { PackageVerifier } from "./package/packageVerifier";
import { createPackageStorage } from "./package/storage";
import { scanSourceFile } from "./scanner";
import type { CodeFix, Finding, PackageRegistry, Severity, VibeGuardConfig } from "./types";

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
  autoSyncPackageCache: boolean;
  showCriticalPopups?: boolean;
  configPath?: string;
  packageCacheLanguages?: PackageRegistry[];
  packageCacheUpdateInterval?: VibeGuardConfig["package_cache"]["update_interval"];
  packageCacheLightweightMode?: boolean;
  packageCacheBackgroundFullSync?: boolean;
}

const defaultSettings: LspSettings = {
  enabled: true,
  packageVerification: "remote",
  enableL2: true,
  enableL3: false,
  llmProvider: "deepseek",
  autoSyncPackageCache: true,
  showCriticalPopups: true,
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
const criticalPopupSeen = new Set<string>();
let workspaceRoots: string[] = [];
let packageSyncInFlight = false;
let packageSyncQueued = false;
let clientSupportsWorkDoneProgress = false;
let clientSupportsShowDocument = false;
const storedLlmCredentialPromises = new Map<LlmProvider, Promise<string | undefined>>();

connection.onInitialize((params: InitializeParams): InitializeResult => {
  setWorkspaceRoots(params);
  clientSupportsWorkDoneProgress = params.capabilities.window?.workDoneProgress === true;
  clientSupportsShowDocument = params.capabilities.window?.showDocument?.support === true;
  applySettings(readInitialSettings(params.initializationOptions), true);
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      codeActionProvider: {
        codeActionKinds: [CodeActionKind.QuickFix]
      },
      executeCommandProvider: {
        commands: [lspIgnoreFindingCommand, lspApplyFixCommand, lspApplyL3FixCommand]
      }
    },
    serverInfo: {
      name: "VibeGuard LSP",
      version: "0.1.0"
    }
  };
});

connection.onInitialized(() => {
  queuePackageCacheSync();
});

connection.onDidChangeConfiguration((change) => {
  applySettings(readVibeGuardSettings(change.settings));
  queuePackageCacheSync();
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

connection.onExecuteCommand(async (params: ExecuteCommandParams): Promise<void> => {
  if (params.command === lspIgnoreFindingCommand) {
    await executeLspIgnoreFinding(params.arguments?.[0]);
    return;
  }
  if (params.command === lspApplyFixCommand) {
    await executeLspFix(params.arguments?.[0]);
    return;
  }
  if (params.command === lspApplyL3FixCommand) {
    await executeLspL3Fix(params.arguments?.[0]);
  }
});

async function executeLspIgnoreFinding(value: unknown): Promise<void> {
  const argument = parseLspIgnoreCommandArgument(value);
  if (!argument) {
    connection.console.warn("VibeGuard ignore command was missing a valid finding ID and scope.");
    return;
  }
  const finding = findCurrentFinding(argument.findingId);
  if (!finding) {
    connection.console.warn("VibeGuard ignore command referred to a finding that is no longer active.");
    return;
  }
  if (argument.scope === "package" && finding.type !== "hallucinated_package") {
    connection.console.warn("VibeGuard package ignore command can only be applied to package findings.");
    return;
  }

  const saved = await saveLspIgnoreRule(finding, argument.scope, "Ignored from LSP quick fix");
  if (!saved) {
    return;
  }
  connection.console.info(`VibeGuard saved ${argument.scope} ignore rule for ${finding.detection_rule}.`);
  refreshOpenDocuments();
}

async function executeLspL3Fix(value: unknown): Promise<void> {
  const argument = parseLspApplyL3FixCommandArgument(value);
  if (!argument) {
    connection.console.warn("VibeGuard L3 fix command was missing a valid finding ID and document URI.");
    return;
  }
  const finding = findCurrentFindingInDocument(argument.uri, argument.findingId);
  const document = documents.get(argument.uri);
  if (!finding || !document || finding.detection_layer !== "L3" || !finding.fix) {
    connection.console.warn("VibeGuard L3 fix command referred to a finding that is no longer active.");
    return;
  }
  if (!lspFixStillMatchesDocument(document, finding, finding.fix)) {
    connection.console.warn("VibeGuard did not apply the L3 fix because the document changed after it was scanned.");
    return;
  }
  const choice = await connection.window.showWarningMessage(
    "VibeGuard received this replacement from an LLM. Review the change before applying it.",
    { title: "Apply replacement" }
  );
  if (choice?.title !== "Apply replacement") {
    return;
  }
  const current = findCurrentFindingInDocument(argument.uri, argument.findingId);
  const currentDocument = documents.get(argument.uri);
  if (!current || !currentDocument || current.detection_layer !== "L3" || !current.fix) {
    return;
  }
  await applyLspFindingFix(argument.uri, current, current.fix, true);
}

async function executeLspFix(value: unknown): Promise<void> {
  const argument = parseLspApplyFixCommandArgument(value);
  if (!argument) {
    connection.console.warn("VibeGuard fix command was missing a valid finding ID, document URI, or fix index.");
    return;
  }
  const finding = findCurrentFindingInDocument(argument.uri, argument.findingId);
  if (!finding || finding.detection_layer === "L3") {
    connection.console.warn("VibeGuard fix command referred to a finding that is no longer safe to apply.");
    return;
  }
  const fix = lspFixesForFinding(finding)[argument.fixIndex];
  if (!fix) {
    connection.console.warn("VibeGuard fix command referred to an unavailable replacement.");
    return;
  }
  await applyLspFindingFix(argument.uri, finding, fix);
}

interface LspValidationOptions {
  layers: ExecutedLayers;
  packageVerification?: LspSettings["packageVerification"];
  replaceAll?: boolean;
}

interface LspCriticalPopupAction {
  title: string;
  kind: "fix" | "ignore" | "manage";
  scope: LspIgnoreScope | "";
  [key: string]: string | boolean | number | object;
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

function applySettings(incoming: Partial<LspSettings>, reset = false): void {
  settings = {
    ...(reset ? defaultSettings : settings),
    ...incoming
  };
  storedLlmCredentialPromises.clear();
}

function readInitialSettings(value: unknown): Partial<LspSettings> {
  return readVibeGuardSettings(value);
}

function readVibeGuardSettings(value: unknown): Partial<LspSettings> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const source = value as Record<string, unknown>;
  const nested = source.vibeguard;
  if (nested && typeof nested === "object" && !Array.isArray(nested)) {
    return nested as Partial<LspSettings>;
  }
  return source as Partial<LspSettings>;
}

function setWorkspaceRoots(params: InitializeParams): void {
  const folders = params.workspaceFolders?.map((folder) => folder.uri) ?? [];
  if (folders.length === 0 && params.rootUri) {
    folders.push(params.rootUri);
  }
  workspaceRoots = [...new Set(folders.map(filePathFromUri))];
}

function queuePackageCacheSync(): void {
  if (settings.autoSyncPackageCache !== true) {
    packageSyncQueued = false;
    return;
  }
  packageSyncQueued = true;
  if (packageSyncInFlight) {
    return;
  }
  queueMicrotask(() => {
    void syncPackageCacheInBackground();
  });
}

async function syncPackageCacheInBackground(): Promise<void> {
  if (packageSyncInFlight || !packageSyncQueued || settings.autoSyncPackageCache !== true) {
    return;
  }
  packageSyncQueued = false;
  packageSyncInFlight = true;
  let workDoneProgress: WorkDoneProgressReporter | undefined;
  try {
    const loaded = await loadLspConfig();
    const configured = applyLspPackageCacheSettings(loaded.config);
    const detectedRegistries = await detectWorkspacePackageRegistries();
    const selectedRegistries = selectConfiguredPackageSyncRegistries(
      configured.package_cache.languages,
      detectedRegistries
    );
    const syncConfig = withPackageCacheLanguages(configured, selectedRegistries);
    const willUpgradeFullIndex = shouldUpgradePackageCacheInBackground(syncConfig);
    workDoneProgress = await createPackageCacheProgress(selectedRegistries);
    connection.console.info(
      `VibeGuard package cache sync started: ${selectedRegistries.length > 0 ? selectedRegistries.join(", ") : "no registries"}.`
    );
    const staged = await syncConfiguredPackageIndexesInBackground({
      config: syncConfig,
      storage,
      upgradeFull: true,
      continueOnError: true,
      onTierStart: (tier) => {
        const percentage = tier === "full" && willUpgradeFullIndex ? 50 : 0;
        connection.console.info(`VibeGuard package cache ${packageCacheTierLabel(tier)} started.`);
        workDoneProgress?.report(percentage, `${packageCacheTierLabel(tier)} started`);
      },
      onProgress: (tier, progress) => {
        const percentage = packageSyncTierPercentage(tier, progress.completed, progress.total, willUpgradeFullIndex);
        if (progress.phase === "starting") {
          connection.console.info(
            `VibeGuard package cache ${packageCacheTierLabel(tier)}: ${progress.registry} (${progress.completed + 1}/${progress.total}).`
          );
          workDoneProgress?.report(
            percentage,
            `${packageCacheTierLabel(tier)}: syncing ${progress.registry} package names`
          );
        } else {
          workDoneProgress?.report(
            percentage,
            `${packageCacheTierLabel(tier)}: ${progress.registry} ${progress.status ?? "completed"}`
          );
        }
      },
      onTierComplete: (tier, result) => {
        const synced = result.results.filter((entry) => entry.status === "synced").length;
        connection.console.info(`VibeGuard package cache ${packageCacheTierLabel(tier)} finished: ${synced} synced.`);
        if (synced > 0) {
          refreshOpenDocumentsAfterPackageSync();
        }
      }
    });
    const outcomes = staged.tiers.flatMap((entry) => entry.result.results);
    const syncedCount = outcomes.filter((entry) => entry.status === "synced").length;
    const failedCount = outcomes.filter((entry) => entry.status === "failed").length;
    connection.console.info(
      `VibeGuard package cache sync finished: ${syncedCount} synced, ${outcomes.length - syncedCount - failedCount} skipped, ${failedCount} failed.`
    );
    workDoneProgress?.report(
      100,
      `Package cache ready: ${syncedCount} synced, ${outcomes.length - syncedCount - failedCount} skipped, ${failedCount} failed`
    );
    if (failedCount > 0 && syncedCount === 0) {
      connection.console.warn(
        "VibeGuard package cache sync did not complete; package checks will keep using the existing local cache and seed catalog."
      );
    }
  } catch (error) {
    workDoneProgress?.report(100, "Package cache sync failed");
    connection.console.warn(`VibeGuard package cache sync error: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    workDoneProgress?.done();
    packageSyncInFlight = false;
    if (packageSyncQueued && settings.autoSyncPackageCache === true) {
      queueMicrotask(() => {
        void syncPackageCacheInBackground();
      });
    }
  }
}

async function createPackageCacheProgress(registries: PackageRegistry[]): Promise<WorkDoneProgressReporter | undefined> {
  if (!clientSupportsWorkDoneProgress) {
    return undefined;
  }
  try {
    const progress = await connection.window.createWorkDoneProgress();
    progress.begin(
      "VibeGuard package cache",
      0,
      registries.length > 0 ? `Preparing ${registries.length} package registry${registries.length === 1 ? "" : "ies"}` : "Preparing",
      false
    );
    return progress;
  } catch (error) {
    connection.console.warn(
      `VibeGuard package cache progress is unavailable: ${error instanceof Error ? error.message : String(error)}`
    );
    return undefined;
  }
}

function packageSyncTierPercentage(
  tier: PackageCacheSyncTier,
  completed: number,
  total: number,
  willUpgradeFullIndex: boolean
): number {
  const percentage = total <= 0 ? 100 : Math.max(0, Math.min(100, Math.round((completed / total) * 100)));
  if (!willUpgradeFullIndex) {
    return percentage;
  }
  return tier === "lightweight" ? Math.round(percentage / 2) : 50 + Math.round(percentage / 2);
}

function packageCacheTierLabel(tier: PackageCacheSyncTier): string {
  return tier === "full" ? "Tier 2 full index" : "Tier 1 quick index";
}

async function loadLspConfig(): Promise<{ config: VibeGuardConfig; path: string; exists: boolean }> {
  const configuredPath = typeof settings.configPath === "string" ? settings.configPath.trim() : "";
  const configPath = configuredPath ? resolveLspConfigPath(configuredPath) : undefined;
  try {
    const loaded = await loadConfig(configPath);
    if (configuredPath && !loaded.exists) {
      connection.console.warn(`VibeGuard config file not found: ${loaded.path}`);
    }
    return loaded;
  } catch (error) {
    connection.console.warn(`VibeGuard config error: ${error instanceof Error ? error.message : String(error)}`);
    return {
      config: cloneDefaultConfig(),
      path: configPath ?? defaultConfigPath(),
      exists: false
    };
  }
}

function resolveLspConfigPath(value: string): string {
  const expanded = value === "~" ? process.env.HOME ?? process.env.USERPROFILE ?? value : value;
  if (path.isAbsolute(expanded) || value.startsWith("~/") || value.startsWith("~\\")) {
    return value;
  }
  return path.resolve(workspaceRoots[0] ?? process.cwd(), value);
}

function applyLspPackageCacheSettings(config: VibeGuardConfig): VibeGuardConfig {
  return {
    ...config,
    detection_layers: { ...config.detection_layers },
    custom_rules: [...config.custom_rules],
    ignored_findings: [...config.ignored_findings],
    package_cache: {
      languages: configuredPackageCacheLanguages(config.package_cache.languages),
      update_interval: configuredPackageCacheUpdateInterval(config.package_cache.update_interval),
      lightweight_mode:
        typeof settings.packageCacheLightweightMode === "boolean"
          ? settings.packageCacheLightweightMode
          : config.package_cache.lightweight_mode,
      background_full_sync:
        typeof settings.packageCacheBackgroundFullSync === "boolean"
          ? settings.packageCacheBackgroundFullSync
          : config.package_cache.background_full_sync
    }
  };
}

function configuredPackageCacheLanguages(fallback: PackageRegistry[]): PackageRegistry[] {
  if (!Array.isArray(settings.packageCacheLanguages)) {
    return [...fallback];
  }
  return [...new Set(settings.packageCacheLanguages.filter(isPackageRegistry))];
}

function configuredPackageCacheUpdateInterval(
  fallback: VibeGuardConfig["package_cache"]["update_interval"]
): VibeGuardConfig["package_cache"]["update_interval"] {
  const value = settings.packageCacheUpdateInterval;
  return value === "daily" || value === "weekly" ? value : fallback;
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

async function detectWorkspacePackageRegistries(): Promise<PackageRegistry[]> {
  const manifests: Array<[PackageRegistry, string[]]> = [
    ["npm", ["package.json"]],
    ["pypi", ["requirements.txt", "pyproject.toml"]],
    ["cargo", ["Cargo.toml"]],
    ["gomod", ["go.mod"]],
    ["maven", ["pom.xml", "build.gradle", "build.gradle.kts"]]
  ];
  const roots = workspaceRoots.length > 0 ? workspaceRoots : [process.cwd()];
  const detected = await Promise.all(
    manifests.map(async ([registry, files]) => {
      const candidates = roots.flatMap((root) => files.map((file) => path.join(root, file)));
      return (await Promise.all(candidates.map(fileExists))).some(Boolean) ? registry : undefined;
    })
  );
  return detected.filter(isPackageRegistry);
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function refreshOpenDocumentsAfterPackageSync(): void {
  const packageVerification = settings.packageVerification === "remote" ? "seed" : settings.packageVerification;
  for (const document of documents.all()) {
    const revision = documentRevisions.get(document.uri) ?? nextDocumentRevision(document.uri);
    void validateDocument(document, revision, {
      layers: { l1: true },
      packageVerification
    });
  }
}

function refreshOpenDocuments(): void {
  for (const document of documents.all()) {
    scheduleImmediateValidation(document, true);
  }
}

function isPackageRegistry(value: unknown): value is PackageRegistry {
  return value === "npm" || value === "pypi" || value === "cargo" || value === "gomod" || value === "maven";
}

function parseLspIgnoreCommandArgument(value: unknown): LspIgnoreFindingCommandArgument | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const argument = value as Record<string, unknown>;
  const findingId = typeof argument.findingId === "string" ? argument.findingId.trim() : "";
  const scope = argument.scope;
  if (!findingId || !isLspIgnoreScope(scope)) {
    return undefined;
  }
  return { findingId, scope };
}

function parseLspApplyL3FixCommandArgument(value: unknown): LspApplyL3FixCommandArgument | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const argument = value as Record<string, unknown>;
  const findingId = typeof argument.findingId === "string" ? argument.findingId.trim() : "";
  const uri = typeof argument.uri === "string" ? argument.uri.trim() : "";
  return findingId && uri ? { findingId, uri } : undefined;
}

function parseLspApplyFixCommandArgument(value: unknown): LspApplyFixCommandArgument | undefined {
  const base = parseLspApplyL3FixCommandArgument(value);
  if (!base || !value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const fixIndex = (value as Record<string, unknown>).fixIndex;
  if (typeof fixIndex !== "number" || !Number.isSafeInteger(fixIndex) || fixIndex < 0) {
    return undefined;
  }
  return { ...base, fixIndex };
}

function isLspIgnoreScope(value: unknown): value is LspIgnoreScope {
  return value === "line" || value === "file" || value === "global" || value === "package";
}

function findCurrentFinding(findingId: string): Finding | undefined {
  for (const findings of findingsByUri.values()) {
    const finding = findings.find((candidate) => candidate.id === findingId && !candidate.dismissed);
    if (finding) {
      return finding;
    }
  }
  return undefined;
}

function findCurrentFindingInDocument(uri: string, findingId: string): Finding | undefined {
  return findingsByUri.get(uri)?.find((finding) => finding.id === findingId && !finding.dismissed);
}

function lspFixesForFinding(finding: Finding): CodeFix[] {
  if (!finding.fix) {
    return [];
  }
  return finding.detection_layer === "L3" ? [finding.fix] : [finding.fix, ...(finding.alternativeFixes ?? [])];
}

async function saveLspIgnoreRule(finding: Finding, scope: LspIgnoreScope, reasonPrefix: string): Promise<boolean> {
  const ignoreRulesPath = settings.ignoreRulesPath?.trim() || defaultIgnoreRulesPath();
  const reason = scopedIgnoreReason(reasonPrefix, scope);
  try {
    if (scope === "package") {
      const registry = finding.detection_rule.replace(/^hallucinated_package_/, "");
      if (!isPackageRegistry(registry)) {
        connection.console.warn("VibeGuard package ignore command used an unsupported package registry.");
        return false;
      }
      await appendIgnoreRule(
        {
          package: finding.evidence,
          registry,
          reason
        },
        ignoreRulesPath
      );
      return true;
    }

    await appendIgnoreRule(
      {
        rule: finding.detection_rule,
        path: scope === "global" ? undefined : finding.file,
        line: scope === "line" ? finding.line : undefined,
        reason
      },
      ignoreRulesPath
    );
    return true;
  } catch (error) {
    connection.console.warn(
      `VibeGuard could not save ${scope} ignore rule: ${error instanceof Error ? error.message : String(error)}`
    );
    return false;
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
      l3Analyzer: layers.l3 ? await createLspL3Analyzer() : undefined,
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
  maybeShowCriticalPopup(document.uri, findings);
}

function maybeShowCriticalPopup(documentUri: string, findings: Finding[]): void {
  if (settings.showCriticalPopups === false) {
    return;
  }
  const critical = findings.find(
    (finding) => finding.severity === "critical" && !finding.dismissed && !criticalPopupSeen.has(finding.id)
  );
  if (!critical) {
    return;
  }

  criticalPopupSeen.add(critical.id);
  const actions = criticalPopupActions(critical);
  void connection.window
    .showWarningMessage(criticalAlertMessage(critical), ...actions)
    .then(async (response) => {
      const action = actions.find((candidate) => candidate.title === response?.title);
      if (!action) {
        return;
      }
      const current = findCurrentFinding(critical.id);
      if (!current) {
        return;
      }
      if (action.kind === "fix") {
        const fix = criticalPopupFixes(current).find((candidate) => criticalFixActionTitle(candidate) === action.title);
        if (!fix) {
          return;
        }
        await applyLspFindingFix(documentUri, current, fix);
        return;
      }
      if (action.kind === "manage") {
        await openLspIgnoreRules();
        return;
      }
      if (!action.scope || !(await saveLspIgnoreRule(current, action.scope, "Ignored from LSP critical alert"))) {
        return;
      }
      connection.console.info(`VibeGuard saved ${action.scope} ignore rule for ${current.detection_rule}.`);
      refreshOpenDocuments();
    })
    .catch((error) => {
      connection.console.warn(`VibeGuard critical alert is unavailable: ${error instanceof Error ? error.message : String(error)}`);
    });
}

function criticalPopupActions(finding: Finding): LspCriticalPopupAction[] {
  const actions: LspCriticalPopupAction[] = [];
  for (const fix of criticalPopupFixes(finding)) {
    actions.push({ title: criticalFixActionTitle(fix), kind: "fix", scope: "" });
  }
  actions.push(
    { title: "Ignore this VibeGuard finding", kind: "ignore", scope: "line" },
    { title: "Ignore this VibeGuard rule in this file", kind: "ignore", scope: "file" },
    { title: "Ignore this VibeGuard rule globally", kind: "ignore", scope: "global" }
  );
  if (finding.type === "hallucinated_package") {
    actions.push({ title: `Ignore package ${finding.evidence}`, kind: "ignore", scope: "package" });
  }
  if (clientSupportsShowDocument) {
    actions.push({ title: "Manage Ignore Rules", kind: "manage", scope: "" });
  }
  return actions;
}

function criticalPopupFixes(finding: Finding): CodeFix[] {
  if (!finding.fix || finding.detection_layer === "L3") {
    return [];
  }
  return [finding.fix, ...(finding.alternativeFixes ?? [])];
}

function criticalFixActionTitle(fix: CodeFix): string {
  return `Apply fix: ${fix.description}`;
}

async function applyLspFindingFix(
  documentUri: string,
  finding: Finding,
  fix: CodeFix,
  allowL3 = false
): Promise<void> {
  if (finding.detection_layer === "L3" && !allowL3) {
    return;
  }
  const document = documents.get(documentUri);
  if (!document || !lspFixStillMatchesDocument(document, finding, fix)) {
    connection.console.warn("VibeGuard did not apply the fix because the document changed after it was scanned.");
    return;
  }
  const result = await connection.workspace.applyEdit({
    changes: {
      [documentUri]: fix.edits.map((edit) => ({
        range: {
          start: {
            line: Math.max(0, edit.startLine - 1),
            character: Math.max(0, edit.startColumn - 1)
          },
          end: {
            line: Math.max(0, edit.endLine - 1),
            character: Math.max(0, edit.endColumn - 1)
          }
        },
        newText: edit.newText
      }))
    }
  });
  if (!result.applied) {
    connection.console.warn(`VibeGuard could not apply critical-finding fix: ${result.failureReason ?? "client rejected the edit"}`);
  }
}

function lspFixStillMatchesDocument(document: TextDocument, finding: Finding, fix: CodeFix): boolean {
  if (finding.type === "hardcoded_secret") {
    return redactedSecretFixStillMatchesSource(finding, fix, document.getText());
  }
  if (finding.detection_layer === "L3") {
    if (finding.fix !== fix || fix.edits.length !== 1) {
      return false;
    }
    const edit = fix.edits[0];
    try {
      return document.getText(toLspRange(edit)) === finding.evidence;
    } catch {
      return false;
    }
  }
  try {
    return document.getText(toLspFindingRange(finding)) === finding.evidence;
  } catch {
    return false;
  }
}

function toLspRange(edit: CodeFix["edits"][number]) {
  return {
    start: {
      line: Math.max(0, edit.startLine - 1),
      character: Math.max(0, edit.startColumn - 1)
    },
    end: {
      line: Math.max(0, edit.endLine - 1),
      character: Math.max(0, edit.endColumn - 1)
    }
  };
}

function toLspFindingRange(finding: Finding) {
  return {
    start: {
      line: Math.max(0, finding.line - 1),
      character: Math.max(0, finding.column - 1)
    },
    end: {
      line: Math.max(0, (finding.endLine ?? finding.line) - 1),
      character: Math.max(1, (finding.endColumn ?? finding.column + finding.evidence.length) - 1)
    }
  };
}

async function openLspIgnoreRules(): Promise<void> {
  if (!clientSupportsShowDocument) {
    connection.console.info("VibeGuard ignore rules are at the configured ignoreRulesPath; this LSP client cannot open documents.");
    return;
  }
  const filePath = await ensureIgnoreRulesFile(settings.ignoreRulesPath?.trim() || defaultIgnoreRulesPath());
  const result = await connection.window.showDocument({
    uri: pathToFileURL(filePath).toString(),
    takeFocus: true
  });
  if (!result.success) {
    connection.console.warn(`VibeGuard could not open ignore rules: ${filePath}`);
  }
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

async function createLspL3Analyzer(): Promise<LlmSemanticAnalyzer | undefined> {
  if (!settings.enableL3) {
    return undefined;
  }
  const provider = settings.llmProvider ?? "deepseek";
  const apiKey =
    getLlmApiKeyFromEnv(provider, settings.llmApiKeyEnv) ??
    (await (storedLlmCredentialPromises.get(provider) ?? rememberStoredLlmCredential(provider)));
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

function rememberStoredLlmCredential(provider: LlmProvider): Promise<string | undefined> {
  const credential = readStoredLlmCredential(provider).then((stored) => stored?.apiKey);
  storedLlmCredentialPromises.set(provider, credential);
  return credential;
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
