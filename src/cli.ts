#!/usr/bin/env node
import fs from "fs/promises";
import path from "path";
import {
  cloneDefaultConfig,
  defaultConfigPath,
  ensureConfigFile,
  loadConfig,
  resolveConfigCustomRulePaths,
  updateLlmApiKeyStored,
  updateIgnoredFinding
} from "./config";
import { loadCustomRules } from "./customRules";
import { createComplianceReport, formatComplianceMarkdown, type ComplianceFramework } from "./findings/compliance";
import { formatFindingsDashboard } from "./findings/dashboard";
import { uploadFindings } from "./findings/ingestClient";
import type { DashboardAccessRole, DashboardRole, OidcDashboardAuthOptions } from "./findings/auth";
import { startFindingsDashboardServer } from "./findings/server";
import {
  defaultFindingsDbPath,
  SqliteFindingStore,
  type FindingAuthor,
  type RecordScanRunInput,
  type FindingStoreSummary,
  type StoredFinding
} from "./findings/storage";
import { gitAuthorsForFiles, normalizeAuthorFilePath } from "./gitAuthors";
import { filterFindingsToAiLineRanges, filterScanFiles, type AiDetectionMode, type ScanMode } from "./gitFilter";
import { appendIgnoreRule, defaultIgnoreRulesPath, expandHome, loadIgnoreRules, scopedIgnoreReason } from "./ignore";
import { cliFalsePositiveTelemetryEvent, isFalsePositiveDismissalReason, reportFalsePositiveTelemetry } from "./telemetry";
import {
  deleteStoredLlmCredential,
  hasEncryptedLlmCredential,
  llmCredentialPinEnvironment,
  readStoredLlmCredential,
  storeLlmCredential,
  type StoredLlmCredentialSource
} from "./l3/credentials";
import { getLlmApiKeyFromEnv, LlmSemanticAnalyzer, type LlmProvider } from "./l3/llm";
import { defaultIndexPath } from "./package/cache";
import { syncConfiguredPackageIndexes, type ConfiguredPackageSyncResult } from "./package/configSync";
import { readPackageNameFile } from "./package/importer";
import { PackageVerifier } from "./package/packageVerifier";
import { createPackageStorage, type PackageStorageKind } from "./package/storage";
import { fetchNpmChangeSnapshot, fetchPackageNames, type SyncableRegistry } from "./package/sync";
import { defaultSqlitePath } from "./package/sqliteStore";
import {
  buildScanReport,
  formatGithubAnnotations,
  formatHumanReport,
  formatJsonReport,
  formatMarkdownReport,
  formatSarifReport
} from "./reporters";
import { scanSourceFile } from "./scanner";
import { formatSemgrepRules } from "./semgrep";
import { getProApiKeyFromEnv, getProSubscriptionStatus } from "./subscription";
import type { Finding, PackageRegistry, ScanPerformance, Severity } from "./types";
import { extensionOf, severityMeetsThreshold } from "./utils";

type ReportFormat = "human" | "json" | "sarif" | "markdown";

interface CliOptions {
  paths: string[];
  mode: ScanMode;
  aiDetection: AiDetectionMode;
  baseRef?: string;
  headRef?: string;
  reportFormat: ReportFormat;
  outputPath?: string;
  sarifPath?: string;
  markdownPath?: string;
  githubAnnotations: boolean;
  failOn: Severity | "none";
  packageVerification?: "off" | "seed" | "remote";
  includeSast?: boolean;
  includeL3?: boolean;
  ignoreRulesPath?: string;
  customRulePaths: string[];
  packageIndexPath?: string;
  sqlitePath?: string;
  storage: PackageStorageKind;
  useIgnoreRules: boolean;
  useConfig: boolean;
  configPath?: string;
  dedupWithExistingTools?: boolean;
  storeFindings: boolean;
  findingsDbPath?: string;
  findingsProject?: string;
  findingsEndpoint?: string;
  findingsTokenEnv?: string;
  findingsUploadRequired: boolean;
  llmProvider?: LlmProvider;
  llmModel?: string;
  llmBaseUrl?: string;
  llmApiKeyEnv?: string;
}

const supportedExtensions = new Set([
  "js",
  "jsx",
  "ts",
  "tsx",
  "mjs",
  "cjs",
  "py",
  "rs",
  "go",
  "java",
  "kt",
  "kts",
  "json",
  "toml",
  "xml",
  "gradle",
  "sh",
  "bash",
  "zsh",
  "ps1",
  "yml",
  "yaml",
  "txt"
]);
const supportedFileNames = new Set([
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "cargo.toml",
  "go.mod",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "dockerfile"
]);
const ignoredDirectories = new Set(["node_modules", ".git", "out", "dist", "build", "coverage", ".vscode-test"]);

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "rules") {
    await runRulesCommand(args.slice(1));
    return;
  }
  if (args[0] === "packages") {
    await runPackagesCommand(args.slice(1));
    return;
  }
  if (args[0] === "config") {
    await runConfigCommand(args.slice(1));
    return;
  }
  if (args[0] === "findings") {
    await runFindingsCommand(args.slice(1));
    return;
  }
  if (args[0] === "subscription") {
    await runSubscriptionCommand(args.slice(1));
    return;
  }
  if (args[0] === "llm-key") {
    await runLlmKeyCommand(args.slice(1));
    return;
  }
  if (args[0] === "ignore-rules") {
    await runIgnoreRulesCommand(args.slice(1));
    return;
  }

  const scanStartedAt = Date.now();
  const options = parseArgs(args);
  const loadedConfig = options.useConfig
    ? await loadConfig(options.configPath)
    : {
        config: cloneDefaultConfig(),
        path: path.resolve(expandHome(options.configPath ?? defaultConfigPath())),
        exists: false
      };
  if (options.useConfig && options.configPath && !loadedConfig.exists) {
    throw new Error(`Config file not found: ${loadedConfig.path}`);
  }
  const config = loadedConfig.config;
  const packageVerification = options.packageVerification ?? config.package_verification;
  const includeSast = options.includeSast ?? config.detection_layers.l2;
  const includeL3 = options.includeL3 ?? config.detection_layers.l3;
  const llmProvider = options.llmProvider ?? config.llm_provider ?? "deepseek";
  const l3Analyzer = includeL3
    ? await createCliL3Analyzer(llmProvider, options.llmModel, options.llmBaseUrl, options.llmApiKeyEnv)
    : undefined;
  const dedupWithExistingTools = options.dedupWithExistingTools ?? config.dedup_with_existing_tools;
  const storage = createPackageStorage({
    kind: options.storage,
    indexPath: options.packageIndexPath,
    sqlitePath: options.sqlitePath
  });
  const verifier = new PackageVerifier({
    cache: storage.cache,
    packageIndex: storage.packageIndex
  });
  const ignoreRules = options.useIgnoreRules ? await loadIgnoreRules(options.ignoreRulesPath) : undefined;
  const configCustomRulePaths = options.useConfig ? resolveConfigCustomRulePaths(config, loadedConfig.path) : [];
  const customRules = await loadCustomRules([...configCustomRulePaths, ...options.customRulePaths]);
  const collectedFiles = await collectFiles(options.paths);
  const gitCwd = await resolveGitCwd(options.paths);
  const filterResult = await filterScanFiles(collectedFiles, {
    mode: options.mode,
    aiDetection: options.aiDetection,
    baseRef: options.baseRef,
    headRef: options.headRef,
    cwd: gitCwd
  });
  if (filterResult.warning) {
    process.stderr.write(`${filterResult.warning}\n`);
  }
  const files = filterResult.files;
  const allFindings: Finding[] = [];
  const performances: ScanPerformance[] = [];

  for (const filePath of files) {
    const text = await fs.readFile(filePath, "utf8");
    const result = await scanSourceFile(
      {
        filePath,
        text
      },
      {
        enabled: config.enabled,
        detectionLayers: {
          l1: config.detection_layers.l1,
          l2: includeSast,
          l3: includeL3
        },
        packageVerification,
        packageVerifier: verifier,
        l3Analyzer,
        customRules,
        ignoreRules,
        ignoredFindingIds: config.ignored_findings,
        dedupWithExistingTools
      }
    );
    allFindings.push(...filterFindingsToAiLineRanges(result.findings, filePath, filterResult.aiLineRanges));
    performances.push(result.performance);
  }

  const report = buildScanReport(allFindings, performances);
  let scanInput: RecordScanRunInput | undefined;
  if (options.storeFindings || options.findingsEndpoint) {
    try {
      scanInput = await createScanRunInput(options, files.length, allFindings, scanStartedAt, gitCwd);
      if (options.storeFindings) {
        await storeScanFindings(options, scanInput);
      }
    } catch (error) {
      process.stderr.write(`VibeGuard findings storage warning: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  }
  if (options.githubAnnotations) {
    const annotations = formatGithubAnnotations(report.findings, process.cwd());
    if (annotations) {
      process.stderr.write(`${annotations}\n`);
    }
  }
  if (options.sarifPath) {
    await writeTextFile(options.sarifPath, formatSarifReport(report, process.cwd()));
  }
  if (options.markdownPath) {
    await writeTextFile(options.markdownPath, formatMarkdownReport(report, files.length, process.cwd()));
  }
  await emitPrimaryReport(options, report, files.length);

  let uploadFailed = false;
  if (options.findingsEndpoint) {
    if (!scanInput) {
      uploadFailed = true;
      process.stderr.write("VibeGuard findings upload warning: scan metadata could not be prepared.\n");
    } else {
      try {
        const result = await uploadScanFindings(options, scanInput);
        process.stderr.write(`VibeGuard findings upload: stored scan ${result.scanId} (${result.activeCount} active finding(s)).\n`);
      } catch (error) {
        uploadFailed = true;
        process.stderr.write(`VibeGuard findings upload warning: ${error instanceof Error ? error.message : String(error)}\n`);
      }
    }
  }

  const shouldFail =
    allFindings.some((finding) => !finding.dismissed && severityMeetsThreshold(finding.severity, options.failOn)) ||
    (uploadFailed && options.findingsUploadRequired);
  process.exitCode = shouldFail ? 1 : 0;
}

async function runPackagesCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printPackagesHelp();
    return;
  }

  if (subcommand === "import") {
    await importPackageIndex(args);
    return;
  }
  if (subcommand === "sync") {
    await syncPackageIndex(args);
    return;
  }
  if (subcommand === "sync-config") {
    await syncConfiguredPackageIndexesCommand(args);
    return;
  }
  if (subcommand === "status") {
    await printPackageIndexStatus(args);
    return;
  }
  if (subcommand === "check") {
    await checkPackageIndex(args);
    return;
  }

  throw new Error(`Unknown packages subcommand: ${subcommand}`);
}

async function runRulesCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printRulesHelp();
    return;
  }

  if (subcommand === "export-semgrep") {
    await exportSemgrepRules(args);
    return;
  }

  throw new Error(`Unknown rules subcommand: ${subcommand}`);
}

async function runConfigCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printConfigHelp();
    return;
  }

  if (subcommand === "init") {
    await initConfig(args);
    return;
  }

  if (subcommand === "path") {
    console.log(defaultConfigPath());
    return;
  }
  if (subcommand === "ignore-finding") {
    await updateConfigIgnoredFinding(args, "add");
    return;
  }
  if (subcommand === "unignore-finding") {
    await updateConfigIgnoredFinding(args, "remove");
    return;
  }

  throw new Error(`Unknown config subcommand: ${subcommand}`);
}

async function updateConfigIgnoredFinding(args: string[], action: "add" | "remove"): Promise<void> {
  let filePath = defaultConfigPath();
  const positional: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--path") {
      filePath = path.resolve(expandHome(args[++index] ?? defaultConfigPath()));
    } else if (arg.startsWith("--path=")) {
      filePath = path.resolve(expandHome(arg.slice("--path=".length)));
    } else if (arg === "-h" || arg === "--help") {
      printConfigHelp();
      return;
    } else {
      positional.push(arg);
    }
  }

  const findingId = positional[0];
  if (!findingId) {
    throw new Error(`Usage: vibeguard config ${action === "add" ? "ignore-finding" : "unignore-finding"} <finding-id> [--path path]`);
  }
  const result = await updateIgnoredFinding(findingId, action, filePath);
  const verb = action === "add" ? "Ignored" : "Unignored";
  console.log(`${verb} finding ${findingId} in ${result.path}`);
}

async function runSubscriptionCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printSubscriptionHelp();
    return;
  }
  if (subcommand === "status") {
    await printSubscriptionStatus(args);
    return;
  }
  throw new Error(`Unknown subscription subcommand: ${subcommand}`);
}

async function runLlmKeyCommand(args: string[]): Promise<void> {
  const action = args.shift();
  if (!action || action === "-h" || action === "--help") {
    printLlmKeyHelp();
    return;
  }
  if (action !== "set" && action !== "delete" && action !== "status") {
    throw new Error(`Unknown llm-key subcommand: ${action}`);
  }

  let provider: LlmProvider | undefined;
  let configPath = defaultConfigPath();
  let source: "stdin" | "environment" | undefined;
  let environmentName: string | undefined;
  let pinEnvironment: string | undefined;
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--provider") {
      provider = parseLlmProvider(readRequiredOptionValue(args[++index], "--provider"));
    } else if (arg.startsWith("--provider=")) {
      provider = parseLlmProvider(readRequiredOptionValue(arg.slice("--provider=".length), "--provider"));
    } else if (arg === "--config") {
      configPath = path.resolve(expandHome(readRequiredOptionValue(args[++index], "--config")));
    } else if (arg.startsWith("--config=")) {
      configPath = path.resolve(expandHome(readRequiredOptionValue(arg.slice("--config=".length), "--config")));
    } else if (arg === "--stdin") {
      if (source) {
        throw new Error("Use only one LLM key source: --stdin or --from-env.");
      }
      source = "stdin";
    } else if (arg === "--from-env") {
      if (source) {
        throw new Error("Use only one LLM key source: --stdin or --from-env.");
      }
      source = "environment";
      environmentName = readEnvironmentVariableName(args[++index], "--from-env");
    } else if (arg.startsWith("--from-env=")) {
      if (source) {
        throw new Error("Use only one LLM key source: --stdin or --from-env.");
      }
      source = "environment";
      environmentName = readEnvironmentVariableName(arg.slice("--from-env=".length), "--from-env");
    } else if (arg === "--pin-env") {
      pinEnvironment = readEnvironmentVariableName(args[++index], "--pin-env");
    } else if (arg.startsWith("--pin-env=")) {
      pinEnvironment = readEnvironmentVariableName(arg.slice("--pin-env=".length), "--pin-env");
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-h" || arg === "--help") {
      printLlmKeyHelp();
      return;
    } else {
      if (action === "set") {
        throw new Error("Unsupported llm-key set option. Use --stdin or --from-env ENV_VAR; plaintext key arguments are not supported.");
      }
      throw new Error(`Unknown llm-key ${action} option: ${arg}`);
    }
  }

  if (action !== "set" && source) {
    throw new Error(`--stdin and --from-env are only valid for vibeguard llm-key set.`);
  }
  if (action === "set" && !source) {
    throw new Error("vibeguard llm-key set requires --stdin or --from-env NAME; plaintext command-line keys are not supported.");
  }

  const loaded = await loadConfig(configPath);
  const selectedProvider = provider ?? loaded.config.llm_provider ?? "deepseek";
  const pin = pinEnvironment ? process.env[pinEnvironment] : process.env[llmCredentialPinEnvironment];

  if (action === "set") {
    const apiKey =
      source === "stdin"
        ? await readLlmKeyFromStdin()
        : process.env[environmentName ?? ""]?.trim();
    if (!apiKey) {
      throw new Error(source === "environment" ? `Environment variable ${environmentName} is empty.` : "LLM API key must not be empty.");
    }
    const storedSource = await storeLlmCredential(selectedProvider, apiKey, { pin });
    const updated = await updateLlmApiKeyStored(true, configPath, selectedProvider);
    printLlmKeyResult(
      { provider: selectedProvider, stored: true, changed: true, configPath: updated.path, source: storedSource },
      json
    );
    return;
  }

  if (action === "delete") {
    const deleted = await deleteStoredLlmCredential(selectedProvider, { pin });
    const updated = await updateLlmApiKeyStored(false, configPath, selectedProvider);
    printLlmKeyResult(
      {
        provider: selectedProvider,
        stored: false,
        changed: deleted.nativeDeleted || deleted.encryptedDeleted,
        configPath: updated.path,
        source: deleted.encryptedDeleted ? "encrypted" : "native"
      },
      json
    );
    return;
  }

  const credential = await readStoredLlmCredential(selectedProvider, { pin });
  const encryptedStored = !credential && (await hasEncryptedLlmCredential(selectedProvider));
  printLlmKeyResult(
    {
      provider: selectedProvider,
      stored: Boolean(credential) || encryptedStored,
      changed: false,
      configPath: loaded.path,
      source: credential?.source ?? (encryptedStored ? "encrypted" : "native")
    },
    json
  );
}

function printLlmKeyResult(
  result: { provider: LlmProvider; stored: boolean; changed: boolean; configPath: string; source: StoredLlmCredentialSource },
  json: boolean
): void {
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(
    `VibeGuard ${result.provider} API key: ${result.stored ? `stored securely (${result.source})` : "not stored"}.`
  );
  if (result.changed) {
    console.log(`Config marker updated: ${result.configPath}`);
  }
}

async function readLlmKeyFromStdin(): Promise<string> {
  if (!process.stdin.isTTY) {
    let value = "";
    for await (const chunk of process.stdin) {
      value += String(chunk);
      if (value.length > 16 * 1024) {
        throw new Error("LLM API key must not exceed 16 KiB.");
      }
    }
    return value.trim();
  }

  const input = process.stdin as NodeJS.ReadStream & { isRaw?: boolean; setRawMode?: (mode: boolean) => void };
  return new Promise<string>((resolve, reject) => {
    let value = "";
    const wasRaw = input.isRaw ?? false;
    const cleanup = () => {
      input.off("data", onData);
      input.setRawMode?.(wasRaw);
      input.pause();
    };
    const onData = (chunk: Buffer) => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\r" || character === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolve(value.trim());
          return;
        }
        if (character === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("LLM API key entry cancelled."));
          return;
        }
        if (character === "\b" || character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        value += character;
        if (value.length > 16 * 1024) {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("LLM API key must not exceed 16 KiB."));
          return;
        }
      }
    };
    process.stdout.write("Enter LLM API key: ");
    input.setRawMode?.(true);
    input.resume();
    input.on("data", onData);
  });
}

async function printSubscriptionStatus(args: string[]): Promise<void> {
  let apiKeyEnvironment: string | undefined;
  let baseUrl: string | undefined;
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--api-key-env") {
      apiKeyEnvironment = readEnvironmentVariableName(args[++index], "--api-key-env");
    } else if (arg.startsWith("--api-key-env=")) {
      apiKeyEnvironment = readEnvironmentVariableName(arg.slice("--api-key-env=".length), "--api-key-env");
    } else if (arg === "--base-url") {
      baseUrl = readRequiredOptionValue(args[++index], "--base-url");
    } else if (arg.startsWith("--base-url=")) {
      baseUrl = readRequiredOptionValue(arg.slice("--base-url=".length), "--base-url");
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-h" || arg === "--help") {
      printSubscriptionHelp();
      return;
    } else {
      throw new Error(`Unknown subscription status option: ${arg}`);
    }
  }
  const status = await getProSubscriptionStatus({
    apiKey: getProApiKeyFromEnv(apiKeyEnvironment) ?? (await readStoredLlmCredential("vibeguard"))?.apiKey,
    baseUrl
  });
  if (json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }
  console.log(`VibeGuard subscription: ${status.plan} (${status.state})`);
  if (status.reason === "missing_credential") {
    console.log("No VIBEGUARD_PRO_API_KEY credential is configured.");
    return;
  }
  console.log(`Account active: ${status.active ? "yes" : "no"}`);
  console.log(`Features: ${status.features.length > 0 ? status.features.join(", ") : "none"}`);
  if (status.l3Requests) {
    console.log(
      `Official L3 requests: ${status.l3Requests.used}/${status.l3Requests.limit}${
        status.l3Requests.resetAt ? `; resets ${status.l3Requests.resetAt}` : ""
      }`
    );
  }
}

async function runFindingsCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printFindingsHelp();
    return;
  }

  if (subcommand === "status") {
    await printFindingsStatus(args);
    return;
  }
  if (subcommand === "list") {
    await listStoredFindings(args);
    return;
  }
  if (subcommand === "summary") {
    await printFindingsSummary(args);
    return;
  }
  if (subcommand === "dashboard") {
    await writeFindingsDashboard(args);
    return;
  }
  if (subcommand === "compliance") {
    await writeComplianceReport(args);
    return;
  }
  if (subcommand === "audit") {
    await listAuditEvents(args);
    return;
  }
  if (subcommand === "serve") {
    await serveFindingsDashboard(args);
    return;
  }
  if (subcommand === "prune") {
    await pruneStoredFindings(args);
    return;
  }

  throw new Error(`Unknown findings subcommand: ${subcommand}`);
}

async function runIgnoreRulesCommand(args: string[]): Promise<void> {
  const subcommand = args.shift();
  if (!subcommand || subcommand === "-h" || subcommand === "--help") {
    printIgnoreRulesHelp();
    return;
  }

  if (subcommand === "add-rule") {
    await addIgnoreRuleCommand(args);
    return;
  }
  if (subcommand === "add-package") {
    await addIgnorePackageCommand(args);
    return;
  }

  throw new Error(`Unknown ignore-rules subcommand: ${subcommand}`);
}

async function addIgnoreRuleCommand(args: string[]): Promise<void> {
  let ignoreRulesPath = defaultIgnoreRulesPath();
  let configPath = defaultConfigPath();
  let targetPath: string | undefined;
  let scope: string | undefined;
  let line: number | undefined;
  let reason: string | undefined;
  let json = false;
  const positional: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--ignore-rules") {
      ignoreRulesPath = path.resolve(expandHome(args[++index] ?? defaultIgnoreRulesPath()));
    } else if (arg.startsWith("--ignore-rules=")) {
      ignoreRulesPath = path.resolve(expandHome(arg.slice("--ignore-rules=".length)));
    } else if (arg === "--config") {
      configPath = path.resolve(expandHome(args[++index] ?? defaultConfigPath()));
    } else if (arg.startsWith("--config=")) {
      configPath = path.resolve(expandHome(arg.slice("--config=".length)));
    } else if (arg === "--path") {
      targetPath = args[++index];
    } else if (arg.startsWith("--path=")) {
      targetPath = arg.slice("--path=".length);
    } else if (arg === "--scope") {
      scope = args[++index];
    } else if (arg.startsWith("--scope=")) {
      scope = arg.slice("--scope=".length);
    } else if (arg === "--line") {
      line = parsePositiveInteger(args[++index], "--line");
    } else if (arg.startsWith("--line=")) {
      line = parsePositiveInteger(arg.slice("--line=".length), "--line");
    } else if (arg === "--reason") {
      reason = args[++index];
    } else if (arg.startsWith("--reason=")) {
      reason = arg.slice("--reason=".length);
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-h" || arg === "--help") {
      printIgnoreRulesHelp();
      return;
    } else {
      positional.push(arg);
    }
  }

  const rule = positional[0];
  if (!rule) {
    throw new Error("Usage: vibeguard ignore-rules add-rule <rule-id-or-type> [--path glob] [--line n] [--reason text]");
  }
  if (line !== undefined && !targetPath && !scope) {
    throw new Error("--line requires --path or --scope so the ignore does not apply to every file.");
  }
  const reasonScope = line !== undefined ? "line" : targetPath || scope ? "file" : "global";
  const entry = {
    rule,
    path: targetPath,
    scope,
    line,
    reason: scopedIgnoreReason(reason, reasonScope)
  };
  const filePath = await appendIgnoreRule(entry, ignoreRulesPath);
  await reportCliFalsePositive(rule, reasonScope, entry.reason, configPath);

  if (json) {
    console.log(JSON.stringify({ path: filePath, rule: entry }, null, 2));
    return;
  }
  console.log(`Added ignore rule for ${rule} to ${filePath}.`);
}

async function addIgnorePackageCommand(args: string[]): Promise<void> {
  let ignoreRulesPath = defaultIgnoreRulesPath();
  let configPath = defaultConfigPath();
  let reason: string | undefined = "internal_package";
  let json = false;
  const positional: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--ignore-rules") {
      ignoreRulesPath = path.resolve(expandHome(args[++index] ?? defaultIgnoreRulesPath()));
    } else if (arg.startsWith("--ignore-rules=")) {
      ignoreRulesPath = path.resolve(expandHome(arg.slice("--ignore-rules=".length)));
    } else if (arg === "--config") {
      configPath = path.resolve(expandHome(args[++index] ?? defaultConfigPath()));
    } else if (arg.startsWith("--config=")) {
      configPath = path.resolve(expandHome(arg.slice("--config=".length)));
    } else if (arg === "--reason") {
      reason = args[++index];
    } else if (arg.startsWith("--reason=")) {
      reason = arg.slice("--reason=".length);
    } else if (arg === "--no-reason") {
      reason = undefined;
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "-h" || arg === "--help") {
      printIgnoreRulesHelp();
      return;
    } else {
      positional.push(arg);
    }
  }

  const registry = parseRegistry(positional[0]);
  const packageName = positional[1];
  if (!registry || !packageName) {
    throw new Error("Usage: vibeguard ignore-rules add-package <npm|pypi|cargo|gomod|maven> <package> [--reason text]");
  }
  const entry = {
    package: packageName,
    registry,
    reason: scopedIgnoreReason(reason, "package")
  };
  const filePath = await appendIgnoreRule(entry, ignoreRulesPath);
  await reportCliFalsePositive(`hallucinated_package_${registry}`, "package", entry.reason, configPath);

  if (json) {
    console.log(JSON.stringify({ path: filePath, rule: entry }, null, 2));
    return;
  }
  console.log(`Added package ignore for ${registry}:${packageName} to ${filePath}.`);
}

async function reportCliFalsePositive(
  rule: string,
  scope: "line" | "file" | "global" | "package",
  reason: string | undefined,
  configPath: string
): Promise<void> {
  if (!isFalsePositiveDismissalReason(reason)) {
    return;
  }
  try {
    const loadedConfig = await loadConfig(configPath);
    await reportFalsePositiveTelemetry({
      enabled: loadedConfig.config.telemetry,
      event: cliFalsePositiveTelemetryEvent(rule, "cli", scope)
    });
  } catch {
    // Anonymous feedback must never prevent a local ignore rule from being saved.
  }
}

async function initConfig(args: string[]): Promise<void> {
  let filePath = defaultConfigPath();
  let force = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--path") {
      filePath = path.resolve(expandHome(args[++index] ?? defaultConfigPath()));
    } else if (arg.startsWith("--path=")) {
      filePath = path.resolve(expandHome(arg.slice("--path=".length)));
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "-h" || arg === "--help") {
      printConfigHelp();
      return;
    } else {
      throw new Error(`Unknown config init option: ${arg}`);
    }
  }

  const result = await ensureConfigFile(filePath, { force });
  console.log(`${result.created ? "Created" : "Existing"} VibeGuard config: ${result.path}`);
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    paths: [],
    mode: "full-scan",
    aiDetection: "author",
    reportFormat: "human",
    githubAnnotations: false,
    failOn: "critical",
    customRulePaths: [],
    storage: "auto",
    useIgnoreRules: true,
    useConfig: true,
    storeFindings: true,
    findingsUploadRequired: false
  };

  const rest = [...args];
  if (rest[0] === "scan") {
    rest.shift();
  }

  while (rest.length > 0) {
    const arg = rest.shift() ?? "";
    if (arg === "--json") {
      options.reportFormat = "json";
    } else if (arg === "--mode") {
      options.mode = parseScanMode(rest.shift() ?? "full-scan");
    } else if (arg.startsWith("--mode=")) {
      options.mode = parseScanMode(arg.slice("--mode=".length));
    } else if (arg === "--ai-detection") {
      options.aiDetection = parseAiDetectionMode(rest.shift() ?? "author");
    } else if (arg.startsWith("--ai-detection=")) {
      options.aiDetection = parseAiDetectionMode(arg.slice("--ai-detection=".length));
    } else if (arg === "--base-ref") {
      options.baseRef = rest.shift();
    } else if (arg.startsWith("--base-ref=")) {
      options.baseRef = arg.slice("--base-ref=".length);
    } else if (arg === "--head-ref") {
      options.headRef = rest.shift();
    } else if (arg.startsWith("--head-ref=")) {
      options.headRef = arg.slice("--head-ref=".length);
    } else if (arg === "--format") {
      options.reportFormat = parseReportFormat(rest.shift() ?? "human");
    } else if (arg.startsWith("--format=")) {
      options.reportFormat = parseReportFormat(arg.slice("--format=".length));
    } else if (arg === "--output") {
      options.outputPath = path.resolve(expandHome(rest.shift() ?? "vibeguard-report.json"));
    } else if (arg.startsWith("--output=")) {
      options.outputPath = path.resolve(expandHome(arg.slice("--output=".length)));
    } else if (arg === "--sarif") {
      options.sarifPath = path.resolve(expandHome(rest.shift() ?? "vibeguard.sarif"));
    } else if (arg.startsWith("--sarif=")) {
      options.sarifPath = path.resolve(expandHome(arg.slice("--sarif=".length)));
    } else if (arg === "--markdown") {
      options.markdownPath = path.resolve(expandHome(rest.shift() ?? "vibeguard-report.md"));
    } else if (arg.startsWith("--markdown=")) {
      options.markdownPath = path.resolve(expandHome(arg.slice("--markdown=".length)));
    } else if (arg === "--github-annotations") {
      options.githubAnnotations = true;
    } else if (arg === "--no-github-annotations") {
      options.githubAnnotations = false;
    } else if (arg === "--no-l2") {
      options.includeSast = false;
    } else if (arg === "--l2") {
      options.includeSast = true;
    } else if (arg === "--l3") {
      options.includeL3 = true;
    } else if (arg === "--no-l3") {
      options.includeL3 = false;
    } else if (arg === "--llm-provider") {
      options.llmProvider = parseLlmProvider(rest.shift() ?? "deepseek");
    } else if (arg.startsWith("--llm-provider=")) {
      options.llmProvider = parseLlmProvider(arg.slice("--llm-provider=".length));
    } else if (arg === "--llm-model") {
      options.llmModel = rest.shift();
    } else if (arg.startsWith("--llm-model=")) {
      options.llmModel = arg.slice("--llm-model=".length);
    } else if (arg === "--llm-base-url") {
      options.llmBaseUrl = rest.shift();
    } else if (arg.startsWith("--llm-base-url=")) {
      options.llmBaseUrl = arg.slice("--llm-base-url=".length);
    } else if (arg === "--llm-api-key-env") {
      options.llmApiKeyEnv = rest.shift();
    } else if (arg.startsWith("--llm-api-key-env=")) {
      options.llmApiKeyEnv = arg.slice("--llm-api-key-env=".length);
    } else if (arg === "--fail-on") {
      options.failOn = parseSeverity(rest.shift() ?? "critical");
    } else if (arg.startsWith("--fail-on=")) {
      options.failOn = parseSeverity(arg.slice("--fail-on=".length));
    } else if (arg === "--package-verification") {
      options.packageVerification = parsePackageVerification(rest.shift() ?? "seed");
    } else if (arg.startsWith("--package-verification=")) {
      options.packageVerification = parsePackageVerification(arg.slice("--package-verification=".length));
    } else if (arg === "--package-index") {
      options.packageIndexPath = path.resolve(expandHome(rest.shift() ?? defaultIndexPath()));
    } else if (arg.startsWith("--package-index=")) {
      options.packageIndexPath = path.resolve(expandHome(arg.slice("--package-index=".length)));
    } else if (arg === "--sqlite-db") {
      options.sqlitePath = path.resolve(expandHome(rest.shift() ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      options.sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      options.storage = parseStorageKind(rest.shift() ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      options.storage = parseStorageKind(arg.slice("--storage=".length));
    } else if (arg === "--ignore-rules") {
      options.ignoreRulesPath = path.resolve(expandHome(rest.shift() ?? defaultIgnoreRulesPath()));
    } else if (arg.startsWith("--ignore-rules=")) {
      options.ignoreRulesPath = path.resolve(expandHome(arg.slice("--ignore-rules=".length)));
    } else if (arg === "--custom-rules") {
      options.customRulePaths.push(path.resolve(expandHome(rest.shift() ?? "vibeguard-rules.yml")));
    } else if (arg.startsWith("--custom-rules=")) {
      options.customRulePaths.push(path.resolve(expandHome(arg.slice("--custom-rules=".length))));
    } else if (arg === "--no-ignore") {
      options.useIgnoreRules = false;
    } else if (arg === "--config") {
      options.configPath = path.resolve(expandHome(rest.shift() ?? defaultConfigPath()));
    } else if (arg.startsWith("--config=")) {
      options.configPath = path.resolve(expandHome(arg.slice("--config=".length)));
    } else if (arg === "--no-config") {
      options.useConfig = false;
    } else if (arg === "--dedup-existing-tools") {
      options.dedupWithExistingTools = true;
    } else if (arg === "--no-dedup-existing-tools") {
      options.dedupWithExistingTools = false;
    } else if (arg === "--findings-db") {
      options.findingsDbPath = path.resolve(expandHome(rest.shift() ?? defaultFindingsDbPath()));
    } else if (arg.startsWith("--findings-db=")) {
      options.findingsDbPath = path.resolve(expandHome(arg.slice("--findings-db=".length)));
    } else if (arg === "--findings-project") {
      options.findingsProject = readProjectIdentifier(rest.shift(), "--findings-project");
    } else if (arg.startsWith("--findings-project=")) {
      options.findingsProject = readProjectIdentifier(arg.slice("--findings-project=".length), "--findings-project");
    } else if (arg === "--findings-endpoint") {
      options.findingsEndpoint = readRequiredOptionValue(rest.shift(), "--findings-endpoint");
    } else if (arg.startsWith("--findings-endpoint=")) {
      options.findingsEndpoint = readRequiredOptionValue(arg.slice("--findings-endpoint=".length), "--findings-endpoint");
    } else if (arg === "--findings-token-env") {
      options.findingsTokenEnv = readEnvironmentVariableName(rest.shift(), "--findings-token-env");
    } else if (arg.startsWith("--findings-token-env=")) {
      options.findingsTokenEnv = readEnvironmentVariableName(arg.slice("--findings-token-env=".length), "--findings-token-env");
    } else if (arg === "--findings-upload-required") {
      options.findingsUploadRequired = true;
    } else if (arg === "--no-findings-upload-required") {
      options.findingsUploadRequired = false;
    } else if (arg === "--no-store-findings") {
      options.storeFindings = false;
    } else if (arg === "-h" || arg === "--help") {
      printHelp();
      process.exit(0);
    } else {
      options.paths.push(path.resolve(arg));
    }
  }

  if (options.paths.length === 0) {
    options.paths.push(process.cwd());
  }
  if (options.findingsUploadRequired && !options.findingsEndpoint) {
    throw new Error("--findings-upload-required requires --findings-endpoint.");
  }

  return options;
}

function parseSeverity(value: string): Severity | "none" {
  if (["critical", "high", "medium", "low", "info", "none"].includes(value)) {
    return value as Severity | "none";
  }
  throw new Error(`Invalid --fail-on value: ${value}`);
}

function parsePackageVerification(value: string): "off" | "seed" | "remote" {
  if (value === "off" || value === "seed" || value === "remote") {
    return value;
  }
  throw new Error(`Invalid --package-verification value: ${value}`);
}

function parseStorageKind(value: string): PackageStorageKind {
  if (value === "auto" || value === "json" || value === "sqlite") {
    return value;
  }
  throw new Error(`Invalid --storage value: ${value}`);
}

function parseReportFormat(value: string): ReportFormat {
  if (value === "human" || value === "json" || value === "sarif" || value === "markdown") {
    return value;
  }
  throw new Error(`Invalid --format value: ${value}`);
}

function parseScanMode(value: string): ScanMode {
  if (value === "full-scan" || value === "ai-code-scan") {
    return value;
  }
  throw new Error(`Invalid --mode value: ${value}`);
}

function parseAiDetectionMode(value: string): AiDetectionMode {
  if (value === "author" || value === "message" || value === "aggressive") {
    return value;
  }
  throw new Error(`Invalid --ai-detection value: ${value}`);
}

async function emitPrimaryReport(options: CliOptions, report: ReturnType<typeof buildScanReport>, fileCount: number): Promise<void> {
  const output = formatPrimaryReport(options.reportFormat, report, fileCount);
  if (options.outputPath) {
    await writeTextFile(options.outputPath, output);
    return;
  }
  console.log(output);
}

async function storeScanFindings(
  options: CliOptions,
  input: RecordScanRunInput
): Promise<void> {
  const store = new SqliteFindingStore(options.findingsDbPath ?? defaultFindingsDbPath());
  try {
    store.recordScanRun(input);
  } finally {
    store.close();
  }
}

async function createScanRunInput(
  options: CliOptions,
  fileCount: number,
  findings: Finding[],
  startedAt: number,
  gitCwd: string
): Promise<RecordScanRunInput> {
  return {
    startedAt,
    completedAt: Date.now(),
    project: options.findingsProject,
    cwd: process.cwd(),
    targetPaths: options.paths,
    fileCount,
    findings,
    findingAuthors: await resolveFindingAuthors(findings, gitCwd)
  };
}

async function uploadScanFindings(options: CliOptions, scan: RecordScanRunInput) {
  const tokenEnvironment = options.findingsTokenEnv ?? "VIBEGUARD_FINDINGS_INGEST_TOKEN";
  const token = readEnvironmentValue(tokenEnvironment, "--findings-token-env");
  return uploadFindings({
    endpoint: options.findingsEndpoint ?? "",
    token,
    scan
  });
}

async function resolveFindingAuthors(findings: Finding[], gitCwd: string): Promise<Record<string, FindingAuthor>> {
  const authorByFindingId: Record<string, FindingAuthor> = {};
  if (findings.length === 0) {
    return authorByFindingId;
  }
  const files = [...new Set(findings.map((finding) => finding.file))];
  const fileAuthors = await gitAuthorsForFiles(files, gitCwd);
  for (const finding of findings) {
    const author = fileAuthors.get(normalizeAuthorFilePath(finding.file));
    if (author) {
      authorByFindingId[finding.id] = author;
    }
  }
  return authorByFindingId;
}

async function printFindingsStatus(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const stats = store.stats(options.project);
    if (options.json) {
      console.log(JSON.stringify(stats, null, 2));
      return;
    }
    console.log(`Findings DB: ${options.dbPath}`);
    if (options.project) {
      console.log(`Project: ${options.project}`);
    }
    console.log(`Scans: ${stats.scanCount}`);
    console.log(`Findings: ${stats.findingCount} (${stats.activeCount} active, ${stats.dismissedCount} dismissed)`);
    console.log(`Latest scan: ${stats.latestScanAt ? new Date(stats.latestScanAt).toISOString() : "none"}`);
    console.log(`Storage: ${formatStorageBytes(stats.databaseBytes ?? 0)} / ${formatStorageBytes(stats.maxDatabaseBytes ?? 0)}`);
  } finally {
    store.close();
  }
}

async function printFindingsSummary(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const since = options.days === undefined ? undefined : Date.now() - options.days * 24 * 60 * 60 * 1000;
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const summary = store.summary({ since, topLimit: options.topLimit, project: options.project });
    if (options.json) {
      console.log(JSON.stringify(summary, null, 2));
      return;
    }
    printHumanFindingsSummary(options.dbPath, summary);
  } finally {
    store.close();
  }
}

async function writeFindingsDashboard(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const since = options.days === undefined ? undefined : Date.now() - options.days * 24 * 60 * 60 * 1000;
  const outputPath = options.outputPath ?? path.resolve("vibeguard-dashboard.html");
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const summary = store.summary({ since, topLimit: options.topLimit, project: options.project });
    const html = formatFindingsDashboard(summary, {
      dbPath: options.dbPath,
      generatedAt: Date.now()
    });
    await writeTextFile(outputPath, html);
    if (options.json) {
      console.log(JSON.stringify({ outputPath, ...summary }, null, 2));
      return;
    }
    console.log(`Wrote VibeGuard findings dashboard to ${outputPath}`);
  } finally {
    store.close();
  }
}

async function writeComplianceReport(args: string[]): Promise<void> {
  const options = parseComplianceCommandOptions(args);
  const since = options.days === undefined ? undefined : Date.now() - options.days * 24 * 60 * 60 * 1000;
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const summary = store.summary({ since, topLimit: options.topLimit, project: options.project });
    const report = createComplianceReport(summary, {
      frameworks: options.frameworks,
      auditEvents: options.project ? [] : store.listAuditEvents({ since, limit: 1000 })
    });
    if (options.json) {
      if (options.outputPath) {
        await writeTextFile(options.outputPath, `${JSON.stringify(report, null, 2)}\n`);
        console.log(`Wrote VibeGuard compliance evidence JSON to ${options.outputPath}`);
      } else {
        console.log(JSON.stringify(report, null, 2));
      }
      return;
    }
    const outputPath = options.outputPath ?? path.resolve("vibeguard-compliance-report.md");
    await writeTextFile(outputPath, formatComplianceMarkdown(report));
    console.log(`Wrote VibeGuard compliance evidence report to ${outputPath}`);
  } finally {
    store.close();
  }
}

async function serveFindingsDashboard(args: string[]): Promise<void> {
  let dbPath = defaultFindingsDbPath();
  let host = "127.0.0.1";
  let port = 8787;
  let days: number | undefined;
  let topLimit = 10;
  let token: string | undefined;
  let ingestToken: string | undefined;
  let ingestMaxFindings: number | undefined;
  let telemetryCollection = false;
  let telemetryMaxEventsPerMinute: number | undefined;
  let project: string | undefined;
  let oidcIssuerEnvironment: string | undefined;
  let oidcClientIdEnvironment: string | undefined;
  let oidcClientSecretEnvironment: string | undefined;
  let oidcSessionSecretEnvironment: string | undefined;
  let oidcRoleClaim: string | undefined;
  let oidcDefaultRole: DashboardAccessRole | undefined;
  let publicUrl: string | undefined;
  let secureCookies: boolean | undefined;
  const oidcRoleMappings: Record<string, DashboardRole> = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--db") {
      dbPath = path.resolve(expandHome(args[++index] ?? defaultFindingsDbPath()));
    } else if (arg.startsWith("--db=")) {
      dbPath = path.resolve(expandHome(arg.slice("--db=".length)));
    } else if (arg === "--host") {
      host = args[++index]?.trim() || host;
    } else if (arg.startsWith("--host=")) {
      host = arg.slice("--host=".length).trim() || host;
    } else if (arg === "--port") {
      port = parseDashboardPort(args[++index]);
    } else if (arg.startsWith("--port=")) {
      port = parseDashboardPort(arg.slice("--port=".length));
    } else if (arg === "--days") {
      days = parseNonNegativeInteger(args[++index], "--days");
    } else if (arg.startsWith("--days=")) {
      days = parseNonNegativeInteger(arg.slice("--days=".length), "--days");
    } else if (arg === "--top") {
      topLimit = parsePositiveInteger(args[++index], "--top");
    } else if (arg.startsWith("--top=")) {
      topLimit = parsePositiveInteger(arg.slice("--top=".length), "--top");
    } else if (arg === "--token-env") {
      token = readDashboardToken(args[++index]);
    } else if (arg.startsWith("--token-env=")) {
      token = readDashboardToken(arg.slice("--token-env=".length));
    } else if (arg === "--ingest-token-env") {
      ingestToken = readIngestToken(args[++index]);
    } else if (arg.startsWith("--ingest-token-env=")) {
      ingestToken = readIngestToken(arg.slice("--ingest-token-env=".length));
    } else if (arg === "--ingest-max-findings") {
      ingestMaxFindings = parsePositiveInteger(args[++index], "--ingest-max-findings");
    } else if (arg.startsWith("--ingest-max-findings=")) {
      ingestMaxFindings = parsePositiveInteger(arg.slice("--ingest-max-findings=".length), "--ingest-max-findings");
    } else if (arg === "--telemetry-collection") {
      telemetryCollection = true;
    } else if (arg === "--telemetry-max-events-per-minute") {
      telemetryMaxEventsPerMinute = parsePositiveInteger(
        args[++index],
        "--telemetry-max-events-per-minute"
      );
    } else if (arg.startsWith("--telemetry-max-events-per-minute=")) {
      telemetryMaxEventsPerMinute = parsePositiveInteger(
        arg.slice("--telemetry-max-events-per-minute=".length),
        "--telemetry-max-events-per-minute"
      );
    } else if (arg === "--project") {
      project = readProjectIdentifier(args[++index], "--project");
    } else if (arg.startsWith("--project=")) {
      project = readProjectIdentifier(arg.slice("--project=".length), "--project");
    } else if (arg === "--oidc-issuer-env") {
      oidcIssuerEnvironment = readEnvironmentVariableName(args[++index], "--oidc-issuer-env");
    } else if (arg.startsWith("--oidc-issuer-env=")) {
      oidcIssuerEnvironment = readEnvironmentVariableName(arg.slice("--oidc-issuer-env=".length), "--oidc-issuer-env");
    } else if (arg === "--oidc-client-id-env") {
      oidcClientIdEnvironment = readEnvironmentVariableName(args[++index], "--oidc-client-id-env");
    } else if (arg.startsWith("--oidc-client-id-env=")) {
      oidcClientIdEnvironment = readEnvironmentVariableName(arg.slice("--oidc-client-id-env=".length), "--oidc-client-id-env");
    } else if (arg === "--oidc-client-secret-env") {
      oidcClientSecretEnvironment = readEnvironmentVariableName(args[++index], "--oidc-client-secret-env");
    } else if (arg.startsWith("--oidc-client-secret-env=")) {
      oidcClientSecretEnvironment = readEnvironmentVariableName(arg.slice("--oidc-client-secret-env=".length), "--oidc-client-secret-env");
    } else if (arg === "--oidc-session-secret-env") {
      oidcSessionSecretEnvironment = readEnvironmentVariableName(args[++index], "--oidc-session-secret-env");
    } else if (arg.startsWith("--oidc-session-secret-env=")) {
      oidcSessionSecretEnvironment = readEnvironmentVariableName(arg.slice("--oidc-session-secret-env=".length), "--oidc-session-secret-env");
    } else if (arg === "--oidc-role-claim") {
      oidcRoleClaim = readRequiredOptionValue(args[++index], "--oidc-role-claim");
    } else if (arg.startsWith("--oidc-role-claim=")) {
      oidcRoleClaim = readRequiredOptionValue(arg.slice("--oidc-role-claim=".length), "--oidc-role-claim");
    } else if (arg === "--oidc-role") {
      addOidcRoleMapping(args[++index], oidcRoleMappings);
    } else if (arg.startsWith("--oidc-role=")) {
      addOidcRoleMapping(arg.slice("--oidc-role=".length), oidcRoleMappings);
    } else if (arg === "--oidc-default-role") {
      oidcDefaultRole = parseDashboardAccessRole(args[++index], "--oidc-default-role");
    } else if (arg.startsWith("--oidc-default-role=")) {
      oidcDefaultRole = parseDashboardAccessRole(arg.slice("--oidc-default-role=".length), "--oidc-default-role");
    } else if (arg === "--public-url") {
      publicUrl = readRequiredOptionValue(args[++index], "--public-url");
    } else if (arg.startsWith("--public-url=")) {
      publicUrl = readRequiredOptionValue(arg.slice("--public-url=".length), "--public-url");
    } else if (arg === "--secure-cookies") {
      secureCookies = true;
    } else if (arg === "--no-secure-cookies") {
      secureCookies = false;
    } else if (arg === "-h" || arg === "--help") {
      printFindingsHelp();
      return;
    } else {
      throw new Error(`Unknown findings serve option: ${arg}`);
    }
  }
  const oidc = createOidcDashboardOptions({
    issuerEnvironment: oidcIssuerEnvironment,
    clientIdEnvironment: oidcClientIdEnvironment,
    clientSecretEnvironment: oidcClientSecretEnvironment,
    sessionSecretEnvironment: oidcSessionSecretEnvironment,
    roleClaim: oidcRoleClaim,
    roleMappings: oidcRoleMappings,
    defaultRole: oidcDefaultRole,
    publicUrl,
    secureCookies
  });
  const dashboard = await startFindingsDashboardServer({
    dbPath,
    host,
    port,
    days,
    topLimit,
    token,
    ingestToken,
    ingestMaxFindings,
    telemetryCollection,
    telemetryMaxEventsPerMinute,
    project,
    oidc
  });
  console.log(`VibeGuard team dashboard listening at ${dashboard.url}`);
  if (!token && !oidc) {
    console.log("Warning: dashboard authentication is disabled. Use --token-env or OIDC before exposing it beyond localhost.");
  } else if (oidc) {
    console.log(`OIDC role claim: ${oidc.roleClaim ?? "roles"}; unmapped users receive ${oidc.defaultRole ?? "none"} access.`);
  }
  if (ingestToken) {
    console.log("CI findings ingestion is enabled at POST /api/ingest with its separate bearer token.");
  }
  if (telemetryCollection) {
    console.log("Anonymous false-positive telemetry is enabled at POST /api/telemetry/false-positive.");
  }
  const close = async () => {
    await dashboard.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void close());
  process.once("SIGTERM", () => void close());
}

function readDashboardToken(environmentVariable: string | undefined): string {
  const name = readEnvironmentVariableName(environmentVariable, "--token-env");
  const token = readEnvironmentValue(name, "--token-env");
  return token;
}

function readIngestToken(environmentVariable: string | undefined): string {
  const name = readEnvironmentVariableName(environmentVariable, "--ingest-token-env");
  return readEnvironmentValue(name, "--ingest-token-env");
}

interface OidcDashboardOptionInputs {
  issuerEnvironment?: string;
  clientIdEnvironment?: string;
  clientSecretEnvironment?: string;
  sessionSecretEnvironment?: string;
  roleClaim?: string;
  roleMappings: Record<string, DashboardRole>;
  defaultRole?: DashboardAccessRole;
  publicUrl?: string;
  secureCookies?: boolean;
}

function createOidcDashboardOptions(input: OidcDashboardOptionInputs): OidcDashboardAuthOptions | undefined {
  const configured = [
    input.issuerEnvironment,
    input.clientIdEnvironment,
    input.clientSecretEnvironment,
    input.sessionSecretEnvironment,
    input.roleClaim,
    input.defaultRole,
    input.publicUrl,
    input.secureCookies,
    ...Object.keys(input.roleMappings)
  ].some((value) => value !== undefined);
  if (!configured) {
    return undefined;
  }
  const issuerEnvironment = input.issuerEnvironment ?? missingOidcOption("--oidc-issuer-env");
  const clientIdEnvironment = input.clientIdEnvironment ?? missingOidcOption("--oidc-client-id-env");
  const sessionSecretEnvironment = input.sessionSecretEnvironment ?? missingOidcOption("--oidc-session-secret-env");
  return {
    issuer: readEnvironmentValue(issuerEnvironment, "--oidc-issuer-env"),
    clientId: readEnvironmentValue(clientIdEnvironment, "--oidc-client-id-env"),
    clientSecret: input.clientSecretEnvironment
      ? readEnvironmentValue(input.clientSecretEnvironment, "--oidc-client-secret-env")
      : undefined,
    sessionSecret: readEnvironmentValue(sessionSecretEnvironment, "--oidc-session-secret-env"),
    roleClaim: input.roleClaim,
    roleMappings: Object.keys(input.roleMappings).length > 0 ? input.roleMappings : undefined,
    defaultRole: input.defaultRole,
    publicUrl: input.publicUrl,
    secureCookies: input.secureCookies
  };
}

function missingOidcOption(option: string): never {
  throw new Error(`${option} is required whenever OIDC dashboard options are used.`);
}

function readEnvironmentVariableName(value: string | undefined, option: string): string {
  const name = value?.trim();
  if (!name) {
    throw new Error(`${option} requires an environment variable name.`);
  }
  return name;
}

function readEnvironmentValue(name: string, option: string): string {
  const token = process.env[name]?.trim();
  if (!token) {
    throw new Error(`${option} environment variable ${name} is empty.`);
  }
  return token;
}

function readRequiredOptionValue(value: string | undefined, option: string): string {
  const result = value?.trim();
  if (!result) {
    throw new Error(`${option} requires a value.`);
  }
  return result;
}

function readProjectIdentifier(value: string | undefined, option: string): string {
  const project = readRequiredOptionValue(value, option);
  if (project.length > 256) {
    throw new Error(`${option} must be at most 256 characters.`);
  }
  return project;
}

function addOidcRoleMapping(value: string | undefined, mappings: Record<string, DashboardRole>): void {
  const assignment = readRequiredOptionValue(value, "--oidc-role");
  const separator = assignment.lastIndexOf("=");
  const sourceRole = assignment.slice(0, separator).trim();
  const dashboardRole = assignment.slice(separator + 1).trim();
  if (!sourceRole || separator <= 0) {
    throw new Error("--oidc-role must be <claim-value>=<viewer|analyst|admin>.");
  }
  mappings[sourceRole] = parseDashboardRole(dashboardRole, "--oidc-role");
}

function parseDashboardRole(value: string | undefined, option: string): DashboardRole {
  if (value === "viewer" || value === "analyst" || value === "admin") {
    return value;
  }
  throw new Error(`${option} role must be viewer, analyst, or admin.`);
}

function parseDashboardAccessRole(value: string | undefined, option: string): DashboardAccessRole {
  if (value === "none" || value === "viewer" || value === "analyst" || value === "admin") {
    return value;
  }
  throw new Error(`${option} must be none, viewer, analyst, or admin.`);
}

function parseDashboardPort(value: string | undefined): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--port must be an integer between 1 and 65535.");
  }
  return port;
}

async function listStoredFindings(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const findings = store.listFindings({
      limit: options.limit,
      includeDismissed: options.includeDismissed,
      project: options.project
    });
    if (options.json) {
      console.log(JSON.stringify(findings, null, 2));
      return;
    }
    if (findings.length === 0) {
      console.log("No stored findings.");
      return;
    }
    for (const finding of findings) {
      console.log(formatStoredFinding(finding));
    }
  } finally {
    store.close();
  }
}

async function listAuditEvents(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const events = store.listAuditEvents({ limit: options.limit });
    if (options.json) {
      console.log(JSON.stringify(events, null, 2));
      return;
    }
    if (events.length === 0) {
      console.log("No stored dashboard audit events.");
      return;
    }
    for (const event of events) {
      const subject = event.subject ? ` ${event.subject}` : "";
      const role = event.role ? ` (${event.role})` : "";
      const details = Object.keys(event.details).length > 0 ? ` ${JSON.stringify(event.details)}` : "";
      console.log(`${new Date(event.timestamp).toISOString()} ${event.outcome} ${event.action}${subject}${role}${details}`);
    }
  } finally {
    store.close();
  }
}

async function pruneStoredFindings(args: string[]): Promise<void> {
  const options = parseFindingsCommandOptions(args);
  const days = options.days ?? 30;
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const store = new SqliteFindingStore(options.dbPath);
  try {
    const result = store.pruneBefore(cutoff);
    if (options.json) {
      console.log(JSON.stringify({ ...result, cutoff }, null, 2));
      return;
    }
    console.log(
      `Deleted ${result.deletedScans} scan(s), ${result.deletedFindings} finding(s), ${result.deletedAuditEvents} audit event(s), and ${result.deletedTelemetryBuckets} anonymous telemetry bucket(s) older than ${days} day(s).`
    );
  } finally {
    store.close();
  }
}

function parseFindingsCommandOptions(args: string[]): {
  dbPath: string;
  json: boolean;
  limit: number;
  includeDismissed: boolean;
  days?: number;
  topLimit: number;
  outputPath?: string;
  project?: string;
} {
  let dbPath = defaultFindingsDbPath();
  let json = false;
  let limit = 50;
  let includeDismissed = false;
  let days: number | undefined;
  let topLimit = 10;
  let outputPath: string | undefined;
  let project: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--db") {
      dbPath = path.resolve(expandHome(args[++index] ?? defaultFindingsDbPath()));
    } else if (arg.startsWith("--db=")) {
      dbPath = path.resolve(expandHome(arg.slice("--db=".length)));
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--limit") {
      limit = parsePositiveInteger(args[++index], "--limit");
    } else if (arg.startsWith("--limit=")) {
      limit = parsePositiveInteger(arg.slice("--limit=".length), "--limit");
    } else if (arg === "--all") {
      includeDismissed = true;
    } else if (arg === "--days") {
      days = parseNonNegativeInteger(args[++index], "--days");
    } else if (arg.startsWith("--days=")) {
      days = parseNonNegativeInteger(arg.slice("--days=".length), "--days");
    } else if (arg === "--top") {
      topLimit = parsePositiveInteger(args[++index], "--top");
    } else if (arg.startsWith("--top=")) {
      topLimit = parsePositiveInteger(arg.slice("--top=".length), "--top");
    } else if (arg === "--output") {
      outputPath = path.resolve(expandHome(args[++index] ?? "vibeguard-dashboard.html"));
    } else if (arg.startsWith("--output=")) {
      outputPath = path.resolve(expandHome(arg.slice("--output=".length)));
    } else if (arg === "--project") {
      project = readProjectIdentifier(args[++index], "--project");
    } else if (arg.startsWith("--project=")) {
      project = readProjectIdentifier(arg.slice("--project=".length), "--project");
    } else if (arg === "-h" || arg === "--help") {
      printFindingsHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown findings option: ${arg}`);
    }
  }

  return { dbPath, json, limit, includeDismissed, days, topLimit, outputPath, project };
}

function parseComplianceCommandOptions(args: string[]): ReturnType<typeof parseFindingsCommandOptions> & { frameworks: ComplianceFramework[] } {
  const frameworks: ComplianceFramework[] = [];
  const remaining: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--framework") {
      addComplianceFramework(args[++index], frameworks);
    } else if (arg.startsWith("--framework=")) {
      addComplianceFramework(arg.slice("--framework=".length), frameworks);
    } else {
      remaining.push(arg);
    }
  }
  return {
    ...parseFindingsCommandOptions(remaining),
    frameworks: frameworks.length > 0 ? frameworks : ["soc2", "iso27001"]
  };
}

function addComplianceFramework(value: string | undefined, target: ComplianceFramework[]): void {
  if (value === "all") {
    target.splice(0, target.length, "soc2", "iso27001");
    return;
  }
  if (value === "soc2" || value === "iso27001") {
    if (!target.includes(value)) {
      target.push(value);
    }
    return;
  }
  throw new Error("--framework must be soc2, iso27001, or all.");
}

function printHumanFindingsSummary(dbPath: string, summary: FindingStoreSummary): void {
  console.log(`Findings DB: ${dbPath}`);
  console.log(`Window: ${summary.since ? `since ${new Date(summary.since).toISOString()}` : "all time"}`);
  console.log(`Scans: ${summary.scanCount}`);
  console.log(`Findings: ${summary.findingCount} (${summary.activeCount} active, ${summary.dismissedCount} dismissed)`);
  console.log(`Latest scan: ${summary.latestScanAt ? new Date(summary.latestScanAt).toISOString() : "none"}`);
  if (summary.databaseBytes !== undefined && summary.maxDatabaseBytes !== undefined) {
    console.log(`Storage: ${formatStorageBytes(summary.databaseBytes)} / ${formatStorageBytes(summary.maxDatabaseBytes)}`);
  }
  console.log(
    `Latest scan change: ${summary.latestScanDelta
      ? `${summary.latestScanDelta.introducedCount} introduced, ${summary.latestScanDelta.resolvedCount} resolved, ${summary.latestScanDelta.persistentCount} persistent active finding(s)`
      : "need at least two scans in this window"}`
  );
  console.log(`Severity: ${formatSummaryBuckets(summary.severityCounts)}`);
  console.log(`Type: ${formatSummaryBuckets(summary.typeCounts)}`);
  console.log(`Dismissal reasons: ${formatSummaryBuckets(summary.dismissedReasonCounts)}`);
  console.log(`Authors: ${formatAuthorBuckets(summary.authorCounts)}`);

  console.log("Top rules:");
  if (summary.topRules.length === 0) {
    console.log("  none");
  } else {
    for (const rule of summary.topRules) {
      console.log(
        `  ${rule.key}: ${rule.count} (${rule.activeCount} active, ${rule.dismissedCount} dismissed, ${rule.severity}/${rule.type})`
      );
    }
  }

  console.log("Rule feedback:");
  if (summary.falsePositiveRules.length === 0) {
    console.log("  no false-positive dismissals");
  } else {
    for (const rule of summary.falsePositiveRules) {
      console.log(
        `  ${rule.key}: ${rule.falsePositiveCount} false-positive dismissal(s), ${Math.round(rule.falsePositiveRate * 100)}% of ${rule.count} finding(s)`
      );
    }
  }

  console.log("Daily trend:");
  if (summary.trend.length === 0) {
    console.log("  none");
  } else {
    for (const point of summary.trend) {
      console.log(
        `  ${point.date}: ${point.scanCount} scan(s), ${point.findingCount} finding(s), ${point.activeCount} active, ${point.dismissedCount} dismissed`
      );
    }
  }
}

function formatSummaryBuckets(buckets: FindingStoreSummary["severityCounts"]): string {
  if (buckets.length === 0) {
    return "none";
  }
  return buckets
    .map((bucket) => `${bucket.key} ${bucket.count} (${bucket.activeCount} active, ${bucket.dismissedCount} dismissed)`)
    .join(", ");
}

function formatAuthorBuckets(authors: FindingStoreSummary["authorCounts"]): string {
  if (authors.length === 0) {
    return "none";
  }
  return authors
    .map((author) => {
      const label = author.name && author.email ? `${author.name} <${author.email}>` : author.name ?? author.email ?? author.key;
      const rate = `${Math.round(author.highRiskRate * 100)}% high-risk`;
      return `${label} ${author.count} (${author.activeCount} active, ${author.highRiskCount} high-risk, ${rate})`;
    })
    .join(", ");
}

function formatStorageBytes(bytes: number): string {
  if (bytes < 1_000_000) {
    return `${Math.ceil(bytes / 1024)} KiB`;
  }
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

function formatStoredFinding(finding: StoredFinding): string {
  const status = finding.dismissed ? "DISMISSED" : "ACTIVE";
  const lines = [
    `[${status}:${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.message}`,
    `  ${finding.detection_rule} (${finding.detection_layer}) from ${new Date(finding.scanCompletedAt).toISOString()}`
  ];
  if (finding.dismissed_reason) {
    lines.push(`  Dismissed: ${finding.dismissed_reason}`);
  }
  return lines.join("\n");
}

function formatPrimaryReport(format: ReportFormat, report: ReturnType<typeof buildScanReport>, fileCount: number): string {
  if (format === "json") {
    return formatJsonReport(report);
  }
  if (format === "sarif") {
    return formatSarifReport(report, process.cwd());
  }
  if (format === "markdown") {
    return formatMarkdownReport(report, fileCount, process.cwd());
  }
  return formatHumanReport(report, fileCount);
}

async function writeTextFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${content}\n`, "utf8");
}

async function exportSemgrepRules(args: string[]): Promise<void> {
  let outputPath: string | undefined;
  let rulePrefix = "vibeguard";

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--output") {
      outputPath = path.resolve(expandHome(args[++index] ?? "vibeguard-semgrep.yml"));
    } else if (arg.startsWith("--output=")) {
      outputPath = path.resolve(expandHome(arg.slice("--output=".length)));
    } else if (arg === "--prefix") {
      rulePrefix = args[++index] ?? "vibeguard";
    } else if (arg.startsWith("--prefix=")) {
      rulePrefix = arg.slice("--prefix=".length);
    } else if (arg === "-h" || arg === "--help") {
      printRulesHelp();
      return;
    }
  }

  const yaml = formatSemgrepRules({ rulePrefix });
  if (outputPath) {
    await writeTextFile(outputPath, yaml.trimEnd());
    return;
  }
  console.log(yaml.trimEnd());
}

async function importPackageIndex(args: string[]): Promise<void> {
  let coverage: "partial" | "full" = "partial";
  let indexPath = defaultIndexPath();
  let sqlitePath = defaultSqlitePath();
  let storageKind: PackageStorageKind = "auto";
  let json = false;
  const positional: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--full") {
      coverage = "full";
    } else if (arg === "--partial") {
      coverage = "partial";
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--index") {
      indexPath = path.resolve(expandHome(args[++index] ?? defaultIndexPath()));
    } else if (arg.startsWith("--index=")) {
      indexPath = path.resolve(expandHome(arg.slice("--index=".length)));
    } else if (arg === "--sqlite-db") {
      sqlitePath = path.resolve(expandHome(args[++index] ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      storageKind = parseStorageKind(args[++index] ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      storageKind = parseStorageKind(arg.slice("--storage=".length));
    } else {
      positional.push(arg);
    }
  }

  const registry = parseRegistry(positional[0]);
  const filePath = positional[1] ? path.resolve(expandHome(positional[1])) : undefined;
  if (!registry || !filePath) {
    throw new Error("Usage: vibeguard packages import <registry> <file> [--full|--partial] [--index path]");
  }

  const parsed = await readPackageNameFile(filePath);
  const storage = createPackageStorage({
    kind: storageKind,
    indexPath,
    sqlitePath
  });
  const entry = await storage.packageIndex.importPackageNames(registry, parsed.names, coverage);

  if (json) {
    console.log(JSON.stringify({ ...entry, imported: parsed.names.length, format: parsed.format, storage: storage.kind, path: storage.sqlitePath ?? storage.indexPath }, null, 2));
  } else {
    console.log(
      `Imported ${parsed.names.length} ${registry} package name(s) from ${parsed.format}; index now has ${entry.packageCount} package(s) with ${entry.coverage} coverage.`
    );
    console.log(`${storage.kind === "sqlite" ? "SQLite DB" : "Index"}: ${storage.sqlitePath ?? storage.indexPath}`);
  }
}

async function syncPackageIndex(args: string[]): Promise<void> {
  let requestedCoverage: "partial" | "full" = "partial";
  let indexPath = defaultIndexPath();
  let sqlitePath = defaultSqlitePath();
  let storageKind: PackageStorageKind = "auto";
  let sourceUrl: string | undefined;
  let limit: number | undefined;
  let json = false;
  const positional: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--full") {
      requestedCoverage = "full";
    } else if (arg === "--partial") {
      requestedCoverage = "partial";
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--limit") {
      limit = parsePositiveInteger(args[++index], "--limit");
    } else if (arg.startsWith("--limit=")) {
      limit = parsePositiveInteger(arg.slice("--limit=".length), "--limit");
    } else if (arg === "--url") {
      sourceUrl = args[++index];
    } else if (arg.startsWith("--url=")) {
      sourceUrl = arg.slice("--url=".length);
    } else if (arg === "--index") {
      indexPath = path.resolve(expandHome(args[++index] ?? defaultIndexPath()));
    } else if (arg.startsWith("--index=")) {
      indexPath = path.resolve(expandHome(arg.slice("--index=".length)));
    } else if (arg === "--sqlite-db") {
      sqlitePath = path.resolve(expandHome(args[++index] ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      storageKind = parseStorageKind(args[++index] ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      storageKind = parseStorageKind(arg.slice("--storage=".length));
    } else {
      positional.push(arg);
    }
  }

  const registry = parseSyncableRegistry(positional[0]);
  if (!registry) {
    throw new Error("Usage: vibeguard packages sync <npm|pypi|cargo|gomod|maven> [--limit n] [--full|--partial] [--url URL]");
  }

  let npmSnapshot;
  if (registry === "npm") {
    try {
      npmSnapshot = await fetchNpmChangeSnapshot(sourceUrl);
    } catch {
      // A full sync remains valid when a mirror omits its optional replication snapshot endpoint.
    }
  }
  const syncResult = await fetchPackageNames({
    registry,
    sourceUrl,
    limit
  });
  const effectiveCoverage = requestedCoverage === "full" && !syncResult.truncated ? "full" : "partial";
  const storage = createPackageStorage({
    kind: storageKind,
    indexPath,
    sqlitePath
  });
  const syncMetadata = npmSnapshot ? { ...syncResult.syncMetadata, ...npmSnapshot } : syncResult.syncMetadata;
  const entry = await storage.packageIndex.importPackageNames(registry, syncResult.names, effectiveCoverage, syncMetadata);
  const payload = {
    ...entry,
    imported: syncResult.names.length,
    requestedCoverage,
    effectiveCoverage,
    truncated: syncResult.truncated,
    totalAvailable: syncResult.totalAvailable,
    pagesFetched: syncResult.pagesFetched,
    sourceUrl: syncResult.sourceUrl,
    format: syncResult.format,
    storage: storage.kind,
    path: storage.sqlitePath ?? storage.indexPath
  };

  if (json) {
    console.log(JSON.stringify(payload, null, 2));
    return;
  }

  console.log(
    `Synced ${payload.imported} ${registry} package name(s) from ${payload.format}; index now has ${payload.packageCount} package(s) with ${payload.coverage} coverage.`
  );
  if (payload.pagesFetched && payload.pagesFetched > 1) {
    console.log(`Fetched ${payload.pagesFetched} page(s) from the remote registry.`);
  }
  if (requestedCoverage === "full" && effectiveCoverage !== "full") {
    console.log("Requested full coverage but the remote result was truncated, so VibeGuard stored this as partial coverage.");
  }
  console.log(`${storage.kind === "sqlite" ? "SQLite DB" : "Index"}: ${payload.path}`);
}

async function syncConfiguredPackageIndexesCommand(args: string[]): Promise<void> {
  let configPath = defaultConfigPath();
  let configPathExplicit = false;
  let useConfig = true;
  let indexPath = defaultIndexPath();
  let sqlitePath = defaultSqlitePath();
  let storageKind: PackageStorageKind = "auto";
  let limit: number | undefined;
  let json = false;
  let force = false;
  let failFast = false;
  const sourceUrls: Partial<Record<PackageRegistry, string>> = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      json = true;
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "--fail-fast") {
      failFast = true;
    } else if (arg === "--no-config") {
      useConfig = false;
    } else if (arg === "--config") {
      configPath = path.resolve(expandHome(args[++index] ?? defaultConfigPath()));
      configPathExplicit = true;
    } else if (arg.startsWith("--config=")) {
      configPath = path.resolve(expandHome(arg.slice("--config=".length)));
      configPathExplicit = true;
    } else if (arg === "--limit") {
      limit = parsePositiveInteger(args[++index], "--limit");
    } else if (arg.startsWith("--limit=")) {
      limit = parsePositiveInteger(arg.slice("--limit=".length), "--limit");
    } else if (arg === "--url") {
      parseRegistrySourceUrl(args[++index], sourceUrls);
    } else if (arg.startsWith("--url=")) {
      parseRegistrySourceUrl(arg.slice("--url=".length), sourceUrls);
    } else if (arg === "--index") {
      indexPath = path.resolve(expandHome(args[++index] ?? defaultIndexPath()));
    } else if (arg.startsWith("--index=")) {
      indexPath = path.resolve(expandHome(arg.slice("--index=".length)));
    } else if (arg === "--sqlite-db") {
      sqlitePath = path.resolve(expandHome(args[++index] ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      storageKind = parseStorageKind(args[++index] ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      storageKind = parseStorageKind(arg.slice("--storage=".length));
    } else {
      throw new Error(`Unknown packages sync-config option: ${arg}`);
    }
  }

  const loadedConfig = useConfig
    ? await loadConfig(configPath)
    : {
        config: cloneDefaultConfig(),
        path: path.resolve(expandHome(configPath)),
        exists: false
      };
  if (useConfig && configPathExplicit && !loadedConfig.exists) {
    throw new Error(`Config file not found: ${loadedConfig.path}`);
  }

  const storage = createPackageStorage({
    kind: storageKind,
    indexPath,
    sqlitePath
  });
  const result = await syncConfiguredPackageIndexes({
    config: loadedConfig.config,
    storage,
    limit,
    force,
    sourceUrls,
    continueOnError: !failFast
  });

  if (json) {
    console.log(
      JSON.stringify(
        {
          ...result,
          configPath: loadedConfig.path,
          configExists: loadedConfig.exists
        },
        null,
        2
      )
    );
  } else {
    printConfiguredPackageSyncReport(result, loadedConfig.path, loadedConfig.exists);
  }

  if (result.results.some((entry) => entry.status === "failed")) {
    process.exitCode = 1;
  }
}

async function printPackageIndexStatus(args: string[]): Promise<void> {
  let indexPath = defaultIndexPath();
  let sqlitePath = defaultSqlitePath();
  let storageKind: PackageStorageKind = "auto";
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      json = true;
    } else if (arg === "--index") {
      indexPath = path.resolve(expandHome(args[++index] ?? defaultIndexPath()));
    } else if (arg.startsWith("--index=")) {
      indexPath = path.resolve(expandHome(arg.slice("--index=".length)));
    } else if (arg === "--sqlite-db") {
      sqlitePath = path.resolve(expandHome(args[++index] ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      storageKind = parseStorageKind(args[++index] ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      storageKind = parseStorageKind(arg.slice("--storage=".length));
    }
  }

  const storage = createPackageStorage({
    kind: storageKind,
    indexPath,
    sqlitePath
  });
  const stats = await storage.packageIndex.stats();
  if (json) {
    console.log(JSON.stringify({ storage: storage.kind, path: storage.sqlitePath ?? storage.indexPath, registries: stats }, null, 2));
    return;
  }
  console.log(`${storage.kind === "sqlite" ? "SQLite DB" : "Package index"}: ${storage.sqlitePath ?? storage.indexPath}`);
  if (stats.length === 0) {
    console.log("No indexed registries.");
    return;
  }
  for (const entry of stats) {
    console.log(
      `${entry.registry}: ${entry.packageCount} package(s), ${entry.coverage} coverage, updated ${new Date(entry.updatedAt).toISOString()}`
    );
  }
}

async function checkPackageIndex(args: string[]): Promise<void> {
  let indexPath = defaultIndexPath();
  let sqlitePath = defaultSqlitePath();
  let storageKind: PackageStorageKind = "auto";
  let json = false;
  const positional: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      json = true;
    } else if (arg === "--index") {
      indexPath = path.resolve(expandHome(args[++index] ?? defaultIndexPath()));
    } else if (arg.startsWith("--index=")) {
      indexPath = path.resolve(expandHome(arg.slice("--index=".length)));
    } else if (arg === "--sqlite-db") {
      sqlitePath = path.resolve(expandHome(args[++index] ?? defaultSqlitePath()));
    } else if (arg.startsWith("--sqlite-db=")) {
      sqlitePath = path.resolve(expandHome(arg.slice("--sqlite-db=".length)));
    } else if (arg === "--storage") {
      storageKind = parseStorageKind(args[++index] ?? "auto");
    } else if (arg.startsWith("--storage=")) {
      storageKind = parseStorageKind(arg.slice("--storage=".length));
    } else {
      positional.push(arg);
    }
  }

  const registry = parseRegistry(positional[0]);
  const packageName = positional[1];
  if (!registry || !packageName) {
    throw new Error("Usage: vibeguard packages check <registry> <package> [--index path]");
  }

  const storage = createPackageStorage({
    kind: storageKind,
    indexPath,
    sqlitePath
  });
  const exists = await storage.packageIndex.get(registry, packageName);
  const coverage = await storage.packageIndex.coverage(registry);
  if (json) {
    console.log(JSON.stringify({ registry, packageName, exists, coverage, storage: storage.kind, path: storage.sqlitePath ?? storage.indexPath }, null, 2));
    return;
  }
  const status = exists === true ? "exists" : exists === false ? "missing" : "unknown";
  console.log(`${registry}:${packageName} is ${status} in ${coverage ?? "no"} local index coverage.`);
}

function printConfiguredPackageSyncReport(
  result: ConfiguredPackageSyncResult,
  configPath: string,
  configExists: boolean
): void {
  const mode = result.lightweightMode ? "lightweight" : "full";
  console.log(
    `Config-driven package sync (${mode}, ${result.updateInterval}) using ${result.storage} storage: ${result.path}`
  );
  console.log(`Config: ${configPath}${configExists ? "" : " (defaults; file not found)"}`);
  if (result.results.length === 0) {
    console.log("No registries configured in package_cache.languages.");
    return;
  }

  for (const entry of result.results) {
    if (entry.status === "skipped") {
      const status = entry.reason === "not-modified" ? "registry not modified (304), skipped" : "fresh, skipped";
      console.log(
        `${entry.registry}: ${status} (${entry.packageCount ?? 0} package(s), ${entry.coverage ?? "unknown"} coverage, updated ${formatTimestamp(entry.updatedAt)})`
      );
    } else if (entry.status === "synced") {
      if (entry.incremental) {
        console.log(
          `${entry.registry}: applied ${entry.additions ?? 0} addition(s) and ${entry.removals ?? 0} removal(s) from ${entry.changesFetched ?? 0} incremental change(s), ${entry.coverage ?? entry.effectiveCoverage ?? "partial"} coverage (${entry.reason})`
        );
      } else {
        console.log(
          `${entry.registry}: synced ${entry.imported ?? 0} package name(s), ${entry.coverage ?? entry.effectiveCoverage ?? "partial"} coverage (${entry.reason})`
        );
      }
      if (entry.pagesFetched && entry.pagesFetched > 1) {
        console.log(`${entry.registry}: fetched ${entry.pagesFetched} page(s).`);
      }
      if (entry.requestedCoverage === "full" && entry.effectiveCoverage !== "full") {
        console.log(`${entry.registry}: remote result was truncated, so VibeGuard stored partial coverage.`);
      }
    } else {
      console.log(`${entry.registry}: sync failed (${entry.reason}): ${entry.error}`);
    }
  }
}

function parseRegistrySourceUrl(value: string | undefined, target: Partial<Record<PackageRegistry, string>>): void {
  const separatorIndex = value?.indexOf("=") ?? -1;
  const registry = parseSyncableRegistry(separatorIndex > 0 ? value?.slice(0, separatorIndex) : undefined);
  const sourceUrl = separatorIndex > 0 ? value?.slice(separatorIndex + 1) : undefined;
  if (!registry || !sourceUrl) {
    throw new Error("Expected --url <npm|pypi|cargo|gomod|maven>=URL.");
  }
  target[registry] = sourceUrl;
}

function formatTimestamp(timestamp: number | undefined): string {
  return timestamp ? new Date(timestamp).toISOString() : "unknown";
}

function parseRegistry(value: string | undefined): PackageRegistry | undefined {
  if (value && ["npm", "pypi", "cargo", "gomod", "maven"].includes(value)) {
    return value as PackageRegistry;
  }
  return undefined;
}

function parseSyncableRegistry(value: string | undefined): SyncableRegistry | undefined {
  if (value && ["npm", "pypi", "cargo", "gomod", "maven"].includes(value)) {
    return value as SyncableRegistry;
  }
  return undefined;
}

function parseLlmProvider(value: string): LlmProvider {
  if (value === "deepseek" || value === "claude" || value === "openai" || value === "local" || value === "vibeguard") {
    return value;
  }
  throw new Error("LLM provider must be one of deepseek, claude, openai, local, vibeguard.");
}

async function createCliL3Analyzer(
  provider: LlmProvider,
  model?: string,
  baseUrl?: string,
  apiKeyEnv?: string
): Promise<LlmSemanticAnalyzer | undefined> {
  const apiKey = getLlmApiKeyFromEnv(provider, apiKeyEnv) ?? (await readStoredLlmCredential(provider))?.apiKey;
  if (provider !== "local" && !apiKey) {
    return undefined;
  }
  return new LlmSemanticAnalyzer({
    provider,
    apiKey,
    model,
    baseUrl
  });
}

function parsePositiveInteger(value: string | undefined, name: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return parsed;
}

function parseNonNegativeInteger(value: string | undefined, name: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer.`);
  }
  return parsed;
}

async function collectFiles(pathsToScan: string[]): Promise<string[]> {
  const files: string[] = [];
  for (const target of pathsToScan) {
    const stat = await fs.stat(target);
    if (stat.isDirectory()) {
      files.push(...(await collectDirectory(target)));
    } else if (isSupportedFile(target)) {
      files.push(target);
    }
  }
  return files.sort();
}

async function resolveGitCwd(pathsToScan: string[]): Promise<string> {
  if (pathsToScan.length !== 1) {
    return process.cwd();
  }
  const target = path.resolve(pathsToScan[0]);
  try {
    const stat = await fs.stat(target);
    return stat.isDirectory() ? target : path.dirname(target);
  } catch {
    return process.cwd();
  }
}

async function collectDirectory(directory: string): Promise<string[]> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        files.push(...(await collectDirectory(path.join(directory, entry.name))));
      }
    } else {
      const filePath = path.join(directory, entry.name);
      if (isSupportedFile(filePath)) {
        files.push(filePath);
      }
    }
  }
  return files;
}

function isSupportedFile(filePath: string): boolean {
  const fileName = path.basename(filePath).toLowerCase();
  return supportedFileNames.has(fileName) || supportedExtensions.has(extensionOf(filePath));
}

function printHelp(): void {
  console.log(`VibeGuard

Usage:
  vibeguard scan [paths...] [--json|--format human|json|sarif|markdown] [--output path]
                 [--sarif path] [--markdown path] [--github-annotations]
                 [--mode full-scan|ai-code-scan] [--ai-detection author|message|aggressive]
                 [--base-ref ref] [--head-ref ref]
                 [--fail-on critical|high|medium|low|info|none]
                 [--package-verification seed|remote|off] [--ignore-rules path]
                 [--custom-rules path] [--config path] [--no-config]
                 [--storage auto|json|sqlite] [--package-index path] [--sqlite-db path]
                 [--no-ignore] [--dedup-existing-tools|--no-dedup-existing-tools]
                 [--findings-db path] [--no-store-findings]
                 [--findings-project project-id]
                 [--findings-endpoint https://dashboard.example.com/api/ingest]
                 [--findings-token-env ENV_VAR] [--findings-upload-required]
                 [--no-l2] [--l2] [--l3] [--no-l3]
                 [--llm-provider deepseek|claude|openai|local|vibeguard] [--llm-model name]
                 [--llm-base-url url] [--llm-api-key-env ENV_VAR]
  vibeguard config init [--path path] [--force]
  vibeguard config path
  vibeguard config ignore-finding <finding-id> [--path path]
  vibeguard config unignore-finding <finding-id> [--path path]
  vibeguard findings <status|list|summary|dashboard|compliance|audit|serve|prune> [--db path] [--json]
  vibeguard llm-key <set|delete|status> [--provider provider] [--config path]
  vibeguard subscription status [--api-key-env ENV_VAR] [--base-url URL] [--json]
  vibeguard ignore-rules <add-rule|add-package> ...
  vibeguard packages <import|sync|sync-config|status|check> ...
  vibeguard rules export-semgrep [--output path] [--prefix id-prefix]

Examples:
  vibeguard scan .
  vibeguard scan src --l3
  DEEPSEEK_API_KEY=... vibeguard scan src --l3 --llm-provider deepseek
  VIBEGUARD_PRO_API_KEY=... vibeguard scan src --l3 --llm-provider vibeguard
  vibeguard llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
  vibeguard llm-key status --provider deepseek
  VIBEGUARD_PRO_API_KEY=... vibeguard subscription status
  vibeguard scan src --json --package-verification remote --fail-on high
  vibeguard scan . --sarif vibeguard.sarif --github-annotations
  vibeguard scan . --markdown vibeguard-report.md
  vibeguard scan . --mode ai-code-scan --base-ref origin/main --head-ref HEAD
  vibeguard scan src --custom-rules ./vibeguard-rules.yml
  vibeguard findings list --limit 20
  vibeguard findings summary --days 30
  vibeguard findings dashboard --days 30 --output vibeguard-dashboard.html
  vibeguard findings compliance --framework all --days 90 --output vibeguard-compliance-report.md
  vibeguard findings audit --limit 100
  VIBEGUARD_DASHBOARD_TOKEN=... vibeguard findings serve --db ./findings.db --token-env VIBEGUARD_DASHBOARD_TOKEN
  VIBEGUARD_FINDINGS_INGEST_TOKEN=... vibeguard findings serve --ingest-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN
  VIBEGUARD_FINDINGS_INGEST_TOKEN=... vibeguard scan . --no-store-findings --findings-project acme/payments-api --findings-endpoint https://guard.example.com/api/ingest --findings-upload-required
  VIBEGUARD_OIDC_ISSUER=... VIBEGUARD_OIDC_CLIENT_ID=... VIBEGUARD_OIDC_SESSION_SECRET=... vibeguard findings serve --oidc-issuer-env VIBEGUARD_OIDC_ISSUER --oidc-client-id-env VIBEGUARD_OIDC_CLIENT_ID --oidc-session-secret-env VIBEGUARD_OIDC_SESSION_SECRET
  vibeguard ignore-rules add-rule insecure_config_debug_true --path "**/test_*" --reason not_issue
  vibeguard ignore-rules add-package npm @company/private-utils
  vibeguard config init
  vibeguard rules export-semgrep --output vibeguard-semgrep.yml
  vibeguard packages import npm ./npm-packages.txt --partial
  vibeguard packages sync npm --limit 100000 --partial
  vibeguard packages sync-config --config ~/.vibeguard/config.json
  vibeguard scan src --package-index ~/.vibeguard/package-index.json.gz
`);
}

function printPackagesHelp(): void {
  console.log(`VibeGuard package index

Usage:
  vibeguard packages import <registry> <file> [--full|--partial] [--index path] [--json]
  vibeguard packages sync <npm|pypi|cargo|gomod|maven> [--limit n] [--full|--partial] [--url URL]
                          [--storage auto|json|sqlite] [--index path] [--sqlite-db path] [--json]
  vibeguard packages sync-config [--config path] [--force] [--limit n] [--url registry=URL]
                                 [--storage auto|json|sqlite] [--index path] [--sqlite-db path] [--json]
  vibeguard packages status [--storage auto|json|sqlite] [--index path] [--sqlite-db path] [--json]
  vibeguard packages check <registry> <package> [--storage auto|json|sqlite] [--index path] [--sqlite-db path] [--json]

Supported import formats:
  - newline-delimited package names
  - JSON array of package names
  - JSON object with packages: [...]
  - npm _all_docs style JSON object with rows: [{ id }]

Remote sync defaults:
  - npm: https://replicate.npmjs.com/_all_docs
  - pypi: https://pypi.org/simple/
  - cargo: https://crates.io/api/v1/crates
  - gomod: https://index.golang.org/index
  - maven: https://search.maven.org/solrsearch/select?q=*:*&rows=100&wt=json

Config-driven sync reads package_cache.languages, update_interval, and lightweight_mode from config.json.
Cargo and Maven sync paginate when needed. Lightweight mode uses a 100000-name partial index target where supported; Cargo currently uses a 100-name page cap.
`);
}

function printRulesHelp(): void {
  console.log(`VibeGuard rules

Usage:
  vibeguard rules export-semgrep [--output path] [--prefix id-prefix]

Examples:
  vibeguard rules export-semgrep
  vibeguard rules export-semgrep --output vibeguard-semgrep.yml
`);
}

function printConfigHelp(): void {
  console.log(`VibeGuard config

Usage:
  vibeguard config init [--path path] [--force]
  vibeguard config path
  vibeguard config ignore-finding <finding-id> [--path path]
  vibeguard config unignore-finding <finding-id> [--path path]

Scan defaults:
  vibeguard scan . --config ~/.vibeguard/config.json
  vibeguard scan . --no-config
`);
}

function printFindingsHelp(): void {
  console.log(`VibeGuard findings

Usage:
  vibeguard findings status [--db path] [--project id] [--json]
  vibeguard findings list [--db path] [--project id] [--limit n] [--all] [--json]
  vibeguard findings summary [--db path] [--project id] [--days n] [--top n] [--json]
  vibeguard findings dashboard [--db path] [--project id] [--days n] [--top n] [--output path] [--json]
  vibeguard findings compliance [--db path] [--project id] [--framework soc2|iso27001|all] [--days n] [--top n] [--output path] [--json]
  vibeguard findings audit [--db path] [--limit n] [--json]
  vibeguard findings serve [--db path] [--project id] [--host 127.0.0.1] [--port 8787] [--days n] [--top n]
                           [--token-env ENV_VAR]
                           [--ingest-token-env ENV_VAR] [--ingest-max-findings n]
                           [--telemetry-collection] [--telemetry-max-events-per-minute n]
                           [--oidc-issuer-env ENV_VAR --oidc-client-id-env ENV_VAR --oidc-session-secret-env ENV_VAR]
                           [--oidc-client-secret-env ENV_VAR] [--oidc-role-claim path]
                           [--oidc-role claim-value=viewer|analyst|admin] [--oidc-default-role none|viewer|analyst|admin]
                           [--public-url https://dashboard.example.com] [--secure-cookies|--no-secure-cookies]
  vibeguard findings prune [--db path] [--days n] [--json]

Scan storage:
  vibeguard scan . --findings-db ~/.vibeguard/findings.db
  vibeguard scan . --no-store-findings
  VIBEGUARD_FINDINGS_INGEST_TOKEN=... vibeguard scan . --findings-project acme/payments-api --findings-endpoint https://dashboard.example.com/api/ingest
`);
}

function printSubscriptionHelp(): void {
  console.log(`VibeGuard subscription

Usage:
  vibeguard subscription status [--api-key-env ENV_VAR] [--base-url URL] [--json]

The Pro credential is read from VIBEGUARD_PRO_API_KEY by default. The hosted service
enforces official L3 request allowances; BYOK and local LLM modes remain available.
`);
}

function printLlmKeyHelp(): void {
  console.log(`VibeGuard LLM credential storage

Usage:
  vibeguard llm-key set [--provider deepseek|claude|openai|vibeguard] (--stdin|--from-env ENV_VAR) [--pin-env PIN_ENV] [--config path] [--json]
  vibeguard llm-key delete [--provider provider] [--pin-env PIN_ENV] [--config path] [--json]
  vibeguard llm-key status [--provider provider] [--pin-env PIN_ENV] [--config path] [--json]

The CLI never accepts a plaintext key argument. It stores credentials in Windows DPAPI,
macOS Keychain, or the Linux Secret Service. If that service is unavailable, set
VIBEGUARD_LLM_CREDENTIAL_PIN (or --pin-env) to allow an AES-256-GCM encrypted fallback
bound to the machine identifier. Environment variables still take precedence for one-off
scans and CI. Local Ollama does not require a credential.

Examples:
  vibeguard llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
  VIBEGUARD_LLM_CREDENTIAL_PIN=... vibeguard llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
  printf %s "$OPENAI_API_KEY" | vibeguard llm-key set --provider openai --stdin
  vibeguard llm-key delete --provider deepseek
`);
}

function printIgnoreRulesHelp(): void {
  console.log(`VibeGuard ignore rules

Usage:
  vibeguard ignore-rules add-rule <rule-id-or-type> [--path glob] [--scope file:glob] [--line n]
                                   [--reason false_positive|not_issue|internal_package|text]
                                   [--ignore-rules path] [--config path] [--json]
  vibeguard ignore-rules add-package <npm|pypi|cargo|gomod|maven> <package>
                                      [--reason false_positive|not_issue|internal_package|text]
                                      [--no-reason] [--ignore-rules path] [--config path] [--json]

Examples:
  vibeguard ignore-rules add-rule insecure_config_debug_true --path "**/test_*" --reason not_issue
  vibeguard ignore-rules add-rule sql_injection --path "migrations/**" --reason "generated migration"
  vibeguard ignore-rules add-package npm @company/private-utils
`);
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
