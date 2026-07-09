#!/usr/bin/env node
import fs from "fs/promises";
import path from "path";
import { loadCustomRules } from "./customRules";
import { filterScanFiles, type AiDetectionMode, type ScanMode } from "./gitFilter";
import { defaultIgnoreRulesPath, expandHome, loadIgnoreRules } from "./ignore";
import { defaultIndexPath } from "./package/cache";
import { readPackageNameFile } from "./package/importer";
import { PackageVerifier } from "./package/packageVerifier";
import { createPackageStorage, type PackageStorageKind } from "./package/storage";
import { fetchPackageNames, type SyncableRegistry } from "./package/sync";
import { defaultSqlitePath } from "./package/sqliteStore";
import {
  buildScanReport,
  formatGithubAnnotations,
  formatHumanReport,
  formatJsonReport,
  formatSarifReport
} from "./reporters";
import { scanSourceFile } from "./scanner";
import { formatSemgrepRules } from "./semgrep";
import type { Finding, PackageRegistry, Severity } from "./types";
import { extensionOf, severityMeetsThreshold } from "./utils";

type ReportFormat = "human" | "json" | "sarif";

interface CliOptions {
  paths: string[];
  mode: ScanMode;
  aiDetection: AiDetectionMode;
  baseRef?: string;
  headRef?: string;
  reportFormat: ReportFormat;
  outputPath?: string;
  sarifPath?: string;
  githubAnnotations: boolean;
  failOn: Severity | "none";
  packageVerification: "off" | "seed" | "remote";
  includeSast: boolean;
  includeL3: boolean;
  ignoreRulesPath?: string;
  customRulePaths: string[];
  packageIndexPath?: string;
  sqlitePath?: string;
  storage: PackageStorageKind;
  useIgnoreRules: boolean;
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
  "build.gradle.kts"
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

  const options = parseArgs(args);
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
  const customRules = await loadCustomRules(options.customRulePaths);
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

  for (const filePath of files) {
    const text = await fs.readFile(filePath, "utf8");
    const result = await scanSourceFile(
      {
        filePath,
        text
      },
      {
        packageVerification: options.packageVerification,
        includeSast: options.includeSast,
        includeL3: options.includeL3,
        packageVerifier: verifier,
        customRules,
        ignoreRules
      }
    );
    allFindings.push(...result.findings);
  }

  const report = buildScanReport(allFindings);
  if (options.githubAnnotations) {
    const annotations = formatGithubAnnotations(report.findings, process.cwd());
    if (annotations) {
      process.stderr.write(`${annotations}\n`);
    }
  }
  if (options.sarifPath) {
    await writeTextFile(options.sarifPath, formatSarifReport(report, process.cwd()));
  }
  await emitPrimaryReport(options, report, files.length);

  const shouldFail = allFindings.some((finding) => !finding.dismissed && severityMeetsThreshold(finding.severity, options.failOn));
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

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    paths: [],
    mode: "full-scan",
    aiDetection: "author",
    reportFormat: "human",
    githubAnnotations: false,
    failOn: "critical",
    packageVerification: "seed",
    includeSast: true,
    includeL3: false,
    customRulePaths: [],
    storage: "auto",
    useIgnoreRules: true
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
    } else if (arg === "--github-annotations") {
      options.githubAnnotations = true;
    } else if (arg === "--no-github-annotations") {
      options.githubAnnotations = false;
    } else if (arg === "--no-l2") {
      options.includeSast = false;
    } else if (arg === "--l3") {
      options.includeL3 = true;
    } else if (arg === "--no-l3") {
      options.includeL3 = false;
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
  if (value === "human" || value === "json" || value === "sarif") {
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

function formatPrimaryReport(format: ReportFormat, report: ReturnType<typeof buildScanReport>, fileCount: number): string {
  if (format === "json") {
    return formatJsonReport(report);
  }
  if (format === "sarif") {
    return formatSarifReport(report, process.cwd());
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
    throw new Error("Usage: vibeguard packages sync <npm|pypi> [--limit n] [--full|--partial] [--url URL]");
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
  const entry = await storage.packageIndex.importPackageNames(registry, syncResult.names, effectiveCoverage);
  const payload = {
    ...entry,
    imported: syncResult.names.length,
    requestedCoverage,
    effectiveCoverage,
    truncated: syncResult.truncated,
    totalAvailable: syncResult.totalAvailable,
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
  if (requestedCoverage === "full" && effectiveCoverage !== "full") {
    console.log("Requested full coverage but the remote result was truncated, so VibeGuard stored this as partial coverage.");
  }
  console.log(`${storage.kind === "sqlite" ? "SQLite DB" : "Index"}: ${payload.path}`);
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

function parseRegistry(value: string | undefined): PackageRegistry | undefined {
  if (value && ["npm", "pypi", "cargo", "gomod", "maven"].includes(value)) {
    return value as PackageRegistry;
  }
  return undefined;
}

function parseSyncableRegistry(value: string | undefined): SyncableRegistry | undefined {
  if (value === "npm" || value === "pypi") {
    return value;
  }
  return undefined;
}

function parsePositiveInteger(value: string | undefined, name: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer.`);
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
  vibeguard scan [paths...] [--json|--format human|json|sarif] [--output path]
                 [--sarif path] [--github-annotations]
                 [--mode full-scan|ai-code-scan] [--ai-detection author|message|aggressive]
                 [--base-ref ref] [--head-ref ref]
                 [--fail-on critical|high|medium|low|info|none]
                 [--package-verification seed|remote|off] [--ignore-rules path]
                 [--custom-rules path]
                 [--storage auto|json|sqlite] [--package-index path] [--sqlite-db path]
                 [--no-ignore] [--no-l2] [--l3]
  vibeguard packages <import|sync|status|check> ...
  vibeguard rules export-semgrep [--output path] [--prefix id-prefix]

Examples:
  vibeguard scan .
  vibeguard scan src --l3
  vibeguard scan src --json --package-verification remote --fail-on high
  vibeguard scan . --sarif vibeguard.sarif --github-annotations
  vibeguard scan . --mode ai-code-scan --base-ref origin/main --head-ref HEAD
  vibeguard scan src --custom-rules ./vibeguard-rules.yml
  vibeguard rules export-semgrep --output vibeguard-semgrep.yml
  vibeguard packages import npm ./npm-packages.txt --partial
  vibeguard packages sync npm --limit 100000 --partial
  vibeguard scan src --package-index ~/.vibeguard/package-index.json
`);
}

function printPackagesHelp(): void {
  console.log(`VibeGuard package index

Usage:
  vibeguard packages import <registry> <file> [--full|--partial] [--index path] [--json]
  vibeguard packages sync <npm|pypi> [--limit n] [--full|--partial] [--url URL]
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

void main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
