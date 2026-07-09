#!/usr/bin/env node
import fs from "fs/promises";
import path from "path";
import { defaultIgnoreRulesPath, expandHome, loadIgnoreRules } from "./ignore";
import { JsonPackageCache, defaultCachePath } from "./package/cache";
import { PackageVerifier } from "./package/packageVerifier";
import { scanSourceFile } from "./scanner";
import type { Finding, Severity } from "./types";
import { extensionOf, severityMeetsThreshold } from "./utils";

interface CliOptions {
  paths: string[];
  json: boolean;
  failOn: Severity | "none";
  packageVerification: "off" | "seed" | "remote";
  includeSast: boolean;
  ignoreRulesPath?: string;
  useIgnoreRules: boolean;
}

const supportedExtensions = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "json", "toml", "txt"]);
const supportedFileNames = new Set(["package.json", "requirements.txt", "pyproject.toml"]);
const ignoredDirectories = new Set(["node_modules", ".git", "out", "dist", "build", "coverage", ".vscode-test"]);

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const verifier = new PackageVerifier({
    cache: new JsonPackageCache(defaultCachePath())
  });
  const ignoreRules = options.useIgnoreRules ? await loadIgnoreRules(options.ignoreRulesPath) : undefined;
  const files = await collectFiles(options.paths);
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
        packageVerifier: verifier,
        ignoreRules
      }
    );
    allFindings.push(...result.findings);
  }

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          findings: allFindings,
          count: allFindings.length,
          activeCount: activeFindings(allFindings).length,
          dismissedCount: dismissedFindings(allFindings).length
        },
        null,
        2
      )
    );
  } else {
    printHumanReport(allFindings, files.length);
  }

  const shouldFail = activeFindings(allFindings).some((finding) => severityMeetsThreshold(finding.severity, options.failOn));
  process.exitCode = shouldFail ? 1 : 0;
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = {
    paths: [],
    json: false,
    failOn: "critical",
    packageVerification: "seed",
    includeSast: true,
    useIgnoreRules: true
  };

  const rest = [...args];
  if (rest[0] === "scan") {
    rest.shift();
  }

  while (rest.length > 0) {
    const arg = rest.shift() ?? "";
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--no-l2") {
      options.includeSast = false;
    } else if (arg === "--fail-on") {
      options.failOn = parseSeverity(rest.shift() ?? "critical");
    } else if (arg.startsWith("--fail-on=")) {
      options.failOn = parseSeverity(arg.slice("--fail-on=".length));
    } else if (arg === "--package-verification") {
      options.packageVerification = parsePackageVerification(rest.shift() ?? "seed");
    } else if (arg.startsWith("--package-verification=")) {
      options.packageVerification = parsePackageVerification(arg.slice("--package-verification=".length));
    } else if (arg === "--ignore-rules") {
      options.ignoreRulesPath = path.resolve(expandHome(rest.shift() ?? defaultIgnoreRulesPath()));
    } else if (arg.startsWith("--ignore-rules=")) {
      options.ignoreRulesPath = path.resolve(expandHome(arg.slice("--ignore-rules=".length)));
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

function printHumanReport(findings: Finding[], fileCount: number): void {
  const active = activeFindings(findings);
  const dismissed = dismissedFindings(findings);
  console.log(`VibeGuard scanned ${fileCount} file(s).`);
  if (findings.length === 0) {
    console.log("No findings.");
    return;
  }

  console.log(`${active.length} active finding(s), ${dismissed.length} dismissed.`);
  for (const finding of active) {
    console.log(
      `[${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.message}`
    );
    console.log(`  ${finding.detection_rule} (${finding.detection_layer})`);
    if (finding.suggestion) {
      console.log(`  ${finding.suggestion}`);
    }
  }
  if (dismissed.length > 0) {
    console.log("");
    console.log("Dismissed findings:");
    for (const finding of dismissed) {
      console.log(
        `[DISMISSED:${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.message}`
      );
      console.log(`  ${finding.dismissed_reason ?? "Matched ignore rule"}`);
    }
  }
}

function printHelp(): void {
  console.log(`VibeGuard

Usage:
  vibeguard scan [paths...] [--json] [--fail-on critical|high|medium|low|info|none]
                 [--package-verification seed|remote|off] [--ignore-rules path]
                 [--no-ignore] [--no-l2]

Examples:
  vibeguard scan .
  vibeguard scan src --json --package-verification remote --fail-on high
`);
}

function activeFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => !finding.dismissed);
}

function dismissedFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => finding.dismissed);
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 2;
});
