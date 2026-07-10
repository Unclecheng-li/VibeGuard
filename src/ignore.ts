import fs from "fs/promises";
import os from "os";
import path from "path";
import { parse } from "yaml";
import { minimatch } from "minimatch";
import type { Finding, IgnoreRuleEntry, IgnoreRules, PackageRegistry } from "./types";

export const emptyIgnoreRules: IgnoreRules = {
  ignore: []
};

export type IgnoreReasonPreset = "false_positive" | "not_issue" | "internal_package";

export interface IgnoreReasonOption {
  id: IgnoreReasonPreset;
  label: string;
  reason: string;
}

export const standardIgnoreReasons: IgnoreReasonOption[] = [
  {
    id: "false_positive",
    label: "False positive",
    reason: "False positive"
  },
  {
    id: "not_issue",
    label: "Not an issue",
    reason: "Not an issue"
  },
  {
    id: "internal_package",
    label: "Internal package",
    reason: "Internal package"
  }
];

export function defaultIgnoreRulesPath(): string {
  return path.join(os.homedir(), ".vibeguard", "ignore-rules.yml");
}

export function expandHome(inputPath: string): string {
  if (inputPath === "~") {
    return os.homedir();
  }
  if (inputPath.startsWith("~/") || inputPath.startsWith("~\\")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }
  return inputPath;
}

export async function loadIgnoreRules(filePath: string = defaultIgnoreRulesPath()): Promise<IgnoreRules> {
  try {
    const raw = await fs.readFile(expandHome(filePath), "utf8");
    return parseIgnoreRules(raw);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return emptyIgnoreRules;
    }
    throw error;
  }
}

export function parseIgnoreRules(raw: string): IgnoreRules {
  const parsed = parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    return emptyIgnoreRules;
  }

  const ignore = (parsed as { ignore?: unknown }).ignore;
  if (!Array.isArray(ignore)) {
    return emptyIgnoreRules;
  }

  return {
    ignore: ignore.map(normalizeRule).filter((rule): rule is IgnoreRuleEntry => Boolean(rule))
  };
}

export function applyIgnoreRules(findings: Finding[], rules: IgnoreRules | undefined): Finding[] {
  if (!rules || rules.ignore.length === 0) {
    return findings;
  }

  return findings.map((finding) => {
    const matched = rules.ignore.find((rule) => matchesIgnoreRule(finding, rule));
    if (!matched) {
      return finding;
    }
    return {
      ...finding,
      dismissed: true,
      dismissed_reason: matched.reason ?? "Matched ignore-rules.yml"
    };
  });
}

export function applyIgnoredFindingIds(findings: Finding[], findingIds: string[] | undefined): Finding[] {
  const ids = new Set((findingIds ?? []).filter(Boolean));
  if (ids.size === 0) {
    return findings;
  }

  return findings.map((finding) => {
    if (finding.dismissed || !ids.has(finding.id)) {
      return finding;
    }
    return {
      ...finding,
      dismissed: true,
      dismissed_reason: "Matched config.ignored_findings"
    };
  });
}

export function matchesIgnoreRule(finding: Finding, rule: IgnoreRuleEntry): boolean {
  if (!matchesRuleId(finding, rule)) {
    return false;
  }
  if (!matchesLine(finding, rule)) {
    return false;
  }
  if (!matchesPackage(finding, rule)) {
    return false;
  }
  return matchesPath(finding, rule);
}

export async function ensureIgnoreRulesFile(filePath: string = defaultIgnoreRulesPath()): Promise<string> {
  const resolved = expandHome(filePath);
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  try {
    await fs.access(resolved);
  } catch {
    await fs.writeFile(resolved, "ignore:\n", "utf8");
  }
  return resolved;
}

export async function appendIgnoreRule(rule: IgnoreRuleEntry, filePath: string = defaultIgnoreRulesPath()): Promise<string> {
  const resolved = await ensureIgnoreRulesFile(filePath);
  const lines = ["", "  -"];
  if (rule.rule) {
    lines.push(`    rule: ${quoteYaml(rule.rule)}`);
  }
  if (rule.path) {
    lines.push(`    path: ${quoteYaml(normalizePath(rule.path))}`);
  }
  if (rule.scope) {
    lines.push(`    scope: ${quoteYaml(rule.scope)}`);
  }
  if (rule.line !== undefined) {
    lines.push(`    line: ${rule.line}`);
  }
  if (rule.package) {
    lines.push(`    package: ${quoteYaml(rule.package)}`);
  }
  if (rule.registry) {
    lines.push(`    registry: ${quoteYaml(rule.registry)}`);
  }
  if (rule.reason) {
    lines.push(`    reason: ${quoteYaml(rule.reason)}`);
  }
  await fs.appendFile(resolved, `${lines.join("\n")}\n`, "utf8");
  return resolved;
}

export function normalizeIgnoreReason(input: string | undefined, fallback?: string): string | undefined {
  const value = input?.trim();
  if (!value) {
    return fallback;
  }
  const normalized = value.toLowerCase().replace(/[\s-]+/g, "_");
  const matched = standardIgnoreReasons.find(
    (option) => option.id === normalized || option.label.toLowerCase() === value.toLowerCase()
  );
  return matched?.reason ?? value;
}

export function scopedIgnoreReason(reason: string | undefined, scope: "line" | "file" | "global" | "package"): string | undefined {
  const normalized = normalizeIgnoreReason(reason);
  if (!normalized) {
    return undefined;
  }
  const suffix =
    scope === "line"
      ? "line"
      : scope === "file"
        ? "file"
        : scope === "global"
          ? "global rule"
          : "package";
  return `${normalized} (${suffix} ignore)`;
}

function normalizeRule(value: unknown): IgnoreRuleEntry | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const input = value as Record<string, unknown>;
  const rules = Array.isArray(input.rules) ? input.rules.filter(isString) : undefined;
  const registry = isString(input.registry) && isRegistry(input.registry) ? input.registry : undefined;
  const line = typeof input.line === "number" ? input.line : undefined;
  return {
    rule: isString(input.rule) ? input.rule : undefined,
    rules,
    path: isString(input.path) ? input.path : undefined,
    scope: isString(input.scope) ? input.scope : undefined,
    line,
    package: isString(input.package) ? input.package : undefined,
    registry,
    reason: isString(input.reason) ? input.reason : undefined
  };
}

function matchesRuleId(finding: Finding, rule: IgnoreRuleEntry): boolean {
  const ruleIds = [rule.rule, ...(rule.rules ?? [])].filter(isString);
  if (ruleIds.length === 0) {
    return true;
  }
  return ruleIds.some((ruleId) => ruleId === finding.detection_rule || ruleId === finding.type);
}

function matchesLine(finding: Finding, rule: IgnoreRuleEntry): boolean {
  return rule.line === undefined || rule.line === finding.line;
}

function matchesPackage(finding: Finding, rule: IgnoreRuleEntry): boolean {
  if (!rule.package && !rule.registry) {
    return true;
  }
  if (finding.type !== "hallucinated_package") {
    return false;
  }
  const registry = finding.detection_rule.replace(/^hallucinated_package_/, "");
  if (rule.registry && rule.registry !== registry) {
    return false;
  }
  if (!rule.package) {
    return true;
  }
  return normalizePackageName(rule.package) === normalizePackageName(finding.evidence);
}

function matchesPath(finding: Finding, rule: IgnoreRuleEntry): boolean {
  const scopePath = parseFileScope(rule.scope);
  const pattern = rule.path ?? scopePath;
  if (!pattern) {
    return true;
  }

  const normalizedFile = normalizePath(finding.file);
  const normalizedPattern = normalizePath(expandHome(pattern));
  const basename = path.basename(normalizedFile);
  return (
    minimatch(normalizedFile, normalizedPattern, { nocase: true, dot: true, matchBase: true }) ||
    minimatch(basename, normalizedPattern, { nocase: true, dot: true, matchBase: true }) ||
    normalizedFile.endsWith(stripGlobPrefix(normalizedPattern))
  );
}

function parseFileScope(scope: string | undefined): string | undefined {
  if (!scope?.startsWith("file:")) {
    return undefined;
  }
  return scope.slice("file:".length);
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/");
}

function stripGlobPrefix(value: string): string {
  return value.replace(/^\*\*\//, "").replace(/^\*\//, "");
}

function normalizePackageName(value: string): string {
  return value.trim().toLowerCase().replace(/_/g, "-");
}

function quoteYaml(value: string): string {
  return JSON.stringify(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isRegistry(value: string): value is PackageRegistry {
  return ["npm", "pypi", "cargo", "gomod", "maven"].includes(value);
}
