import fs from "fs/promises";
import path from "path";
import { parse } from "yaml";
import type { DetectionLayer, Finding, FindingType, Severity, SourceFile } from "./types";
import { createFinding, extensionOf } from "./utils";

export interface CustomRule {
  id: string;
  pattern: string;
  flags?: string;
  severity: Severity;
  type: FindingType;
  message: string;
  suggestion?: string;
  detectionLayer: DetectionLayer;
  languages?: string[];
}

export interface CustomRuleset {
  rules: CustomRule[];
}

const severities = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const findingTypes = new Set<FindingType>([
  "hallucinated_package",
  "hardcoded_secret",
  "insecure_config",
  "ai_pattern_error",
  "sql_injection",
  "xss",
  "ssrf",
  "path_traversal",
  "insecure_deserialization",
  "command_injection",
  "missing_security_measure",
  "other"
]);
const detectionLayers = new Set<DetectionLayer>(["L1", "L2", "L3"]);

export async function loadCustomRules(paths: string[]): Promise<CustomRule[]> {
  const rules: CustomRule[] = [];
  for (const filePath of paths) {
    const raw = await fs.readFile(filePath, "utf8");
    rules.push(...parseCustomRules(raw, filePath).rules);
  }
  return rules;
}

export function parseCustomRules(raw: string, sourceName = "custom rules"): CustomRuleset {
  const parsed = parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`${sourceName}: expected a YAML object with rules.`);
  }
  const rules = (parsed as { rules?: unknown }).rules;
  if (!Array.isArray(rules)) {
    throw new Error(`${sourceName}: expected rules to be an array.`);
  }

  return {
    rules: rules.map((rule, index) => normalizeCustomRule(rule, `${sourceName}: rules[${index}]`))
  };
}

export function detectCustomRules(source: SourceFile, rules: CustomRule[], timestamp: number): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    if (!matchesLanguage(source, rule)) {
      continue;
    }
    const regex = compileRuleRegex(rule);
    for (const match of source.text.matchAll(regex)) {
      const index = match.index ?? 0;
      findings.push(
        createFinding({
          type: rule.type,
          severity: rule.severity,
          message: rule.message,
          file: source.filePath,
          index,
          endIndex: index + match[0].length,
          text: source.text,
          evidence: match[0],
          suggestion: rule.suggestion,
          detectionLayer: rule.detectionLayer,
          ruleId: `custom.${rule.id}`,
          timestamp
        })
      );
    }
  }
  return findings;
}

function normalizeCustomRule(value: unknown, label: string): CustomRule {
  if (!value || typeof value !== "object") {
    throw new Error(`${label}: expected an object.`);
  }
  const input = value as Record<string, unknown>;
  const id = requiredString(input.id, `${label}.id`);
  if (!/^[A-Za-z0-9_.-]+$/.test(id)) {
    throw new Error(`${label}.id: use only letters, numbers, dot, underscore, or hyphen.`);
  }
  const pattern = requiredString(input.pattern ?? input.regex, `${label}.pattern`);
  const flags = optionalString(input.flags, `${label}.flags`);
  validateRegex(pattern, flags, `${label}.pattern`);
  const severity = normalizeSeverity(input.severity, `${label}.severity`);
  const type = normalizeFindingType(input.type, `${label}.type`);
  const detectionLayer = normalizeDetectionLayer(input.layer ?? input.detection_layer, `${label}.layer`);
  const languages = normalizeLanguages(input.languages, `${label}.languages`);

  return {
    id,
    pattern,
    flags,
    severity,
    type,
    message: requiredString(input.message, `${label}.message`),
    suggestion: optionalString(input.suggestion, `${label}.suggestion`),
    detectionLayer,
    languages
  };
}

function compileRuleRegex(rule: CustomRule): RegExp {
  const flags = new Set((rule.flags ?? "g").split(""));
  flags.add("g");
  return new RegExp(rule.pattern, [...flags].join(""));
}

function validateRegex(pattern: string, flags: string | undefined, label: string): void {
  try {
    compileRuleRegex({
      id: "validation",
      pattern,
      flags,
      severity: "info",
      type: "other",
      message: "validation",
      detectionLayer: "L1"
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid regex";
    throw new Error(`${label}: ${detail}`);
  }
}

function matchesLanguage(source: SourceFile, rule: CustomRule): boolean {
  if (!rule.languages || rule.languages.length === 0) {
    return true;
  }
  const candidates = new Set<string>();
  if (source.languageId) {
    candidates.add(source.languageId.toLowerCase());
  }
  const ext = extensionOf(source.filePath);
  if (ext) {
    candidates.add(ext);
  }
  const basename = path.basename(source.filePath).toLowerCase();
  candidates.add(basename);
  return rule.languages.some((language) => candidates.has(language.toLowerCase()));
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label}: expected a non-empty string.`);
  }
  return value.trim();
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${label}: expected a string.`);
  }
  return value;
}

function normalizeSeverity(value: unknown, label: string): Severity {
  const severity = requiredString(value, label).toLowerCase();
  if (!severities.has(severity as Severity)) {
    throw new Error(`${label}: invalid severity "${severity}".`);
  }
  return severity as Severity;
}

function normalizeFindingType(value: unknown, label: string): FindingType {
  const type = requiredString(value ?? "other", label);
  if (!findingTypes.has(type as FindingType)) {
    throw new Error(`${label}: invalid finding type "${type}".`);
  }
  return type as FindingType;
}

function normalizeDetectionLayer(value: unknown, label: string): DetectionLayer {
  const layer = (typeof value === "string" && value.trim().length > 0 ? value : "L1").toUpperCase();
  if (!detectionLayers.has(layer as DetectionLayer)) {
    throw new Error(`${label}: invalid detection layer "${layer}".`);
  }
  return layer as DetectionLayer;
}

function normalizeLanguages(value: unknown, label: string): string[] | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label}: expected an array of language ids or file extensions.`);
  }
  return value.map((item, index) => requiredString(item, `${label}[${index}]`));
}
