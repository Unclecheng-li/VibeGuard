import type { Finding, ScanOptions, ScanResult, SourceFile } from "./types";
import { detectCustomRules } from "./customRules";
import { applyIgnoreRules } from "./ignore";
import { LocalSemanticAnalyzer } from "./l3/analyzer";
import { parsePackageReferences } from "./package/packageParser";
import { PackageVerifier } from "./package/packageVerifier";
import { detectAiPatterns } from "./rules/aiPatterns";
import { detectInsecureConfig } from "./rules/config";
import { detectSast } from "./rules/sast";
import { detectSecrets } from "./rules/secrets";
import { uniqueFindings } from "./utils";

export async function scanSourceFile(source: SourceFile, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  if (options.enabled === false) {
    return {
      findings: [],
      elapsedMs: performance.now() - started
    };
  }

  const timestamp = options.now ?? Date.now();
  const layers = {
    l1: options.detectionLayers?.l1 ?? true,
    l2: options.detectionLayers?.l2 ?? options.includeSast ?? true,
    l3: options.detectionLayers?.l3 ?? options.includeL3 ?? false
  };

  const findings: Finding[] = [];

  if (layers.l1) {
    findings.push(...detectSecrets(source.text, source.filePath, timestamp));
    findings.push(...detectInsecureConfig(source.text, source.filePath, timestamp));
    findings.push(...detectAiPatterns(source.text, source.filePath, timestamp));
    if (options.packageVerification !== "off") {
      findings.push(...(await detectHallucinatedPackages(source, options)));
    }
  }

  if (layers.l2) {
    findings.push(...detectSast(source.text, source.filePath, timestamp));
  }

  if (layers.l3) {
    const analyzer = options.l3Analyzer ?? new LocalSemanticAnalyzer();
    findings.push(...(await analyzer.analyze(source, timestamp)));
  }

  if (options.customRules && options.customRules.length > 0) {
    findings.push(...detectCustomRules(source, options.customRules, timestamp));
  }

  return {
    findings: applyIgnoreRules(uniqueFindings(findings), options.ignoreRules),
    elapsedMs: performance.now() - started
  };
}

async function detectHallucinatedPackages(source: SourceFile, options: ScanOptions): Promise<Finding[]> {
  const mode = options.packageVerification ?? "seed";
  if (mode === "off") {
    return [];
  }

  const verifier = options.packageVerifier ?? new PackageVerifier();
  const references = parsePackageReferences(source.filePath, source.text, source.languageId);
  const findings: Finding[] = [];

  for (const reference of references) {
    const resolution = await verifier.verify(reference, mode);
    if (resolution.exists !== false) {
      continue;
    }

    const suggestion = formatPackageSuggestion(
      reference.packageName,
      reference.registry,
      resolution.similarPackages ?? [],
      resolution.message
    );
    const finding: Finding = {
      id: "",
      type: "hallucinated_package" as const,
      severity: "critical" as const,
      message: `"${reference.packageName}" does not exist in ${reference.registry}.`,
      file: source.filePath,
      line: reference.line,
      column: reference.column,
      endLine: reference.endLine,
      endColumn: reference.endColumn,
      evidence: reference.packageName,
      suggestion,
      detection_layer: "L1" as const,
      detection_rule: `hallucinated_package_${reference.registry}`,
      timestamp: options.now ?? Date.now(),
      dismissed: false
    };

    const firstSuggestion = resolution.similarPackages?.[0];
    if (firstSuggestion && reference.rawSpecifier === reference.packageName) {
      finding.fix = {
        description: `Replace with ${firstSuggestion}`,
        edits: [
          {
            startLine: reference.line,
            startColumn: reference.column,
            endLine: reference.endLine,
            endColumn: reference.endColumn,
            newText: firstSuggestion
          }
        ]
      };
    }
    finding.id = packageFindingId(finding.file, finding.detection_rule, finding.line, finding.column, reference.packageName);
    findings.push(finding);
  }

  return findings;
}

function formatPackageSuggestion(packageName: string, registry: string, suggestions: string[], detail?: string): string {
  const base = `This may be a slopsquatting risk: AI-generated code often invents plausible package names. Verify the package before installing from ${registry}.`;
  const detailText = detail ? ` ${detail}` : "";
  if (suggestions.length === 0) {
    return `${base}${detailText}`;
  }
  return `${base}${detailText} Did you mean ${suggestions.map((item) => `"${item}"`).join(" or ")}?`;
}

function packageFindingId(file: string, rule: string, line: number, column: number, packageName: string): string {
  let hash = 2166136261;
  const input = [file, rule, line, column, packageName].join("\u001f");
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `vg_${(hash >>> 0).toString(16).padStart(8, "0")}`;
}
