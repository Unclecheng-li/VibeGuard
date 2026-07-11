import type {
  CodeFix,
  DetectionLayer,
  Finding,
  PackageReference,
  ScanOptions,
  ScanPerformance,
  ScanPerformanceBudgets,
  ScanResult,
  ScanTimings,
  SourceFile
} from "./types";
import { detectCustomRules } from "./customRules";
import { dedupWithExistingToolAnnotations } from "./dedup";
import { applyIgnoredFindingIds, applyIgnoreRules } from "./ignore";
import { LocalSemanticAnalyzer } from "./l3/analyzer";
import { isLayerExecuted } from "./layers";
import { parsePackageReferences } from "./package/packageParser";
import { PackageVerifier } from "./package/packageVerifier";
import { detectAiPatterns } from "./rules/aiPatterns";
import { detectInsecureConfig } from "./rules/config";
import { detectSast } from "./rules/sast";
import { detectSecrets } from "./rules/secrets";
import { uniqueFindings } from "./utils";

export async function scanSourceFile(source: SourceFile, options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const lineCount = countLines(source.text);
  const timings: ScanTimings = {
    totalMs: 0,
    l1Ms: 0,
    l2Ms: 0,
    l3Ms: 0,
    customRulesMs: 0,
    postProcessingMs: 0
  };
  if (options.enabled === false) {
    timings.totalMs = performance.now() - started;
    return {
      findings: [],
      elapsedMs: timings.totalMs,
      performance: buildScanPerformance(source.filePath, lineCount, timings, { l1: false, l2: false, l3: false }, options)
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
    const layerStarted = performance.now();
    findings.push(...detectSecrets(source.text, source.filePath, timestamp));
    findings.push(...detectInsecureConfig(source.text, source.filePath, timestamp));
    findings.push(...detectAiPatterns(source.text, source.filePath, timestamp));
    if (options.packageVerification !== "off") {
      findings.push(...(await detectHallucinatedPackages(source, options)));
    }
    timings.l1Ms = performance.now() - layerStarted;
  }

  if (layers.l2) {
    const layerStarted = performance.now();
    findings.push(...(await detectSast(source.text, source.filePath, timestamp, source.languageId)));
    timings.l2Ms = performance.now() - layerStarted;
  }

  if (layers.l3) {
    const layerStarted = performance.now();
    const analyzer = options.l3Analyzer ?? new LocalSemanticAnalyzer();
    findings.push(...(await analyzer.analyze(source, timestamp)));
    timings.l3Ms = performance.now() - layerStarted;
  }

  const customRules = options.customRules?.filter((rule) => isLayerExecuted(rule.detectionLayer, layers)) ?? [];
  if (customRules.length > 0) {
    const layerStarted = performance.now();
    findings.push(...detectCustomRules(source, customRules, timestamp));
    timings.customRulesMs = performance.now() - layerStarted;
  }

  const postStarted = performance.now();
  const dedupedFindings =
    options.dedupWithExistingTools === false ? findings : dedupWithExistingToolAnnotations(source.text, findings);
  const unique = uniqueFindings(dedupedFindings);
  const ignoredByRules = applyIgnoreRules(unique, options.ignoreRules);
  const finalFindings = applyIgnoredFindingIds(ignoredByRules, options.ignoredFindingIds);
  timings.postProcessingMs = performance.now() - postStarted;
  timings.totalMs = performance.now() - started;

  return {
    findings: finalFindings,
    elapsedMs: timings.totalMs,
    performance: buildScanPerformance(source.filePath, lineCount, timings, layers, options)
  };
}

const defaultPerformanceBudgets: ScanPerformanceBudgets = {
  l1MinMs: 50,
  l1MsPerLine: 50,
  l2Ms: 2000,
  l3Ms: 5000
};

function buildScanPerformance(
  file: string,
  lineCount: number,
  timings: ScanTimings,
  layers: Record<"l1" | "l2" | "l3", boolean>,
  options: ScanOptions
): ScanPerformance {
  const budgets = { ...defaultPerformanceBudgets, ...options.performanceBudgets };
  const checks = [
    budgetCheck("L1", layers.l1, timings.l1Ms, Math.max(budgets.l1MinMs, lineCount * budgets.l1MsPerLine)),
    budgetCheck("L2", layers.l2, timings.l2Ms, budgets.l2Ms),
    budgetCheck("L3", layers.l3, timings.l3Ms, budgets.l3Ms)
  ].filter((check): check is NonNullable<typeof check> => Boolean(check));

  return {
    file,
    lineCount,
    timings: { ...timings },
    budgets: checks,
    budgetExceeded: checks.some((check) => check.exceeded)
  };
}

function budgetCheck(
  layer: DetectionLayer,
  enabled: boolean,
  elapsedMs: number,
  budgetMs: number
): { layer: DetectionLayer; elapsedMs: number; budgetMs: number; exceeded: boolean } | undefined {
  if (!enabled) {
    return undefined;
  }
  const normalizedBudget = Math.max(0, budgetMs);
  return {
    layer,
    elapsedMs,
    budgetMs: normalizedBudget,
    exceeded: elapsedMs > normalizedBudget
  };
}

function countLines(text: string): number {
  if (text.length === 0) {
    return 1;
  }
  return text.split(/\r\n|\r|\n/).length;
}

async function detectHallucinatedPackages(source: SourceFile, options: ScanOptions): Promise<Finding[]> {
  const mode = options.packageVerification ?? "seed";
  if (mode === "off") {
    return [];
  }

  const verifier = options.packageVerifier ?? new PackageVerifier();
  const references = parsePackageReferences(source.filePath, source.text, source.languageId);
  const findings: Finding[] = [];

  const resolutions = await mapWithConcurrency(references, 5, (reference) => verifier.verify(reference, mode));
  for (const [index, reference] of references.entries()) {
    const resolution = resolutions[index];
    if (resolution.exists === null) {
      if (mode === "remote") {
        findings.push(createUnverifiedPackageFinding(source.filePath, reference, resolution.message, options.now ?? Date.now()));
      }
      continue;
    }
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

    if (reference.rawSpecifier === reference.packageName) {
      const fixes = packageReplacementFixes(reference, resolution.similarPackages ?? []);
      if (fixes.length > 0) {
        finding.fix = fixes[0];
        if (fixes.length > 1) {
          finding.alternativeFixes = fixes.slice(1);
        }
      }
    }
    finding.id = packageFindingId(finding.file, finding.detection_rule, finding.line, finding.column, reference.packageName);
    findings.push(finding);
  }

  return findings;
}

function packageReplacementFixes(reference: PackageReference, candidates: string[]): CodeFix[] {
  const replacements = [...new Set(candidates.map((candidate) => candidate.trim()))].filter(
    (candidate) => candidate !== reference.packageName && isSafePackageReplacement(candidate)
  );
  return replacements.map((replacement) => ({
    description: `Replace with ${replacement}`,
    edits: [
      {
        startLine: reference.line,
        startColumn: reference.column,
        endLine: reference.endLine,
        endColumn: reference.endColumn,
        newText: replacement
      }
    ]
  }));
}

function isSafePackageReplacement(value: string): boolean {
  return value.length > 0 && value.length <= 256 && /^[A-Za-z0-9@._/+:-]+$/.test(value);
}

function createUnverifiedPackageFinding(
  file: string,
  reference: PackageReference,
  detail: string | undefined,
  timestamp: number
): Finding {
  const message = `"${reference.packageName}" could not be verified in ${reference.registry}.`;
  const suggestion = [
    "VibeGuard could not confirm this package because the local index had no answer and the remote registry was unavailable.",
    detail,
    "Check registry connectivity or synchronize the local package-name index before installing it."
  ]
    .filter((item): item is string => Boolean(item))
    .join(" ");
  const finding: Finding = {
    id: "",
    type: "other",
    severity: "medium",
    message,
    file,
    line: reference.line,
    column: reference.column,
    endLine: reference.endLine,
    endColumn: reference.endColumn,
    evidence: reference.packageName,
    suggestion,
    detection_layer: "L1",
    detection_rule: `package_verification_unavailable_${reference.registry}`,
    timestamp,
    dismissed: false
  };
  finding.id = packageFindingId(finding.file, finding.detection_rule, finding.line, finding.column, reference.packageName);
  return finding;
}

async function mapWithConcurrency<T, R>(items: readonly T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, limit), items.length);

  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (true) {
        const index = nextIndex;
        nextIndex += 1;
        if (index >= items.length) {
          return;
        }
        results[index] = await worker(items[index]);
      }
    })
  );
  return results;
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
