export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingType =
  | "hallucinated_package"
  | "hardcoded_secret"
  | "insecure_config"
  | "ai_pattern_error"
  | "sql_injection"
  | "xss"
  | "ssrf"
  | "path_traversal"
  | "insecure_deserialization"
  | "command_injection"
  | "open_redirect"
  | "information_leakage"
  | "missing_security_measure"
  | "other";

export type DetectionLayer = "L1" | "L2" | "L3";

export type PackageRegistry = "npm" | "pypi" | "cargo" | "gomod" | "maven";

export type LlmProvider = "deepseek" | "claude" | "openai" | "local" | "vibeguard";

export type L3ReviewStatus = "remote" | "local" | "localFallback" | "notConfigured" | "consentRequired" | "cancelled" | "failed";

export interface LlmUsageStats {
  provider: LlmProvider;
  model: string;
  tokensIn?: number;
  tokensOut?: number;
}

export interface L3ReviewOutcome {
  status: L3ReviewStatus;
  findings: Finding[];
  provider: LlmProvider;
  model: string;
  elapsedMs: number;
  usage?: LlmUsageStats;
  errorCode?: "notConfigured" | "consentRequired" | "remoteFailed";
  filesScanned: number;
}

export interface TextEdit {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  newText: string;
}

export interface CodeFix {
  description: string;
  edits: TextEdit[];
}

export interface Finding {
  id: string;
  type: FindingType;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  evidence: string;
  suggestion?: string;
  fix?: CodeFix;
  /** Additional verified mechanical fixes, such as alternative package-name candidates. */
  alternativeFixes?: CodeFix[];
  detection_layer: DetectionLayer;
  detection_rule: string;
  timestamp: number;
  dismissed: boolean;
  dismissed_reason?: string;
}

export interface SourceFile {
  filePath: string;
  text: string;
  languageId?: string;
}

export interface ScanOptions {
  enabled?: boolean;
  detectionLayers?: {
    l1?: boolean;
    l2?: boolean;
    l3?: boolean;
  };
  packageVerification?: "off" | "seed" | "remote";
  includeSast?: boolean;
  includeL3?: boolean;
  packageVerifier?: PackageVerifierLike;
  l3Analyzer?: L3AnalyzerLike;
  customRules?: CustomRuleLike[];
  ignoreRules?: IgnoreRules;
  ignoredFindingIds?: string[];
  dedupWithExistingTools?: boolean;
  performanceBudgets?: Partial<ScanPerformanceBudgets>;
  now?: number;
}

export interface ScanResult {
  findings: Finding[];
  elapsedMs: number;
  performance: ScanPerformance;
}

export interface ScanTimings {
  totalMs: number;
  l1Ms: number;
  l2Ms: number;
  l3Ms: number;
  customRulesMs: number;
  postProcessingMs: number;
}

export interface ScanPerformanceBudgets {
  l1MinMs: number;
  l1MsPerLine: number;
  l2Ms: number;
  l3Ms: number;
}

export interface ScanBudgetCheck {
  layer: DetectionLayer;
  elapsedMs: number;
  budgetMs: number;
  exceeded: boolean;
}

export interface ScanPerformance {
  file: string;
  lineCount: number;
  timings: ScanTimings;
  budgets: ScanBudgetCheck[];
  budgetExceeded: boolean;
}

export interface PackageReference {
  registry: PackageRegistry;
  packageName: string;
  /** Maven artifacts use coordinates; JVM source imports are checked as fully qualified classes. */
  mavenLookup?: "coordinate" | "class";
  rawSpecifier: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  source: "import" | "require" | "manifest" | "install";
}

export interface PackageResolution {
  registry: PackageRegistry;
  packageName: string;
  exists: boolean | null;
  source: "seed" | "index" | "cache" | "remote" | "unverified";
  lastVerified: number;
  similarPackages?: string[];
  message?: string;
}

export interface PackageVerifierLike {
  verify(reference: PackageReference, mode: "seed" | "remote"): Promise<PackageResolution>;
}

export interface L3AnalyzerLike {
  analyze(source: SourceFile, timestamp: number): Promise<Finding[]> | Finding[];
}

export interface CustomRuleLike {
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

export interface PackageIndexSyncMetadata {
  sourceUrl?: string;
  etag?: string;
  lastModified?: string;
  changeSourceUrl?: string;
  changeSequence?: string;
}

export interface PackageIndexEntry {
  registry: PackageRegistry;
  coverage: "partial" | "full";
  updatedAt: number;
  packageCount: number;
  syncMetadata?: PackageIndexSyncMetadata;
}

export interface PackageNameIndexLike {
  get(registry: PackageRegistry, packageName: string): Promise<boolean | undefined>;
  coverage(registry: PackageRegistry): Promise<"partial" | "full" | undefined>;
  suggest?(registry: PackageRegistry, packageName: string, limit?: number): Promise<string[]>;
}

export interface IgnoreRules {
  ignore: IgnoreRuleEntry[];
}

export interface IgnoreRuleEntry {
  rule?: string;
  rules?: string[];
  path?: string;
  scope?: string;
  line?: number;
  package?: string;
  registry?: PackageRegistry;
  reason?: string;
}

export interface VibeGuardConfig {
  enabled: boolean;
  detection_layers: {
    l1: boolean;
    l2: boolean;
    l3: boolean;
  };
  package_verification: "off" | "seed" | "remote";
  llm_provider?: LlmProvider;
  llm_api_key_stored?: boolean;
  llm_api_key?: null;
  dedup_with_existing_tools: boolean;
  custom_rules: string[];
  ignored_findings: string[];
  package_cache: {
    languages: PackageRegistry[];
    update_interval: "daily" | "weekly";
    lightweight_mode: boolean;
    background_full_sync: boolean;
  };
  telemetry: boolean;
}

export const defaultConfig: VibeGuardConfig = {
  enabled: true,
  detection_layers: {
    l1: true,
    l2: true,
    l3: false
  },
  package_verification: "seed",
  llm_provider: "deepseek",
  llm_api_key_stored: false,
  llm_api_key: null,
  dedup_with_existing_tools: true,
  custom_rules: [],
  ignored_findings: [],
  package_cache: {
    languages: ["npm", "pypi"],
    update_interval: "daily",
    lightweight_mode: true,
    background_full_sync: true
  },
  telemetry: false
};
