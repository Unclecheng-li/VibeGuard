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
  | "missing_security_measure"
  | "other";

export type DetectionLayer = "L1" | "L2" | "L3";

export type PackageRegistry = "npm" | "pypi" | "cargo" | "gomod" | "maven";

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
  packageVerifier?: PackageVerifierLike;
  ignoreRules?: IgnoreRules;
  now?: number;
}

export interface ScanResult {
  findings: Finding[];
  elapsedMs: number;
}

export interface PackageReference {
  registry: PackageRegistry;
  packageName: string;
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
  source: "seed" | "cache" | "remote" | "unverified";
  lastVerified: number;
  similarPackages?: string[];
  message?: string;
}

export interface PackageVerifierLike {
  verify(reference: PackageReference, mode: "seed" | "remote"): Promise<PackageResolution>;
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
  llm_provider?: "deepseek" | "claude" | "openai" | "local";
  llm_api_key_stored?: boolean;
  llm_api_key?: null;
  dedup_with_existing_tools: boolean;
  custom_rules: string[];
  ignored_findings: string[];
  package_cache: {
    languages: PackageRegistry[];
    update_interval: "daily" | "weekly";
    lightweight_mode: boolean;
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
  llm_provider: "deepseek",
  llm_api_key_stored: false,
  llm_api_key: null,
  dedup_with_existing_tools: true,
  custom_rules: [],
  ignored_findings: [],
  package_cache: {
    languages: ["npm", "pypi"],
    update_interval: "daily",
    lightweight_mode: true
  },
  telemetry: false
};
