import { stringify } from "yaml";
import type { DetectionLayer, FindingType, Severity } from "./types";

export interface SemgrepExportRule {
  id: string;
  vibeguardRuleId: string;
  languages: string[];
  severity: Severity;
  detectionLayer: DetectionLayer;
  findingType: FindingType;
  message: string;
  suggestion: string;
  patternRegex: string;
}

export interface SemgrepExportOptions {
  rulePrefix?: string;
}

export const semgrepExportRules: SemgrepExportRule[] = [
  {
    id: "hardcoded_secret_aws_access_key",
    vibeguardRuleId: "hardcoded_secret_aws_access_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "AWS access key appears to be hardcoded.",
    suggestion: "Move the secret to an environment variable or OS keychain and rotate the exposed value.",
    patternRegex: "\\bA(?:KIA|SIA)[0-9A-Z]{16}\\b"
  },
  {
    id: "hardcoded_secret_github_token",
    vibeguardRuleId: "hardcoded_secret_github_token",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "GitHub token appears to be hardcoded.",
    suggestion: "Move the secret to an environment variable or OS keychain and rotate the exposed value.",
    patternRegex: "\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\\b"
  },
  {
    id: "hardcoded_secret_openai_key",
    vibeguardRuleId: "hardcoded_secret_openai_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "OpenAI API key appears to be hardcoded.",
    suggestion: "Move the secret to an environment variable or OS keychain and rotate the exposed value.",
    patternRegex: "\\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\\b"
  },
  {
    id: "hardcoded_secret_database_url",
    vibeguardRuleId: "hardcoded_secret_database_url",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Database URL with a password appears to be hardcoded.",
    suggestion: "Move database credentials to a secret manager and rotate the exposed value.",
    patternRegex: "\\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\\s/@]+:[^@\\s]+@[^)\\s'\"]+"
  },
  {
    id: "ai_pattern_default_password",
    vibeguardRuleId: "ai_pattern_default_password",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "ai_pattern_error",
    message: "Default password is hardcoded.",
    suggestion: "Generate a unique secret per environment and force users to set their own password.",
    patternRegex: "\\b(?:password|passwd|pwd)\\s*[:=]\\s*[\"'](?:admin|password|123456|12345678|changeme)[\"']"
  },
  {
    id: "ai_pattern_hardcoded_jwt_secret",
    vibeguardRuleId: "ai_pattern_hardcoded_jwt_secret",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "ai_pattern_error",
    message: "JWT secret is hardcoded.",
    suggestion: "Load JWT_SECRET from a secret manager or environment variable and rotate the committed value.",
    patternRegex: "\\bJWT_SECRET\\b\\s*[:=]\\s*[\"'`](?!process\\.env|import\\.meta\\.env|os\\.getenv)[^\"'`]{8,}[\"'`]"
  },
  {
    id: "ai_pattern_frontend_secret_name",
    vibeguardRuleId: "ai_pattern_frontend_secret_name",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "ai_pattern_error",
    message: "Secret-like value is exposed through a frontend environment variable.",
    suggestion: "Move secrets to server-side configuration; frontend-prefixed variables are public.",
    patternRegex: "\\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\\s*[:=]\\s*[\"'`][^\"'`]{8,}[\"'`]"
  },
  {
    id: "ai_pattern_dangerously_set_inner_html",
    vibeguardRuleId: "ai_pattern_dangerously_set_inner_html",
    languages: ["javascript", "typescript"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "ai_pattern_error",
    message: "dangerouslySetInnerHTML is used without an obvious sanitizer.",
    suggestion: "Sanitize HTML with a trusted sanitizer before passing it to dangerouslySetInnerHTML.",
    patternRegex: "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\\s*}"
  },
  {
    id: "insecure_config_debug_true",
    vibeguardRuleId: "insecure_config_debug_true",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "insecure_config",
    message: "Django/Flask debug mode is enabled.",
    suggestion: "Disable debug mode in production and gate it behind an environment variable.",
    patternRegex: "\\bDEBUG\\s*=\\s*True\\b"
  },
  {
    id: "insecure_config_cors_allow_all",
    vibeguardRuleId: "insecure_config_cors_allow_all",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "insecure_config",
    message: "CORS is configured to allow every origin.",
    suggestion: "Restrict CORS to trusted origins.",
    patternRegex: "\\b(?:CORS_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\\s*=\\s*True\\b"
  },
  {
    id: "insecure_config_csrf_exempt",
    vibeguardRuleId: "insecure_config_csrf_exempt",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "insecure_config",
    message: "CSRF protection is disabled for this endpoint.",
    suggestion: "Keep CSRF protection enabled or add a narrower compensating control.",
    patternRegex: "@csrf_exempt\\b|\\bcsrf_exempt\\s*\\("
  },
  {
    id: "insecure_config_eval",
    vibeguardRuleId: "insecure_config_eval",
    languages: ["javascript", "typescript", "python"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "insecure_config",
    message: "eval() executes arbitrary code.",
    suggestion: "Replace eval() with a structured parser or explicit dispatch table.",
    patternRegex: "\\beval\\s*\\("
  },
  {
    id: "insecure_config_yaml_load_without_loader",
    vibeguardRuleId: "insecure_config_yaml_load_without_loader",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L1",
    findingType: "insecure_config",
    message: "yaml.load() is used without an explicit safe loader.",
    suggestion: "Use yaml.safe_load() or pass SafeLoader explicitly.",
    patternRegex: "\\byaml\\.load\\s*\\(\\s*[^,\\n)]+?\\s*\\)"
  },
  {
    id: "sast_sql_template_interpolation",
    vibeguardRuleId: "sast_sql_template_interpolation",
    languages: ["javascript", "typescript"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "sql_injection",
    message: "SQL query uses template interpolation.",
    suggestion: "Use parameterized queries or a query builder that binds variables separately.",
    patternRegex: "\\b(?:query|sql|statement)\\b\\s*=\\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\\b[^`]*\\$\\{[^}]+}[^`]*`"
  },
  {
    id: "sast_sql_python_f_string_execute",
    vibeguardRuleId: "sast_sql_python_f_string_execute",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "sql_injection",
    message: "Database execute() receives an interpolated SQL f-string.",
    suggestion: "Use placeholders and pass parameters as a separate tuple or object.",
    patternRegex: "\\bexecute\\s*\\(\\s*f[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)\\b[^\"']*\\{[^}]+}[^\"']*[\"']"
  },
  {
    id: "sast_xss_inner_html",
    vibeguardRuleId: "sast_xss_inner_html",
    languages: ["javascript", "typescript"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "xss",
    message: "HTML is assigned directly to the DOM.",
    suggestion: "Use textContent for plain text or sanitize trusted HTML before assignment.",
    patternRegex: "\\.(?:innerHTML|outerHTML)\\s*=\\s*(?!DOMPurify|sanitizeHtml|sanitize)[^;\\n]+"
  },
  {
    id: "sast_ssrf_fetch_user_url",
    vibeguardRuleId: "sast_ssrf_fetch_user_url",
    languages: ["javascript", "typescript", "python"],
    severity: "medium",
    detectionLayer: "L2",
    findingType: "ssrf",
    message: "HTTP request appears to use a user-controlled URL.",
    suggestion: "Allowlist outbound hosts and validate URL schemes before making server-side requests.",
    patternRegex: "\\b(?:fetch|axios\\.(?:get|post)|requests\\.(?:get|post)|http\\.get)\\s*\\(\\s*(?:req\\.(?:query|body|params)|request\\.(?:args|form|json))"
  },
  {
    id: "sast_path_traversal_fs_user_input",
    vibeguardRuleId: "sast_path_traversal_fs_user_input",
    languages: ["javascript", "typescript", "python"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "path_traversal",
    message: "File path appears to include user-controlled input.",
    suggestion: "Resolve paths against a fixed base directory and reject traversal outside that directory.",
    patternRegex: "\\b(?:fs\\.(?:readFile|readFileSync|createReadStream)|open|Path\\(|send_file)\\s*\\([^\\)\\n]*(?:req\\.(?:query|body|params)|request\\.(?:args|form|json)|params?\\[)"
  },
  {
    id: "sast_insecure_deserialization_pickle",
    vibeguardRuleId: "sast_insecure_deserialization_pickle",
    languages: ["python"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "insecure_deserialization",
    message: "pickle is deserializing data that may be user-controlled.",
    suggestion: "Use JSON or another safe format for untrusted data.",
    patternRegex: "\\bpickle\\.loads?\\s*\\([^\\)\\n]*(?:request|req\\.|input|body|data)"
  },
  {
    id: "sast_command_injection_os_system",
    vibeguardRuleId: "sast_command_injection_os_system",
    languages: ["javascript", "typescript", "python"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "command_injection",
    message: "Command execution appears to include user-controlled input.",
    suggestion: "Use argument arrays, strict allowlists, and avoid shell=True or string commands.",
    patternRegex: "\\b(?:os\\.system|subprocess\\.(?:call|run|Popen)|child_process\\.exec)\\s*\\([^\\)\\n]*(?:request|req\\.|input|body|params|\\$\\{)"
  }
];

export function formatSemgrepRules(options: SemgrepExportOptions = {}): string {
  const prefix = options.rulePrefix ?? "vibeguard";
  const payload = {
    rules: semgrepExportRules.map((rule) => ({
      id: `${prefix}.${rule.id}`,
      languages: rule.languages,
      severity: semgrepSeverity(rule.severity),
      message: `${rule.message} ${rule.suggestion}`,
      "pattern-regex": rule.patternRegex,
      metadata: {
        category: "security",
        confidence: rule.severity === "critical" ? "high" : "medium",
        technology: ["vibeguard"],
        vibeguard: {
          rule_id: rule.vibeguardRuleId,
          detection_layer: rule.detectionLayer,
          finding_type: rule.findingType,
          severity: rule.severity
        }
      }
    }))
  };
  return stringify(payload);
}

function semgrepSeverity(severity: Severity): "ERROR" | "WARNING" | "INFO" {
  if (severity === "critical" || severity === "high") {
    return "ERROR";
  }
  if (severity === "medium" || severity === "low") {
    return "WARNING";
  }
  return "INFO";
}
