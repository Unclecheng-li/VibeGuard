import { stringify } from "yaml";
import { aiPatternRules } from "./rules/aiPatterns";
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

const aiPatternSemgrepRules: SemgrepExportRule[] = aiPatternRules.map((rule) => ({
  id: rule.id,
  vibeguardRuleId: rule.id,
  languages: rule.languages ?? ["generic"],
  severity: rule.severity,
  detectionLayer: "L1",
  findingType: "ai_pattern_error",
  message: rule.message,
  suggestion: rule.suggestion,
  patternRegex: rule.patternRegex
}));

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
    id: "hardcoded_secret_slack_token",
    vibeguardRuleId: "hardcoded_secret_slack_token",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Slack token appears to be hardcoded.",
    suggestion: "Move the token to an environment variable or secret manager and rotate the exposed value.",
    patternRegex: "\\bxox[baprs]-[A-Za-z0-9-]{20,}\\b"
  },
  {
    id: "hardcoded_secret_stripe_key",
    vibeguardRuleId: "hardcoded_secret_stripe_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Stripe API key appears to be hardcoded.",
    suggestion: "Move the key to a secret manager and rotate the exposed value.",
    patternRegex: "\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\\b"
  },
  {
    id: "hardcoded_secret_google_api_key",
    vibeguardRuleId: "hardcoded_secret_google_api_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Google API key appears to be hardcoded.",
    suggestion: "Move the key to a secret manager and rotate the exposed value.",
    patternRegex: "\\bAIza[0-9A-Za-z_-]{35}\\b"
  },
  {
    id: "hardcoded_secret_npm_token",
    vibeguardRuleId: "hardcoded_secret_npm_token",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "npm access token appears to be hardcoded.",
    suggestion: "Move the token to a secret manager and rotate the exposed value.",
    patternRegex: "\\bnpm_[A-Za-z0-9]{36}\\b"
  },
  {
    id: "hardcoded_secret_anthropic_key",
    vibeguardRuleId: "hardcoded_secret_anthropic_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Anthropic API key appears to be hardcoded.",
    suggestion: "Move the key to a secret manager and rotate the exposed value.",
    patternRegex: "\\bsk-ant-[A-Za-z0-9_-]{32,}\\b"
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
    patternRegex: "\\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\\b"
  },
  {
    id: "hardcoded_secret_jwt",
    vibeguardRuleId: "hardcoded_secret_jwt",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "JWT token appears to be hardcoded.",
    suggestion: "Move the token to a secure runtime source and rotate it if it has been committed.",
    patternRegex: "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"
  },
  {
    id: "hardcoded_secret_private_key",
    vibeguardRuleId: "hardcoded_secret_private_key",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Private key block appears to be hardcoded.",
    suggestion: "Remove the private key from source control and rotate the exposed credential.",
    patternRegex: "-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----"
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
    id: "hardcoded_secret_high_entropy_assignment",
    vibeguardRuleId: "hardcoded_secret_high_entropy_assignment",
    languages: ["generic"],
    severity: "critical",
    detectionLayer: "L1",
    findingType: "hardcoded_secret",
    message: "Sensitive value is assigned a high-entropy-looking literal.",
    suggestion: "Read this value from an environment variable or secret manager instead of committing it.",
    patternRegex:
      "(?:\\b(?:[A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*|(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*)\\b|[\"'](?:authorization|x[_-]?api[_-]?key|api[_-]?key|secret|secret[_-]?key|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential)[\"'])\\s*[:=]\\s*[\"'`](?:Bearer\\s+)?[A-Za-z0-9_+./=-]{20,}[\"'`]"
  },
  ...aiPatternSemgrepRules,
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
    languages: ["javascript", "typescript", "python", "java"],
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
    id: "sast_sql_user_input_execute",
    vibeguardRuleId: "sast_sql_user_input_execute",
    languages: ["javascript", "typescript", "python", "java"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "sql_injection",
    message: "Database execution receives a user-controlled SQL value without bound parameters.",
    suggestion: "Use placeholders and pass request values as separate parameters.",
    patternRegex: "\\b(?:(?:db|database|pool|connection|conn|client|cursor|session)\\.(?:query|execute|executemany)|(?:statement|preparedStatement|callableStatement)\\.(?:execute|executeQuery|executeUpdate))\\s*\\([^\\)\\n]*(?:req\\.(?:query|body|params)|request\\.(?:args|form|json)|request\\s*\\.\\s*(?:getParameter|getHeader|getQueryString)\\s*\\()"
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
    id: "sast_xss_dangerously_set_inner_html",
    vibeguardRuleId: "sast_xss_dangerously_set_inner_html",
    languages: ["javascript", "typescript"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "xss",
    message: "dangerouslySetInnerHTML receives user-controlled HTML.",
    suggestion: "Sanitize untrusted HTML with a well-reviewed sanitizer before rendering it.",
    patternRegex: "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]*\\breq\\.(?:query|body|params)\\b[^}]*}\\s*}"
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
    patternRegex: "\\b(?:fetch|axios\\.(?:get|post|put|patch|delete|head)|got(?:\\.(?:get|post|put|patch|delete|head))?|undici\\.request|(?:http|https)\\.(?:get|request)|requests\\.(?:get|post|put|patch|delete|head)|httpx\\.(?:get|post|put|patch|delete|head)|urllib\\.request\\.urlopen)\\s*\\(\\s*(?:req\\.(?:query|body|params)|request\\.(?:args|form|json))|\\b(?:requests|httpx)\\.request\\s*\\(\\s*[^,\\n]+,\\s*(?:request\\.(?:args|form|json))|\\b(?:axios(?:\\.request)?|(?:http|https)\\.request)\\s*\\(\\s*\\{[^}\\n]*\\b(?:url|uri|baseURL|host|hostname)\\s*:\\s*(?:req\\.(?:query|body|params))"
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
    patternRegex: "\\b(?:fs(?:\\.promises)?\\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync)|open|Path\\(|send_file)\\s*\\([^\\)\\n]*(?:req\\.(?:query|body|params)|request\\.(?:args|form|json)|params?\\[)"
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
    id: "sast_insecure_deserialization_java_object_input_stream",
    vibeguardRuleId: "sast_insecure_deserialization_java_object_input_stream",
    languages: ["java"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "insecure_deserialization",
    message: "ObjectInputStream deserializes data directly from an HTTP request.",
    suggestion: "Use a safe data format such as JSON and validate the request body before processing it.",
    patternRegex: "\\bnew\\s+ObjectInputStream\\s*\\(\\s*request\\s*\\.\\s*(?:getInputStream|getReader)\\s*\\("
  },
  {
    id: "sast_command_injection_os_system",
    vibeguardRuleId: "sast_command_injection_os_system",
    languages: ["javascript", "typescript", "python", "java"],
    severity: "high",
    detectionLayer: "L2",
    findingType: "command_injection",
    message: "Command execution appears to include user-controlled input.",
    suggestion: "Use argument arrays, strict allowlists, and avoid shell=True or string commands.",
    patternRegex: "\\b(?:os\\.system|subprocess\\.(?:call|run|Popen|check_call|check_output)|child_process\\.exec(?:Sync)?)\\s*\\([^\\)\\n]*(?:request|req\\.|input|body|params|\\$\\{)|\\b(?:Runtime\\s*\\.\\s*getRuntime\\s*\\(\\s*\\)\\s*\\.\\s*exec|new\\s+ProcessBuilder)\\s*\\([^\\)\\n]*request\\s*\\.\\s*(?:getParameter|getHeader|getQueryString)\\s*\\("
  },
  {
    id: "sast_open_redirect_user_input",
    vibeguardRuleId: "sast_open_redirect_user_input",
    languages: ["javascript", "typescript", "python"],
    severity: "medium",
    detectionLayer: "L2",
    findingType: "open_redirect",
    message: "Redirect target appears to come from user-controlled input.",
    suggestion: "Redirect only to relative paths or allowlisted hosts after validating the destination.",
    patternRegex: "\\b(?:res|response)\\.redirect\\s*\\(\\s*(?:req\\.(?:query|body|params)|request\\.(?:query|body|params))|\\bredirect\\s*\\(\\s*(?:request\\.(?:args|GET|POST)|req\\.(?:query|body|params))"
  },
  {
    id: "sast_information_leakage_error_details",
    vibeguardRuleId: "sast_information_leakage_error_details",
    languages: ["javascript", "typescript", "python"],
    severity: "low",
    detectionLayer: "L2",
    findingType: "information_leakage",
    message: "Detailed error or sensitive diagnostic information is returned to the client.",
    suggestion: "Return a generic error response and log stack traces, SQL, and sensitive diagnostics server-side only.",
    patternRegex: "\\b(?:res|response)\\.(?:send|json)\\s*\\([^;\\n]*(?:err(?:or)?|exception)\\.(?:stack|message)|\\b(?:res|response)\\.status\\s*\\(\\s*500\\s*\\)\\s*\\.(?:send|json)\\s*\\([^;\\n]*(?:err(?:or)?|exception)\\.(?:stack|message)|\\breturn\\s+(?:traceback\\.format_exc\\s*\\(\\s*\\)|str\\s*\\(\\s*(?:err(?:or)?|exception|e)\\s*\\))|\\b(?:res|response)(?:\\.status\\s*\\(\\s*5\\d\\d\\s*\\))?\\.(?:send|json)\\s*\\([^;\\n]*(?:\\b(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\\s*:|\\(\\s*(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\\b)|\\breturn\\s*\\{[^}\\n]*(?:\\b(?:error|detail|message)\\s*:[^}\\n]+,\\s*)?\\b(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\\s*:"
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
