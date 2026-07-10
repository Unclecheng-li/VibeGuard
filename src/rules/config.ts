import type { Finding, Severity } from "../types";
import { createFinding } from "../utils";

interface ConfigRule {
  id: string;
  regex: RegExp;
  severity: Severity;
  message: string;
  suggestion: string;
  replacement?: (evidence: string) => string;
}

const configRules: ConfigRule[] = [
  {
    id: "insecure_config_debug_true",
    regex: /\bDEBUG\s*=\s*True\b/g,
    severity: "high",
    message: "Django/Flask debug mode is enabled.",
    suggestion: "Disable debug mode in production and gate it behind an environment variable.",
    replacement: (evidence) => evidence.replace(/\bTrue\b/, "False")
  },
  {
    id: "insecure_config_app_debug_true",
    regex: /\bapp\.debug\s*=\s*(?:True|true)\b/g,
    severity: "high",
    message: "Application debug mode is enabled.",
    suggestion: "Disable debug mode outside local development.",
    replacement: (evidence) => evidence.replace(/\b(?:True|true)\b/, evidence.includes("True") ? "False" : "false")
  },
  {
    id: "insecure_config_allowed_hosts_wildcard",
    regex: /\bALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/g,
    severity: "high",
    message: "Django ALLOWED_HOSTS allows every host.",
    suggestion: "Set ALLOWED_HOSTS to the exact production hostnames.",
    replacement: () => "ALLOWED_HOSTS = []"
  },
  {
    id: "insecure_config_cors_allow_all",
    regex: /\b(?:CORS_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\s*=\s*True\b/g,
    severity: "high",
    message: "CORS is configured to allow every origin.",
    suggestion: "Restrict CORS to trusted origins.",
    replacement: (evidence) => evidence.replace(/\bTrue\b/, "False")
  },
  {
    id: "insecure_config_acao_wildcard",
    regex: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/gi,
    severity: "medium",
    message: "Access-Control-Allow-Origin is set to '*'.",
    suggestion: "Return a specific allowlisted origin instead of '*'."
  },
  {
    id: "insecure_config_disable_host_check",
    regex: /\bDANGEROUSLY_DISABLE_HOST_CHECK\s*=\s*(?:true|1)\b/gi,
    severity: "high",
    message: "Host header checks are disabled.",
    suggestion: "Remove DANGEROUSLY_DISABLE_HOST_CHECK and configure trusted hosts explicitly.",
    replacement: (evidence) => evidence.replace(/\b(?:true|1)\b/i, "false")
  },
  {
    id: "insecure_config_csrf_exempt",
    regex: /@csrf_exempt\b|\bcsrf_exempt\s*\(/g,
    severity: "high",
    message: "CSRF protection is disabled for this endpoint.",
    suggestion: "Keep CSRF protection enabled or add a narrower compensating control."
  },
  {
    id: "insecure_config_spring_permit_all",
    regex: /\.permitAll\s*\(/g,
    severity: "medium",
    message: "Spring Security permitAll() may expose an endpoint.",
    suggestion: "Confirm this endpoint is intentionally public and add authorization where needed."
  },
  {
    id: "insecure_config_spring_security_disable",
    regex: /\bsecurity\.disable\s*=\s*true\b/gi,
    severity: "high",
    message: "Spring security appears to be disabled.",
    suggestion: "Enable Spring Security and use environment-specific test overrides if needed.",
    replacement: (evidence) => evidence.replace(/\btrue\b/i, "false")
  },
  {
    id: "insecure_config_cross_origin_wildcard",
    regex: /@CrossOrigin\s*\([^)]*(?:origins\s*=\s*)?["']\*["'][^)]*\)/g,
    severity: "high",
    message: "Spring @CrossOrigin allows every origin.",
    suggestion: "Restrict @CrossOrigin to trusted domains."
  },
  {
    id: "insecure_config_eval",
    regex: /\beval\s*\(/g,
    severity: "high",
    message: "eval() executes arbitrary code.",
    suggestion: "Replace eval() with a structured parser or explicit dispatch table."
  },
  {
    id: "insecure_config_python_exec",
    regex: /\bexec\s*\(/g,
    severity: "high",
    message: "exec() executes arbitrary Python code.",
    suggestion: "Avoid exec(); use explicit functions or safe parsers instead."
  },
  {
    id: "insecure_config_pickle_loads",
    regex: /\bpickle\.loads?\s*\(/g,
    severity: "high",
    message: "pickle deserialization can execute arbitrary code.",
    suggestion: "Use JSON or a safe serialization format for untrusted data."
  },
  {
    id: "insecure_config_yaml_load_without_loader",
    regex: /\byaml\.load\s*\(\s*[^,\n)]+?\s*\)/g,
    severity: "high",
    message: "yaml.load() is used without an explicit safe loader.",
    suggestion: "Use yaml.safe_load() or pass SafeLoader explicitly.",
    replacement: (evidence) => evidence.replace(/\byaml\.load\s*\(/, "yaml.safe_load(")
  }
];

export function detectInsecureConfig(text: string, filePath: string, timestamp: number): Finding[] {
  const findings: Finding[] = [];
  for (const rule of configRules) {
    rule.regex.lastIndex = 0;
    for (const match of text.matchAll(rule.regex)) {
      const index = match.index ?? 0;
      const replacement = rule.replacement?.(match[0]);
      const finding = createFinding({
        type: "insecure_config",
        severity: rule.severity,
        message: rule.message,
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: match[0],
        suggestion: rule.suggestion,
        detectionLayer: "L1",
        ruleId: rule.id,
        timestamp
      });

      if (replacement && finding.endLine !== undefined && finding.endColumn !== undefined) {
        finding.fix = {
          description: `Replace with ${replacement}`,
          edits: [
            {
              startLine: finding.line,
              startColumn: finding.column,
              endLine: finding.endLine,
              endColumn: finding.endColumn,
              newText: replacement
            }
          ]
        };
      }

      findings.push(finding);
    }
  }
  return findings;
}
