import type { Finding, FindingType, Severity } from "../types";
import { createFinding } from "../utils";

interface SastRule {
  id: string;
  type: FindingType;
  regex: RegExp;
  severity: Severity;
  message: string;
  suggestion: string;
  replacement?: (evidence: string) => string;
}

const sastRules: SastRule[] = [
  {
    id: "sast_sql_template_interpolation",
    type: "sql_injection",
    regex: /\b(?:query|sql|statement)\b\s*=\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+}[^`]*`/gi,
    severity: "high",
    message: "SQL query uses template interpolation.",
    suggestion: "Use parameterized queries or a query builder that binds variables separately."
  },
  {
    id: "sast_sql_string_concat",
    type: "sql_injection",
    regex: /\b(?:query|sql|statement)\b\s*=\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/gi,
    severity: "high",
    message: "SQL query is built with string concatenation.",
    suggestion: "Use parameterized queries instead of concatenating user-controlled values."
  },
  {
    id: "sast_sql_python_f_string_execute",
    type: "sql_injection",
    regex: /\bexecute\s*\(\s*f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{[^}]+}[^"']*["']/gi,
    severity: "high",
    message: "Database execute() receives an interpolated SQL f-string.",
    suggestion: "Use placeholders and pass parameters as a separate tuple or object."
  },
  {
    id: "sast_xss_inner_html",
    type: "xss",
    regex: /\.(?:innerHTML|outerHTML)\s*=\s*(?!DOMPurify|sanitizeHtml|sanitize)[^;\n]+/g,
    severity: "high",
    message: "HTML is assigned directly to the DOM.",
    suggestion: "Use textContent for plain text or sanitize trusted HTML before assignment.",
    replacement: (evidence) => evidence.replace(/\.(?:innerHTML|outerHTML)\s*=/, ".textContent =")
  },
  {
    id: "sast_xss_document_write",
    type: "xss",
    regex: /\bdocument\.write\s*\(/g,
    severity: "high",
    message: "document.write() can introduce XSS.",
    suggestion: "Avoid document.write(); create DOM nodes safely or sanitize first."
  },
  {
    id: "sast_ssrf_fetch_user_url",
    type: "ssrf",
    regex: /\b(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.get)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json))/gi,
    severity: "medium",
    message: "HTTP request appears to use a user-controlled URL.",
    suggestion: "Allowlist outbound hosts and validate URL schemes before making server-side requests."
  },
  {
    id: "sast_path_traversal_fs_user_input",
    type: "path_traversal",
    regex: /\b(?:fs\.(?:readFile|readFileSync|createReadStream)|open|Path\(|send_file)\s*\([^)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|params?\[)/gi,
    severity: "high",
    message: "File path appears to include user-controlled input.",
    suggestion: "Resolve paths against a fixed base directory and reject traversal outside that directory."
  },
  {
    id: "sast_insecure_deserialization_pickle",
    type: "insecure_deserialization",
    regex: /\bpickle\.loads?\s*\([^)\n]*(?:request|req\.|input|body|data)/gi,
    severity: "high",
    message: "pickle is deserializing data that may be user-controlled.",
    suggestion: "Use JSON or another safe format for untrusted data."
  },
  {
    id: "sast_insecure_deserialization_yaml",
    type: "insecure_deserialization",
    regex: /\byaml\.load\s*\([^)\n]*(?:request|req\.|input|body|data)(?![^)]*SafeLoader)/gi,
    severity: "high",
    message: "yaml.load() may deserialize user-controlled data without SafeLoader.",
    suggestion: "Use yaml.safe_load() for untrusted YAML.",
    replacement: (evidence) => evidence.replace(/\byaml\.load\s*\(/i, "yaml.safe_load(")
  },
  {
    id: "sast_command_injection_os_system",
    type: "command_injection",
    regex: /\b(?:os\.system|subprocess\.(?:call|run|Popen)|child_process\.exec)\s*\([^)\n]*(?:request|req\.|input|body|params|\$\{)/gi,
    severity: "high",
    message: "Command execution appears to include user-controlled input.",
    suggestion: "Use argument arrays, strict allowlists, and avoid shell=True or string commands."
  },
  {
    id: "sast_open_redirect_user_input",
    type: "open_redirect",
    regex: /\b(?:res|response)\.redirect\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))|\bredirect\s*\(\s*(?:request\.(?:args|GET|POST)|req\.(?:query|body|params))/gi,
    severity: "medium",
    message: "Redirect target appears to come from user-controlled input.",
    suggestion: "Redirect only to relative paths or allowlisted hosts after validating the destination."
  },
  {
    id: "sast_information_leakage_error_details",
    type: "information_leakage",
    regex: /\b(?:res|response)\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception)\.(?:stack|message)|\b(?:res|response)\.status\s*\(\s*500\s*\)\s*\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception)\.(?:stack|message)|\breturn\s+(?:traceback\.format_exc\s*\(\s*\)|str\s*\(\s*(?:err(?:or)?|exception|e)\s*\))/gi,
    severity: "low",
    message: "Detailed error information is returned to the client.",
    suggestion: "Return a generic error response and log stack traces or exception details server-side only."
  }
];

export function detectSast(text: string, filePath: string, timestamp: number): Finding[] {
  const findings: Finding[] = [];
  for (const rule of sastRules) {
    rule.regex.lastIndex = 0;
    for (const match of text.matchAll(rule.regex)) {
      const index = match.index ?? 0;
      const replacement = rule.replacement?.(match[0]);
      const finding = createFinding({
        type: rule.type,
        severity: rule.severity,
        message: rule.message,
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: match[0],
        suggestion: rule.suggestion,
        detectionLayer: "L2",
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
