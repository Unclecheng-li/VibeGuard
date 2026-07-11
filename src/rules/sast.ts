import type { Finding, FindingType, Severity } from "../types";
import { createFinding } from "../utils";
import { detectAstSast } from "./astSast";

interface SastRule {
  id: string;
  type: FindingType;
  regex: RegExp;
  severity: Severity;
  message: string;
  suggestion: string;
  replacement?: (evidence: string, sourceText: string, index: number) => string | undefined;
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
    suggestion: "Use placeholders and pass parameters as a separate tuple or object.",
    replacement: parameterizeSqliteFString
  },
  {
    id: "sast_sql_user_input_execute",
    type: "sql_injection",
    regex: /\b(?:(?:db|database|pool|connection|conn|client|cursor|session)\.(?:query|execute|executemany)|(?:statement|preparedStatement|callableStatement)\.(?:execute|executeQuery|executeUpdate))\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|request\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\()/gi,
    severity: "high",
    message: "Database execution receives a user-controlled SQL value without bound parameters.",
    suggestion: "Use placeholders and pass request values as a separate parameter array, tuple, or object."
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
    id: "sast_xss_dangerously_set_inner_html",
    type: "xss",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]*\breq\.(?:query|body|params)\b[^}]*}\s*}/gi,
    severity: "high",
    message: "dangerouslySetInnerHTML receives user-controlled HTML.",
    suggestion: "Use text rendering where possible, or sanitize untrusted HTML with a well-reviewed sanitizer before rendering it."
  },
  {
    id: "sast_ssrf_fetch_user_url",
    type: "ssrf",
    regex: /\b(?:fetch|axios\.(?:get|post|put|patch|delete|head)|got(?:\.(?:get|post|put|patch|delete|head))?|undici\.request|(?:http|https)\.(?:get|request)|requests\.(?:get|post|put|patch|delete|head)|httpx\.(?:get|post|put|patch|delete|head)|urllib\.request\.urlopen)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json))|\b(?:requests|httpx)\.request\s*\(\s*[^,\n]+,\s*(?:request\.(?:args|form|json))|\b(?:axios(?:\.request)?|(?:http|https)\.request)\s*\(\s*\{[^}\n]*\b(?:url|uri|baseURL|host|hostname)\s*:\s*(?:req\.(?:query|body|params))/gi,
    severity: "medium",
    message: "HTTP request appears to use a user-controlled URL.",
    suggestion: "Allowlist outbound hosts and validate URL schemes before making server-side requests."
  },
  {
    id: "sast_path_traversal_fs_user_input",
    type: "path_traversal",
    regex: /\b(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync)|open|Path\(|send_file)\s*\([^)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|params?\[)/gi,
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
    id: "sast_insecure_deserialization_java_object_input_stream",
    type: "insecure_deserialization",
    regex: /\bnew\s+ObjectInputStream\s*\(\s*request\s*\.\s*(?:getInputStream|getReader)\s*\(/gi,
    severity: "high",
    message: "ObjectInputStream deserializes data directly from an HTTP request.",
    suggestion: "Use a safe data format such as JSON and validate the request body before processing it."
  },
  {
    id: "sast_command_injection_os_system",
    type: "command_injection",
    regex: /\b(?:os\.system|subprocess\.(?:call|run|Popen|check_call|check_output)|child_process\.exec(?:Sync)?)\s*\([^)\n]*(?:request|req\.|input|body|params|\$\{)|\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder)\s*\([^)\n]*request\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\(/gi,
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
    regex: /\b(?:res|response)\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception)\.(?:stack|message)|\b(?:res|response)\.status\s*\(\s*500\s*\)\s*\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception)\.(?:stack|message)|\breturn\s+(?:traceback\.format_exc\s*\(\s*\)|str\s*\(\s*(?:err(?:or)?|exception|e)\s*\))|\b(?:res|response)(?:\.status\s*\(\s*5\d\d\s*\))?\.(?:send|json)\s*\([^;\n]*(?:\b(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\s*:|\(\s*(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\b)|\breturn\s*\{[^}\n]*(?:\b(?:error|detail|message)\s*:[^}\n]+,\s*)?\b(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\s*:/gi,
    severity: "low",
    message: "Detailed error or sensitive diagnostic information is returned to the client.",
    suggestion: "Return a generic error response and log stack traces, SQL, and sensitive diagnostics server-side only."
  }
];

export async function detectSast(text: string, filePath: string, timestamp: number, languageId?: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const astResult = await detectAstSast(text, filePath, languageId);
  const rulesById = new Map(sastRules.map((rule) => [rule.id, rule]));
  for (const candidate of astResult.candidates) {
    const rule = rulesById.get(candidate.ruleId);
    if (rule) {
      findings.push(createSastFinding(rule, candidate.index, candidate.endIndex, candidate.evidence, text, filePath, timestamp));
    }
  }

  for (const rule of sastRules) {
    if (astResult.handledRuleIds.has(rule.id)) {
      continue;
    }
    rule.regex.lastIndex = 0;
    for (const match of text.matchAll(rule.regex)) {
      const index = match.index ?? 0;
      findings.push(createSastFinding(rule, index, index + match[0].length, match[0], text, filePath, timestamp));
    }
  }
  return findings;
}

function createSastFinding(
  rule: SastRule,
  index: number,
  endIndex: number,
  evidence: string,
  text: string,
  filePath: string,
  timestamp: number
): Finding {
  if (rule.id === "sast_xss_inner_html") {
    const propertyAssignment = evidence.match(/\.(?:innerHTML|outerHTML)\s*=\s*[\s\S]+/i);
    if (propertyAssignment?.index !== undefined && propertyAssignment.index > 0) {
      return createSastFinding(
        rule,
        index + propertyAssignment.index,
        index + propertyAssignment.index + propertyAssignment[0].length,
        propertyAssignment[0],
        text,
        filePath,
        timestamp
      );
    }
  }
  const replacement = rule.replacement?.(evidence, text, index);
  const finding = createFinding({
    type: rule.type,
    severity: rule.severity,
    message: rule.message,
    file: filePath,
    index,
    endIndex,
    text,
    evidence,
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
  return finding;
}

function parameterizeSqliteFString(evidence: string, sourceText: string): string | undefined {
  if (!/\b(?:import\s+sqlite3|from\s+sqlite3\s+import|sqlite3\s*\.\s*connect)\b/i.test(sourceText)) {
    return undefined;
  }
  const match = evidence.match(
    /^(\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*\s*\.)+)?execute\s*\(\s*)f(["'])([^"']*)\{([A-Za-z_][A-Za-z0-9_]*)\}([^"']*)\2\s*\)$/
  );
  if (!match || /[{}]/.test(`${match[3]}${match[5]}`)) {
    return undefined;
  }
  return `${match[1]}${match[2]}${match[3]}?${match[5]}${match[2]}, (${match[4]},))`;
}
