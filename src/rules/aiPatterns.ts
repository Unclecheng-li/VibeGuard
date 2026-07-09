import type { Finding, Severity } from "../types";
import { createFinding } from "../utils";

interface AiPatternRule {
  id: string;
  regex: RegExp;
  severity: Severity;
  message: string;
  suggestion: string;
}

const aiPatternRules: AiPatternRule[] = [
  {
    id: "ai_pattern_default_password",
    regex: /\b(?:password|passwd|pwd)\s*[:=]\s*["'](?:admin|password|123456|12345678|changeme)["']/gi,
    severity: "critical",
    message: "Default password is hardcoded.",
    suggestion: "Generate a unique secret per environment and force users to set their own password."
  },
  {
    id: "ai_pattern_admin_admin_credentials",
    regex: /\b(?:username|user|login)\s*[:=]\s*["']admin["'][\s\S]{0,120}\b(?:password|passwd|pwd)\s*[:=]\s*["']admin["']/gi,
    severity: "critical",
    message: "Default admin/admin credentials are present.",
    suggestion: "Remove default credentials and provision an initial admin through a secure setup flow."
  },
  {
    id: "ai_pattern_hardcoded_jwt_secret",
    regex: /\bJWT_SECRET\b\s*[:=]\s*["'`](?!process\.env|import\.meta\.env|os\.getenv)[^"'`]{8,}["'`]/g,
    severity: "critical",
    message: "JWT secret is hardcoded.",
    suggestion: "Load JWT_SECRET from a secret manager or environment variable and rotate the committed value."
  },
  {
    id: "ai_pattern_sql_f_string",
    regex: /\bf["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*\{[^}]+\}[^"'`]*["'`]/gi,
    severity: "high",
    message: "SQL query appears to interpolate a variable directly.",
    suggestion: "Use parameterized queries instead of string interpolation."
  },
  {
    id: "ai_pattern_dangerously_set_inner_html",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\s*}/g,
    severity: "high",
    message: "dangerouslySetInnerHTML is used without an obvious sanitizer.",
    suggestion: "Sanitize HTML with a trusted sanitizer before passing it to dangerouslySetInnerHTML."
  },
  {
    id: "ai_pattern_frontend_secret_name",
    regex: /\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\s*[:=]\s*["'`][^"'`]{8,}["'`]/g,
    severity: "critical",
    message: "Secret-like value is exposed through a frontend environment variable.",
    suggestion: "Move secrets to server-side configuration; frontend-prefixed variables are public."
  }
];

export function detectAiPatterns(text: string, filePath: string, timestamp: number): Finding[] {
  const findings: Finding[] = [];
  for (const rule of aiPatternRules) {
    rule.regex.lastIndex = 0;
    for (const match of text.matchAll(rule.regex)) {
      const index = match.index ?? 0;
      findings.push(
        createFinding({
          type: "ai_pattern_error",
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
        })
      );
    }
  }
  return findings;
}
