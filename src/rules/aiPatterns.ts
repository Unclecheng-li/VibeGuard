import type { Finding, Severity } from "../types";
import { createFinding } from "../utils";

export interface AiPatternRule {
  id: string;
  regex: RegExp;
  patternRegex: string;
  languages?: string[];
  severity: Severity;
  message: string;
  suggestion: string;
}

export const aiPatternRules: AiPatternRule[] = [
  {
    id: "ai_pattern_default_password",
    patternRegex: "\\b(?:password|passwd|pwd)\\s*[:=]\\s*[\"'](?:admin|password|123456|12345678|changeme)[\"']",
    regex: /\b(?:password|passwd|pwd)\s*[:=]\s*["'](?:admin|password|123456|12345678|changeme)["']/gi,
    severity: "critical",
    message: "Default password is hardcoded.",
    suggestion: "Generate a unique secret per environment and force users to set their own password."
  },
  {
    id: "ai_pattern_admin_admin_credentials",
    patternRegex: "\\b(?:username|user|login)\\s*[:=]\\s*[\"']admin[\"'][\\s\\S]{0,120}\\b(?:password|passwd|pwd)\\s*[:=]\\s*[\"']admin[\"']",
    regex: /\b(?:username|user|login)\s*[:=]\s*["']admin["'][\s\S]{0,120}\b(?:password|passwd|pwd)\s*[:=]\s*["']admin["']/gi,
    severity: "critical",
    message: "Default admin/admin credentials are present.",
    suggestion: "Remove default credentials and provision an initial admin through a secure setup flow."
  },
  {
    id: "ai_pattern_hardcoded_jwt_secret",
    patternRegex: "\\bJWT_SECRET\\b\\s*[:=]\\s*[\"'`](?!process\\.env|import\\.meta\\.env|os\\.getenv)[^\"'`]{8,}[\"'`]",
    regex: /\bJWT_SECRET\b\s*[:=]\s*["'`](?!process\.env|import\.meta\.env|os\.getenv)[^"'`]{8,}["'`]/g,
    severity: "critical",
    message: "JWT secret is hardcoded.",
    suggestion: "Load JWT_SECRET from a secret manager or environment variable and rotate the committed value."
  },
  {
    id: "ai_pattern_sql_f_string",
    patternRegex: "\\bf[\"'`][^\"'`]*(?:SELECT|INSERT|UPDATE|DELETE)\\b[^\"'`]*\\{[^}]+}[^\"'`]*[\"'`]",
    languages: ["python"],
    regex: /\bf["'`][^"'`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*\{[^}]+\}[^"'`]*["'`]/gi,
    severity: "high",
    message: "SQL query appears to interpolate a variable directly.",
    suggestion: "Use parameterized queries instead of string interpolation."
  },
  {
    id: "ai_pattern_dangerously_set_inner_html",
    patternRegex: "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\\s*}",
    languages: ["javascript", "typescript"],
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\s*}/g,
    severity: "high",
    message: "dangerouslySetInnerHTML is used without an obvious sanitizer.",
    suggestion: "Sanitize HTML with a trusted sanitizer before passing it to dangerouslySetInnerHTML."
  },
  {
    id: "ai_pattern_frontend_secret_name",
    patternRegex: "\\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\\s*[:=]\\s*[\"'`][^\"'`]{8,}[\"'`]",
    languages: ["javascript", "typescript"],
    regex: /\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\s*[:=]\s*["'`][^"'`]{8,}["'`]/g,
    severity: "critical",
    message: "Secret-like value is exposed through a frontend environment variable.",
    suggestion: "Move secrets to server-side configuration; frontend-prefixed variables are public."
  },
  {
    id: "ai_pattern_jwt_none_algorithm",
    patternRegex: "\\bjwt\\.(?:sign|verify)\\s*\\([\\s\\S]{0,240}\\balgorithms?\\s*:\\s*(?:\\[\\s*)?[\"']none[\"']",
    languages: ["javascript", "typescript"],
    regex: /\bjwt\.(?:sign|verify)\s*\([\s\S]{0,240}\balgorithms?\s*:\s*(?:\[\s*)?["']none["']/gi,
    severity: "critical",
    message: "JWT accepts the none algorithm.",
    suggestion: "Remove none from allowed JWT algorithms and require a signed token algorithm such as RS256 or HS256."
  },
  {
    id: "ai_pattern_jwt_ignore_expiration",
    patternRegex: "\\bjwt\\.verify\\s*\\([\\s\\S]{0,240}\\bignoreExpiration\\s*:\\s*true\\b",
    languages: ["javascript", "typescript"],
    regex: /\bjwt\.verify\s*\([\s\S]{0,240}\bignoreExpiration\s*:\s*true\b/gi,
    severity: "high",
    message: "JWT expiration validation is disabled.",
    suggestion: "Require token expiration checks and refresh tokens through a controlled flow."
  },
  {
    id: "ai_pattern_jwt_decode_without_verify",
    patternRegex: "\\bjwt\\.decode\\s*\\(\\s*(?:req\\.|request\\.|token|authorization|authHeader)",
    languages: ["javascript", "typescript"],
    regex: /\bjwt\.decode\s*\(\s*(?:req\.|request\.|token|authorization|authHeader)/gi,
    severity: "high",
    message: "JWT is decoded without signature verification.",
    suggestion: "Use jwt.verify() with an expected algorithm and issuer/audience checks before trusting token claims."
  },
  {
    id: "ai_pattern_cors_credentials_wildcard",
    patternRegex: "\\bcors\\s*\\(\\s*\\{(?:[\\s\\S]{0,240}\\borigin\\s*:\\s*[\"']\\*[\"'][\\s\\S]{0,240}\\bcredentials\\s*:\\s*true|[\\s\\S]{0,240}\\bcredentials\\s*:\\s*true[\\s\\S]{0,240}\\borigin\\s*:\\s*[\"']\\*[\"'])",
    languages: ["javascript", "typescript"],
    regex: /\bcors\s*\(\s*\{(?:[\s\S]{0,240}\borigin\s*:\s*["']\*["'][\s\S]{0,240}\bcredentials\s*:\s*true|[\s\S]{0,240}\bcredentials\s*:\s*true[\s\S]{0,240}\borigin\s*:\s*["']\*["'])/gi,
    severity: "high",
    message: "CORS allows wildcard origins with credentials.",
    suggestion: "Use an explicit origin allowlist when credentials or cookies are allowed."
  },
  {
    id: "ai_pattern_tls_verification_disabled",
    patternRegex: "\\bNODE_TLS_REJECT_UNAUTHORIZED\\b\\s*=\\s*[\"']?0[\"']?|\\brejectUnauthorized\\s*:\\s*false\\b",
    languages: ["javascript", "typescript"],
    regex: /\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']?0["']?|\brejectUnauthorized\s*:\s*false\b/gi,
    severity: "high",
    message: "TLS certificate verification is disabled.",
    suggestion: "Keep certificate verification enabled and fix trust store or certificate configuration instead."
  },
  {
    id: "ai_pattern_requests_verify_false",
    patternRegex: "\\brequests\\.(?:get|post|put|patch|delete|request)\\s*\\([^\\)\\n]*\\bverify\\s*=\\s*False\\b",
    languages: ["python"],
    regex: /\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\)\n]*\bverify\s*=\s*False\b/g,
    severity: "high",
    message: "Python HTTP request disables TLS verification.",
    suggestion: "Remove verify=False and configure trusted certificate authorities explicitly."
  },
  {
    id: "ai_pattern_bcrypt_low_rounds",
    patternRegex: "\\bbcrypt(?:js)?\\.(?:hash|genSalt)\\s*\\([^\\)\\n]*,\\s*[0-4]\\s*\\)",
    languages: ["javascript", "typescript"],
    regex: /\bbcrypt(?:js)?\.(?:hash|genSalt)\s*\([^\)\n]*,\s*[0-4]\s*\)/gi,
    severity: "high",
    message: "bcrypt uses an extremely low work factor.",
    suggestion: "Use a modern bcrypt cost factor, commonly 10 or higher, and tune it for your environment."
  },
  {
    id: "ai_pattern_plaintext_password_compare",
    patternRegex: "\\b(?:password|passwd|pwd)\\s*={2,3}\\s*(?:user|dbUser|account)\\.(?:password|passwd|pwd)\\b|\\b(?:user|dbUser|account)\\.(?:password|passwd|pwd)\\s*={2,3}\\s*(?:password|passwd|pwd)\\b",
    languages: ["javascript", "typescript"],
    regex: /\b(?:password|passwd|pwd)\s*={2,3}\s*(?:user|dbUser|account)\.(?:password|passwd|pwd)\b|\b(?:user|dbUser|account)\.(?:password|passwd|pwd)\s*={2,3}\s*(?:password|passwd|pwd)\b/gi,
    severity: "high",
    message: "Password appears to be compared in plaintext.",
    suggestion: "Store password hashes and compare with a constant-time password hashing verifier such as bcrypt.compare()."
  },
  {
    id: "ai_pattern_weak_password_hash",
    patternRegex: "\\b(?:crypto\\.)?createHash\\s*\\(\\s*[\"'](?:md5|sha1)[\"']\\s*\\)[\\s\\S]{0,160}\\b(?:password|passwd|pwd)\\b|\\bhashlib\\.(?:md5|sha1)\\s*\\([^\\)\\n]*(?:password|passwd|pwd)",
    languages: ["javascript", "typescript", "python"],
    regex: /\b(?:crypto\.)?createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)[\s\S]{0,160}\b(?:password|passwd|pwd)\b|\bhashlib\.(?:md5|sha1)\s*\([^\)\n]*(?:password|passwd|pwd)/gi,
    severity: "high",
    message: "Weak hash function appears to protect a password.",
    suggestion: "Use a password hashing function such as bcrypt, scrypt, Argon2, or PBKDF2 with a per-user salt."
  },
  {
    id: "ai_pattern_session_secret_placeholder",
    patternRegex: "\\b(?:session|cookieSession)\\s*\\(\\s*\\{[\\s\\S]{0,180}\\bsecret\\s*:\\s*[\"'](?:secret|keyboard cat|changeme|password|123456)[\"']",
    languages: ["javascript", "typescript"],
    regex: /\b(?:session|cookieSession)\s*\(\s*\{[\s\S]{0,180}\bsecret\s*:\s*["'](?:secret|keyboard cat|changeme|password|123456)["']/gi,
    severity: "critical",
    message: "Session middleware uses a placeholder secret.",
    suggestion: "Load a high-entropy session secret from a secret manager or environment variable."
  },
  {
    id: "ai_pattern_math_random_token",
    patternRegex: "\\b(?:token|secret|apiKey|resetToken|sessionId)\\b\\s*[:=]\\s*Math\\.random\\s*\\(",
    languages: ["javascript", "typescript"],
    regex: /\b(?:token|secret|apiKey|resetToken|sessionId)\b\s*[:=]\s*Math\.random\s*\(/g,
    severity: "high",
    message: "Security token is generated with Math.random().",
    suggestion: "Use crypto.randomBytes() or Web Crypto for security-sensitive random values."
  },
  {
    id: "ai_pattern_flask_secret_key_placeholder",
    patternRegex: "\\b(?:app\\.config\\s*\\[\\s*[\"']SECRET_KEY[\"']\\s*\\]\\s*=|SECRET_KEY\\s*=)\\s*[\"'](?:secret|dev|development|changeme|password|123456)[\"']",
    languages: ["python"],
    regex: /\b(?:app\.config\s*\[\s*["']SECRET_KEY["']\s*\]\s*=|SECRET_KEY\s*=)\s*["'](?:secret|dev|development|changeme|password|123456)["']/gi,
    severity: "critical",
    message: "Flask/Django secret key uses a placeholder value.",
    suggestion: "Generate a high-entropy SECRET_KEY and load it from environment-specific secret storage."
  },
  {
    id: "ai_pattern_fastapi_cors_credentials_wildcard",
    patternRegex: "\\bCORSMiddleware\\b[\\s\\S]{0,300}\\ballow_origins\\s*=\\s*\\[\\s*[\"']\\*[\"']\\s*\\][\\s\\S]{0,300}\\ballow_credentials\\s*=\\s*True\\b",
    languages: ["python"],
    regex: /\bCORSMiddleware\b[\s\S]{0,300}\ballow_origins\s*=\s*\[\s*["']\*["']\s*\][\s\S]{0,300}\ballow_credentials\s*=\s*True\b/g,
    severity: "high",
    message: "CORS allows wildcard origins with credentials.",
    suggestion: "Set allow_origins to explicit trusted origins when credentials are enabled."
  },
  {
    id: "ai_pattern_s3_public_read_acl",
    patternRegex: "\\b(?:ACL|acl)\\s*[:=]\\s*[\"']public-read[\"']|\\.putObjectAcl\\s*\\([\\s\\S]{0,160}public-read",
    languages: ["javascript", "typescript", "python"],
    regex: /\b(?:ACL|acl)\s*[:=]\s*["']public-read["']|\.putObjectAcl\s*\([\s\S]{0,160}public-read/gi,
    severity: "high",
    message: "Object storage ACL grants public read access.",
    suggestion: "Keep uploaded objects private by default and serve public assets through explicit, reviewed policies."
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
