import type { Finding } from "../types";
import { createFinding, isEnvReference, lineTextAt, redactSecret, shannonEntropy } from "../utils";

interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: "critical" | "high";
}

const secretPatterns: SecretPattern[] = [
  {
    id: "hardcoded_secret_aws_access_key",
    label: "AWS access key",
    regex: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_github_token",
    label: "GitHub token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_openai_key",
    label: "OpenAI API key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_anthropic_key",
    label: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_jwt",
    label: "JWT token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_private_key",
    label: "private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_database_url",
    label: "database URL with password",
    regex: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s/@]+:[^@\s]+@[^)\s'"]+/gi,
    severity: "critical"
  }
];

const sensitiveAssignment =
  /\b([A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret)[A-Za-z0-9_]*)\b\s*[:=]\s*(["'`])((?:\\.|(?!\2).){6,})\2/gi;

const stringLiteral = /(["'`])((?:\\.|(?!\1).){20,})\1/g;

export function detectSecrets(text: string, filePath: string, timestamp: number): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of secretPatterns) {
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      const index = match.index ?? 0;
      findings.push(
        createFinding({
          type: "hardcoded_secret",
          severity: pattern.severity,
          message: `${pattern.label} appears to be hardcoded.`,
          file: filePath,
          index,
          endIndex: index + match[0].length,
          text,
          evidence: redactSecret(match[0]),
          suggestion: "Move the secret to an environment variable or OS keychain and rotate the exposed value.",
          detectionLayer: "L1",
          ruleId: pattern.id,
          timestamp
        })
      );
    }
  }

  sensitiveAssignment.lastIndex = 0;
  for (const match of text.matchAll(sensitiveAssignment)) {
    const index = match.index ?? 0;
    const line = lineTextAt(text, index);
    const value = match[3] ?? "";
    if (isEnvReference(line) || isPlaceholder(value)) {
      continue;
    }
    findings.push(
      createFinding({
        type: "hardcoded_secret",
        severity: "critical",
        message: `Sensitive variable "${match[1]}" is assigned a literal value.`,
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: `${match[1]} = ${redactSecret(value)}`,
        suggestion: "Read this value from an environment variable or secret manager instead of committing it.",
        detectionLayer: "L1",
        ruleId: "hardcoded_secret_assignment",
        timestamp
      })
    );
  }

  stringLiteral.lastIndex = 0;
  for (const match of text.matchAll(stringLiteral)) {
    const index = match.index ?? 0;
    const literal = match[2] ?? "";
    if (!isLikelyHighEntropySecret(literal) || isEnvReference(lineTextAt(text, index))) {
      continue;
    }
    findings.push(
      createFinding({
        type: "hardcoded_secret",
        severity: "high",
        message: "High-entropy string literal may be a secret.",
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: redactSecret(literal),
        suggestion: "If this is a credential, rotate it and load it from a secure runtime source.",
        detectionLayer: "L1",
        ruleId: "hardcoded_secret_high_entropy_string",
        timestamp
      })
    );
  }

  return findings;
}

function isPlaceholder(value: string): boolean {
  return /^(changeme|change_me|example|placeholder|your[_-]?key|test|dummy|xxx+)$/i.test(value.trim());
}

function isLikelyHighEntropySecret(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 24 || trimmed.length > 180) {
    return false;
  }
  if (/\s/.test(trimmed) || /^https?:\/\//i.test(trimmed) || /^[a-f0-9]{6}$/i.test(trimmed)) {
    return false;
  }
  if (!/[A-Za-z]/.test(trimmed) || !/[0-9]/.test(trimmed)) {
    return false;
  }
  return shannonEntropy(trimmed) >= 4.5;
}
