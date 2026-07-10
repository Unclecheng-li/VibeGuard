import type { CodeFix, Finding } from "../types";
import { createFinding, extensionOf, isEnvReference, lineTextAt, positionAt, redactSecret, shannonEntropy } from "../utils";

interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: "critical" | "high";
}

interface SecretRange {
  start: number;
  end: number;
  findingIndex?: number;
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
    id: "hardcoded_secret_slack_token",
    label: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_stripe_key",
    label: "Stripe API key",
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_google_api_key",
    label: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_npm_token",
    label: "npm access token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_anthropic_key",
    label: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g,
    severity: "critical"
  },
  {
    id: "hardcoded_secret_openai_key",
    label: "OpenAI API key",
    regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
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
  /(?:\b((?:[A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*|(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential|authorization)[A-Za-z0-9_]*))\b|(["'])(authorization|x[_-]?api[_-]?key|api[_-]?key|secret|secret[_-]?key|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|credential)\2)\s*[:=]\s*(["'`])((?:\\.|(?!\4).){6,})\4/gi;

const stringLiteral = /(["'`])((?:\\.|(?!\1).){20,})\1/g;

export function detectSecrets(text: string, filePath: string, timestamp: number): Finding[] {
  const findings: Finding[] = [];
  const reportedRanges: SecretRange[] = [];

  for (const pattern of secretPatterns) {
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      const index = match.index ?? 0;
      const endIndex = index + match[0].length;
      if (overlapsRange(index, endIndex, reportedRanges)) {
        continue;
      }
      const finding = createFinding({
        type: "hardcoded_secret",
        severity: pattern.severity,
        message: `${pattern.label} appears to be hardcoded.`,
        file: filePath,
        index,
        endIndex,
        text,
        evidence: redactSecret(match[0]),
        suggestion: "Move the secret to an environment variable or OS keychain and rotate the exposed value.",
        detectionLayer: "L1",
        ruleId: pattern.id,
        timestamp
      });
      const fix = buildProviderSecretFix(text, filePath, index, match[0]);
      if (fix) {
        finding.fix = fix;
      }
      findings.push(finding);
      reportedRanges.push({ start: index, end: endIndex, findingIndex: findings.length - 1 });
    }
  }

  sensitiveAssignment.lastIndex = 0;
  for (const match of text.matchAll(sensitiveAssignment)) {
    const index = match.index ?? 0;
    const line = lineTextAt(text, index);
    const value = match[5] ?? "";
    const payload = secretPayload(value);
    const valueRange = rangeForCapturedValue(index, match[0], value);
    const overlapping = overlappingRange(valueRange.start, valueRange.end, reportedRanges);
    if (isEnvReference(line) || isPlaceholder(payload)) {
      continue;
    }
    const contextName = match[1] ?? match[3] ?? "secret";
    const fix = buildSecretAssignmentFix(text, filePath, match[0], contextName, value, valueRange);
    if (overlapping) {
      const existingFinding = overlapping.findingIndex === undefined ? undefined : findings[overlapping.findingIndex];
      if (existingFinding && fix && !existingFinding.fix) {
        existingFinding.fix = fix;
      }
      continue;
    }
    const isHighEntropy = isLikelyHighEntropySecret(payload, true);
    const ruleId = isHighEntropy ? "hardcoded_secret_high_entropy_assignment" : "hardcoded_secret_assignment";
    findings.push(
      createFinding({
        type: "hardcoded_secret",
        severity: "critical",
        message: isHighEntropy
          ? `Sensitive value "${contextName}" is assigned a high-entropy literal.`
          : `Sensitive value "${contextName}" is assigned a literal value.`,
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: `${contextName} = ${redactSecret(payload)}`,
        suggestion: "Read this value from an environment variable or secret manager instead of committing it.",
        fix,
        detectionLayer: "L1",
        ruleId,
        timestamp
      })
    );
    reportedRanges.push(valueRange);
  }

  stringLiteral.lastIndex = 0;
  for (const match of text.matchAll(stringLiteral)) {
    const index = match.index ?? 0;
    const literal = match[2] ?? "";
    const line = lineTextAt(text, index);
    const payload = secretPayload(literal);
    const valueRange = { start: index + (match[1]?.length ?? 1), end: index + (match[1]?.length ?? 1) + literal.length };
    const hasContext = hasSecretContext(line);
    if (
      overlapsRange(valueRange.start, valueRange.end, reportedRanges) ||
      isEnvReference(line) ||
      isPlaceholder(payload) ||
      !isLikelyHighEntropySecret(payload, hasContext) ||
      isBenignHighEntropyValue(payload, line, hasContext) ||
      (!hasContext && !looksLikeStandaloneSecret(payload))
    ) {
      continue;
    }
    const ruleId = hasContext ? "hardcoded_secret_high_entropy_context" : "hardcoded_secret_high_entropy_string";
    findings.push(
      createFinding({
        type: "hardcoded_secret",
        severity: hasContext ? "critical" : "high",
        message: hasContext ? "High-entropy string appears in a credential context." : "High-entropy string literal may be a secret.",
        file: filePath,
        index,
        endIndex: index + match[0].length,
        text,
        evidence: redactSecret(payload),
        suggestion: "If this is a credential, rotate it and load it from a secure runtime source.",
        detectionLayer: "L1",
        ruleId,
        timestamp
      })
    );
    reportedRanges.push(valueRange);
  }

  return findings;
}

function isPlaceholder(value: string): boolean {
  const normalized = secretPayload(value).trim().toLowerCase().replace(/\s+/g, "-");
  return /^(changeme|change-me|example|sample|placeholder|your-key|your-api-key|your-secret|your-token|test|test-key|test-token|test-secret|dummy|dummy-key|dummy-token|fake|fake-key|fake-token|todo|xxx+)$/i.test(
    normalized
  );
}

function isLikelyHighEntropySecret(value: string, contextual = false): boolean {
  const trimmed = secretPayload(value).trim();
  if (trimmed.length < (contextual ? 16 : 24) || trimmed.length > 180) {
    return false;
  }
  if (/\s/.test(trimmed) || /^https?:\/\//i.test(trimmed) || /^[a-f0-9]{6}$/i.test(trimmed)) {
    return false;
  }
  if (!/[A-Za-z]/.test(trimmed) || !/[0-9]/.test(trimmed)) {
    return false;
  }
  if (distinctCharacterRatio(trimmed) < 0.45 || repeatedCharacterRun(trimmed) >= 8) {
    return false;
  }

  const threshold = contextual ? (trimmed.length >= 32 ? 4.1 : 3.8) : 4.5;
  return shannonEntropy(trimmed) >= threshold;
}

function secretPayload(value: string): string {
  const trimmed = value.trim();
  const authMatch = /^(?:bearer|token)\s+(.+)$/i.exec(trimmed);
  return authMatch?.[1]?.trim() ?? trimmed;
}

function hasSecretContext(line: string): boolean {
  return /\b(?:api[_-]?key|secret|password|passwd|pwd|token|authorization|credential|private[_-]?key|jwt|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|signing[_-]?secret|x[_-]?api[_-]?key)\b/i.test(
    line
  );
}

function looksLikeStandaloneSecret(value: string): boolean {
  const trimmed = secretPayload(value).trim();
  return trimmed.length >= 32 && characterClassCount(trimmed) >= 3 && shannonEntropy(trimmed) >= 4.8;
}

function isBenignHighEntropyValue(value: string, line: string, hasContext: boolean): boolean {
  const trimmed = secretPayload(value).trim();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trimmed)) {
    return true;
  }
  if (!hasContext && /^[a-f0-9]{32,128}$/i.test(trimmed)) {
    return true;
  }
  if (!hasContext && /\b(?:hash|checksum|digest|sha(?:1|256|384|512)?|md5|uuid|guid|fixture|snapshot|testdata|certificate|public[_-]?key|data:image|base64|integrity|sri)\b/i.test(line)) {
    return true;
  }
  return false;
}

function distinctCharacterRatio(value: string): number {
  return new Set(value).size / value.length;
}

function repeatedCharacterRun(value: string): number {
  const match = /(.)\1+/g;
  let longest = 0;
  for (const run of value.matchAll(match)) {
    longest = Math.max(longest, run[0].length);
  }
  return longest;
}

function characterClassCount(value: string): number {
  return [/[a-z]/.test(value), /[A-Z]/.test(value), /[0-9]/.test(value), /[^A-Za-z0-9]/.test(value)].filter(Boolean).length;
}

function buildSecretAssignmentFix(
  text: string,
  filePath: string,
  fullMatch: string,
  contextName: string,
  value: string,
  valueRange: SecretRange
): CodeFix | undefined {
  if (!fullMatch.slice(0, fullMatch.lastIndexOf(value)).includes("=")) {
    return undefined;
  }

  return buildSecretLiteralFix(text, filePath, contextName, valueRange);
}

function buildProviderSecretFix(text: string, filePath: string, secretIndex: number, value: string): CodeFix | undefined {
  const lineStart = text.lastIndexOf("\n", Math.max(0, secretIndex - 1)) + 1;
  const beforeSecret = text.slice(lineStart, secretIndex);
  const contextMatch = /\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(?:(["'`])[^"'`]*)?$/.exec(beforeSecret);
  const contextName = contextMatch?.[1];
  if (!contextName) {
    return undefined;
  }
  return buildSecretLiteralFix(text, filePath, contextName, { start: secretIndex, end: secretIndex + value.length });
}

function buildSecretLiteralFix(text: string, filePath: string, contextName: string, valueRange: SecretRange): CodeFix | undefined {
  const envName = environmentName(contextName);
  const replacement = secretRuntimeReference(text, filePath, envName);
  if (!replacement) {
    return undefined;
  }

  const literalRange = quotedLiteralRange(text, valueRange);
  const start = positionAt(text, literalRange.start);
  const end = positionAt(text, literalRange.end);
  const edits = [
    {
      startLine: start.line,
      startColumn: start.column,
      endLine: end.line,
      endColumn: end.column,
      newText: replacement.newText
    }
  ];

  if (replacement.importEdit) {
    edits.unshift(replacement.importEdit);
  }

  return {
    description: `Read ${envName} from the environment`,
    edits
  };
}

function environmentName(contextName: string): string {
  const normalized = contextName
    .replace(/["'`]/g, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
  return normalized || "VIBEGUARD_SECRET";
}

function secretRuntimeReference(
  text: string,
  filePath: string,
  envName: string
): { newText: string; importEdit?: CodeFix["edits"][number] } | undefined {
  const extension = extensionOf(filePath);
  if (["js", "jsx", "ts", "tsx", "mjs", "cjs"].includes(extension)) {
    return { newText: `process.env.${envName} ?? ""` };
  }

  if (extension === "py") {
    if (/(^|\n)\s*from\s+os\s+import\s+[^#\n]*\bgetenv\b/.test(text)) {
      return { newText: `getenv("${envName}", "")` };
    }
    const hasOsImport = /(^|\n)\s*import\s+[^#\n]*\bos\b/.test(text);
    const importEdit = hasOsImport ? undefined : pythonImportEdit(text);
    return {
      newText: `os.getenv("${envName}", "")`,
      importEdit
    };
  }

  return undefined;
}

function pythonImportEdit(text: string): CodeFix["edits"][number] {
  const offset = pythonImportInsertOffset(text);
  const position = positionAt(text, offset);
  return {
    startLine: position.line,
    startColumn: position.column,
    endLine: position.line,
    endColumn: position.column,
    newText: "import os\n"
  };
}

function pythonImportInsertOffset(text: string): number {
  let offset = 0;
  const firstLineEnd = text.indexOf("\n");
  const firstLine = firstLineEnd === -1 ? text : text.slice(0, firstLineEnd);
  if (firstLine.startsWith("#!")) {
    offset = firstLineEnd === -1 ? text.length : firstLineEnd + 1;
  }

  const nextLineEnd = text.indexOf("\n", offset);
  const nextLine = nextLineEnd === -1 ? text.slice(offset) : text.slice(offset, nextLineEnd);
  if (/coding[:=]\s*[-\w.]+/.test(nextLine)) {
    offset = nextLineEnd === -1 ? text.length : nextLineEnd + 1;
  }
  return offset;
}

function quotedLiteralRange(text: string, valueRange: SecretRange): SecretRange {
  const quoteBefore = text[valueRange.start - 1];
  const quoteAfter = text[valueRange.end];
  if (quoteBefore && quoteBefore === quoteAfter && /["'`]/.test(quoteBefore)) {
    return { start: valueRange.start - 1, end: valueRange.end + 1 };
  }
  return valueRange;
}

function rangeForCapturedValue(matchIndex: number, fullMatch: string, value: string): SecretRange {
  const offset = fullMatch.lastIndexOf(value);
  const start = matchIndex + Math.max(0, offset);
  return { start, end: start + value.length };
}

function overlapsRange(start: number, end: number, ranges: SecretRange[]): boolean {
  return Boolean(overlappingRange(start, end, ranges));
}

function overlappingRange(start: number, end: number, ranges: SecretRange[]): SecretRange | undefined {
  return ranges.find((range) => start < range.end && end > range.start);
}
