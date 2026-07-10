import type { Finding, L3AnalyzerLike, Severity, SourceFile, VibeGuardConfig } from "../types";
import { createFinding, lineStarts, lineTextAt } from "../utils";
import { LocalSemanticAnalyzer } from "./analyzer";

export type LlmProvider = NonNullable<VibeGuardConfig["llm_provider"]>;

export interface LlmSemanticAnalyzerOptions {
  provider: LlmProvider;
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  fallbackAnalyzer?: L3AnalyzerLike | false;
}

interface LlmFindingPayload {
  ruleId?: unknown;
  rule_id?: unknown;
  severity?: unknown;
  message?: unknown;
  evidence?: unknown;
  suggestion?: unknown;
  replacement?: unknown;
  line?: unknown;
  column?: unknown;
}

const systemPrompt = [
  "You are VibeGuard's L3 semantic security reviewer.",
  "Find missing security measures in AI-generated code.",
  "Return only JSON. Do not include markdown.",
  "Use this schema: {\"findings\":[{\"ruleId\":\"l3_llm_missing_authentication\",\"severity\":\"high\",\"message\":\"...\",\"evidence\":\"exact code snippet\",\"suggestion\":\"...\",\"replacement\":\"optional replacement for exactly the evidence snippet\",\"line\":1,\"column\":1}]}",
  "Only provide replacement when replacing exactly the evidence snippet is a complete, reviewable fix. Do not use Markdown fences, unified diffs, or edits outside evidence.",
  "Only report actionable issues involving authentication, authorization, rate limiting, input validation, output encoding, parameterized queries, error handling, SSRF, path traversal, insecure deserialization, or secret exposure."
].join("\n");

export class LlmSemanticAnalyzer implements L3AnalyzerLike {
  private readonly fallbackAnalyzer: L3AnalyzerLike | undefined;

  constructor(private readonly options: LlmSemanticAnalyzerOptions) {
    this.fallbackAnalyzer =
      options.fallbackAnalyzer === false ? undefined : options.fallbackAnalyzer ?? new LocalSemanticAnalyzer();
  }

  async analyze(source: SourceFile, timestamp: number): Promise<Finding[]> {
    if (this.options.provider !== "local" && !this.options.apiKey) {
      return this.fallback(source, timestamp);
    }

    try {
      const raw = await requestLlmSecurityReview(this.options, buildLlmSecurityReviewPrompt(source));
      return parseLlmSecurityFindings(raw, source, timestamp);
    } catch {
      return this.fallback(source, timestamp);
    }
  }

  private async fallback(source: SourceFile, timestamp: number): Promise<Finding[]> {
    return this.fallbackAnalyzer ? await this.fallbackAnalyzer.analyze(source, timestamp) : [];
  }
}

export async function requestLlmSecurityReview(options: LlmSemanticAnalyzerOptions, prompt: string): Promise<string> {
  if (options.provider === "claude") {
    return requestClaudeReview(options, prompt);
  }
  if (options.provider === "local") {
    return requestOllamaReview(options, prompt);
  }
  return requestOpenAiCompatibleReview(options, prompt);
}

export function parseLlmSecurityFindings(raw: string, source: SourceFile, timestamp: number): Finding[] {
  const parsed = parseJsonResponse(raw);
  const values = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as Record<string, unknown>).findings)
      ? ((parsed as Record<string, unknown>).findings as unknown[])
      : [];

  return values
    .map((value) => normalizeLlmFinding(value, source, timestamp))
    .filter((finding): finding is Finding => finding !== undefined)
    .slice(0, 10);
}

export function getLlmApiKeyFromEnv(provider: LlmProvider, explicitEnvVar?: string): string | undefined {
  if (provider === "local") {
    return undefined;
  }
  const names = explicitEnvVar ? [explicitEnvVar] : llmApiKeyEnvNames(provider);
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) {
      return value;
    }
  }
  return undefined;
}

export function llmApiKeyEnvNames(provider: LlmProvider): string[] {
  switch (provider) {
    case "deepseek":
      return ["DEEPSEEK_API_KEY", "VIBEGUARD_LLM_API_KEY"];
    case "claude":
      return ["ANTHROPIC_API_KEY", "VIBEGUARD_LLM_API_KEY"];
    case "openai":
      return ["OPENAI_API_KEY", "VIBEGUARD_LLM_API_KEY"];
    case "local":
      return [];
  }
}

export function defaultLlmModel(provider: LlmProvider): string {
  switch (provider) {
    case "deepseek":
      return "deepseek-v4-flash";
    case "claude":
      return "claude-3-5-haiku-latest";
    case "openai":
      return "gpt-4.1-mini";
    case "local":
      return "llama3.2";
  }
}

export function defaultLlmBaseUrl(provider: LlmProvider): string {
  switch (provider) {
    case "deepseek":
      return "https://api.deepseek.com";
    case "claude":
      return "https://api.anthropic.com/v1";
    case "openai":
      return "https://api.openai.com/v1";
    case "local":
      return "http://localhost:11434";
  }
}

export function buildLlmSecurityReviewPrompt(source: SourceFile): string {
  const code = clipSource(source.text, 16000);
  return [
    "Review this code for missing security controls. Focus on issues that require semantic understanding beyond simple regex matching.",
    "",
    `File: ${source.filePath}`,
    `Language: ${source.languageId ?? "unknown"}`,
    "",
    "Return JSON only. If there are no actionable findings, return {\"findings\":[]}.",
    "Each finding must include: ruleId, severity, message, evidence, suggestion, line, column.",
    "Use exact code snippets for evidence so the editor can place diagnostics.",
    "Optionally include replacement only when it can replace exactly that evidence snippet without edits elsewhere. Do not include Markdown fences or diffs.",
    "",
    "Code:",
    "```",
    code,
    "```"
  ].join("\n");
}

async function requestOpenAiCompatibleReview(options: LlmSemanticAnalyzerOptions, prompt: string): Promise<string> {
  const body = {
    model: options.model ?? process.env.VIBEGUARD_LLM_MODEL ?? defaultLlmModel(options.provider),
    temperature: 0,
    max_tokens: 1200,
    stream: false,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: prompt }
    ]
  };
  const response = await fetchWithTimeout(
    endpointUrl(options.baseUrl ?? defaultLlmBaseUrl(options.provider), "/chat/completions"),
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${options.apiKey ?? ""}`,
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    },
    options
  );
  const parsed = await readJsonResponse(response, options.provider);
  const content = getNestedString(parsed, ["choices", 0, "message", "content"]);
  if (!content) {
    throw new Error(`${options.provider} response did not include message content.`);
  }
  return content;
}

async function requestClaudeReview(options: LlmSemanticAnalyzerOptions, prompt: string): Promise<string> {
  const body = {
    model: options.model ?? process.env.VIBEGUARD_LLM_MODEL ?? defaultLlmModel("claude"),
    max_tokens: 1200,
    temperature: 0,
    system: systemPrompt,
    messages: [{ role: "user", content: prompt }]
  };
  const response = await fetchWithTimeout(
    endpointUrl(options.baseUrl ?? defaultLlmBaseUrl("claude"), "/messages"),
    {
      method: "POST",
      headers: {
        "x-api-key": options.apiKey ?? "",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    },
    options
  );
  const parsed = await readJsonResponse(response, "claude");
  const content = (parsed as Record<string, unknown>).content;
  if (Array.isArray(content)) {
    const text = content.map((item) => getNestedString(item, ["text"])).filter(Boolean).join("\n");
    if (text) {
      return text;
    }
  }
  throw new Error("Claude response did not include text content.");
}

async function requestOllamaReview(options: LlmSemanticAnalyzerOptions, prompt: string): Promise<string> {
  const body = {
    model: options.model ?? process.env.VIBEGUARD_LLM_MODEL ?? defaultLlmModel("local"),
    stream: false,
    format: "json",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: prompt }
    ],
    options: {
      temperature: 0
    }
  };
  const response = await fetchWithTimeout(
    endpointUrl(options.baseUrl ?? defaultLlmBaseUrl("local"), "/api/chat"),
    {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(body)
    },
    options
  );
  const parsed = await readJsonResponse(response, "local");
  const messageContent = getNestedString(parsed, ["message", "content"]);
  const responseText = getNestedString(parsed, ["response"]);
  if (messageContent || responseText) {
    return messageContent || responseText || "";
  }
  throw new Error("Ollama response did not include message content.");
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  options: LlmSemanticAnalyzerOptions
): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, {
      ...init,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readJsonResponse(response: Response, provider: LlmProvider): Promise<unknown> {
  const raw = await response.text();
  if (!response.ok) {
    throw new Error(`${provider} LLM request failed: HTTP ${response.status} ${raw.slice(0, 200)}`.trim());
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${provider} LLM response was not valid JSON: ${detail}`);
  }
}

function normalizeLlmFinding(value: unknown, source: SourceFile, timestamp: number): Finding | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const input = value as LlmFindingPayload;
  const message = readNonEmptyString(input.message);
  const evidence = readNonEmptyString(input.evidence) ?? evidenceFromLine(source.text, input.line, input.column);
  if (!message || !evidence) {
    return undefined;
  }

  const index = findingIndex(source.text, evidence, input.line, input.column);
  const severity = normalizeSeverity(input.severity);
  const ruleId = normalizeRuleId(readNonEmptyString(input.ruleId) ?? readNonEmptyString(input.rule_id));
  const finding = createFinding({
    type: "missing_security_measure",
    severity,
    message: message.slice(0, 240),
    file: source.filePath,
    index,
    endIndex: Math.min(source.text.length, index + Math.max(1, evidence.length)),
    text: source.text,
    evidence,
    suggestion: readNonEmptyString(input.suggestion)?.slice(0, 400),
    detectionLayer: "L3",
    ruleId,
    timestamp
  });
  const replacement = safeReplacement(input.replacement, evidence, source.text, index);
  if (replacement) {
    finding.fix = {
      description: "Review LLM-generated replacement",
      edits: [
        {
          startLine: finding.line,
          startColumn: finding.column,
          endLine: finding.endLine ?? finding.line,
          endColumn: finding.endColumn ?? finding.column + evidence.length,
          newText: replacement
        }
      ]
    };
  }
  return finding;
}

function safeReplacement(value: unknown, evidence: string, sourceText: string, index: number): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const replacement = value.trim();
  if (
    !replacement ||
    replacement === evidence ||
    replacement.length > 8000 ||
    replacement.length > Math.max(2000, evidence.length * 20) ||
    replacement.includes("```") ||
    replacement.startsWith("diff --git") ||
    replacement.startsWith("--- ") ||
    replacement.includes("\n@@ ") ||
    replacement.includes("\u0000") ||
    sourceText.slice(index, index + evidence.length) !== evidence
  ) {
    return undefined;
  }
  return replacement;
}

function parseJsonResponse(raw: string): unknown {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    // Some providers wrap an otherwise valid JSON response in a Markdown fence.
  }
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1]?.trim();
  const candidate = fenced ?? jsonSubstring(trimmed);
  if (!candidate) {
    throw new Error("LLM response did not include JSON.");
  }
  return JSON.parse(candidate) as unknown;
}

function jsonSubstring(value: string): string | undefined {
  const objectStart = value.indexOf("{");
  const arrayStart = value.indexOf("[");
  const starts = [objectStart, arrayStart].filter((index) => index >= 0);
  if (starts.length === 0) {
    return undefined;
  }
  const start = Math.min(...starts);
  const objectEnd = value.lastIndexOf("}");
  const arrayEnd = value.lastIndexOf("]");
  const end = Math.max(objectEnd, arrayEnd);
  return end >= start ? value.slice(start, end + 1) : undefined;
}

function normalizeSeverity(value: unknown): Severity {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info"
    ? value
    : "medium";
}

function normalizeRuleId(value: string | undefined): string {
  const normalized = (value ?? "security_review").toLowerCase().replace(/[^a-z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "");
  return normalized.startsWith("l3_") ? normalized : `l3_llm_${normalized || "security_review"}`;
}

function findingIndex(text: string, evidence: string, line: unknown, column: unknown): number {
  const exact = text.indexOf(evidence);
  if (exact >= 0) {
    return exact;
  }
  const byLine = offsetFromLineColumn(text, line, column);
  return byLine ?? 0;
}

function offsetFromLineColumn(text: string, line: unknown, column: unknown): number | undefined {
  if (typeof line !== "number" || !Number.isInteger(line) || line < 1) {
    return undefined;
  }
  const starts = lineStarts(text);
  const lineStart = starts[line - 1];
  if (lineStart === undefined) {
    return undefined;
  }
  const columnOffset = typeof column === "number" && Number.isInteger(column) && column > 0 ? column - 1 : 0;
  return Math.min(text.length, lineStart + columnOffset);
}

function evidenceFromLine(text: string, line: unknown, column: unknown): string | undefined {
  const offset = offsetFromLineColumn(text, line, column);
  if (offset === undefined) {
    return undefined;
  }
  return lineTextAt(text, offset).trim() || undefined;
}

function endpointUrl(baseUrl: string, path: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  if (trimmed.endsWith(path)) {
    return trimmed;
  }
  return `${trimmed}${path}`;
}

function getNestedString(value: unknown, path: Array<string | number>): string | undefined {
  let current = value;
  for (const segment of path) {
    if (typeof segment === "number") {
      if (!Array.isArray(current)) {
        return undefined;
      }
      current = current[segment];
    } else {
      if (!current || typeof current !== "object") {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }
  }
  return readNonEmptyString(current);
}

function readNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function clipSource(text: string, maxLength: number): string {
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength)}\n/* VibeGuard truncated the remaining ${text.length - maxLength} characters for LLM review. */`;
}
