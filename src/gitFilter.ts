import { execFile } from "child_process";
import path from "path";
import { promisify } from "util";
import type { Finding } from "./types";

const execFileAsync = promisify(execFile);

export type ScanMode = "full-scan" | "ai-code-scan";
export type AiDetectionMode = "author" | "message" | "aggressive";

export interface GitRunner {
  run(args: string[], cwd: string): Promise<string>;
}

export interface FilterScanFilesOptions {
  mode: ScanMode;
  aiDetection: AiDetectionMode;
  baseRef?: string;
  headRef?: string;
  cwd?: string;
  runner?: GitRunner;
}

export interface FilteredScanFiles {
  files: string[];
  scannedMode: ScanMode;
  /** AI-attributed changed line ranges, keyed by normalized absolute file path. */
  aiLineRanges?: Map<string, AiLineRange[]>;
  warning?: string;
}

export interface AiLineRange {
  startLine: number;
  endLine: number;
}

interface CommitFacts {
  authorName: string;
  authorEmail: string;
  message: string;
}

interface BlameLine extends CommitFacts {
  hash: string;
  line: number;
}

const defaultRunner: GitRunner = {
  async run(args: string[], cwd: string): Promise<string> {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 10 * 1024 * 1024
    });
    return stdout;
  }
};

const aiAuthorPattern = /(?:github-actions\[bot]|cursor-bot|claude\[bot]|copilot|anthropic|openai|chatgpt|gpt|cursor)/i;
const aiMessagePatterns = [
  /co-authored-by:.*(?:copilot|cursor|claude|openai|chatgpt|gpt|anthropic)/i,
  /\b(?:generated|created|written|authored)\s+by\s+(?:ai|copilot|cursor|claude|openai|chatgpt|gpt)\b/i,
  /\b(?:copilot|cursor|claude|openai|chatgpt|gpt)\b.*\b(?:generated|created|wrote|authored)\b/i,
  /\bai[- ]generated\b/i
];

export async function filterScanFiles(files: string[], options: FilterScanFilesOptions): Promise<FilteredScanFiles> {
  if (options.mode === "full-scan") {
    return {
      files,
      scannedMode: "full-scan"
    };
  }

  const cwd = options.cwd ?? process.cwd();
  const runner = options.runner ?? defaultRunner;
  const range = gitRange(options.baseRef, options.headRef);

  try {
    const changedFiles = await listChangedFiles(runner, cwd, range);
    const changedSet = new Set(changedFiles.map((file) => normalizeAbsolutePath(path.resolve(cwd, file))));
    const candidates = files.filter((file) => changedSet.has(normalizeAbsolutePath(path.resolve(file))));
    const aiFiles: string[] = [];
    const aiLineRanges = new Map<string, AiLineRange[]>();
    const commitCache = new Map<string, Promise<CommitFacts>>();

    for (const file of candidates) {
      const relativeFile = normalizeRelativePath(path.relative(cwd, path.resolve(file)));
      const ranges = await aiLineRangesForFile(
        runner,
        cwd,
        range,
        options.headRef?.trim() || "HEAD",
        relativeFile,
        options.aiDetection,
        commitCache
      );
      if (ranges.length > 0) {
        aiFiles.push(file);
        aiLineRanges.set(normalizeAbsolutePath(file), ranges);
      }
    }

    return {
      files: aiFiles,
      scannedMode: "ai-code-scan",
      aiLineRanges
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown git error";
    return {
      files,
      scannedMode: "full-scan",
      warning: `VibeGuard: ai-code-scan could not inspect git history (${detail}); falling back to full scan.`
    };
  }
}

/** Retains findings that overlap AI-attributed changed lines for an ai-code-scan file. */
export function filterFindingsToAiLineRanges(
  findings: Finding[],
  filePath: string,
  aiLineRanges: ReadonlyMap<string, AiLineRange[]> | undefined
): Finding[] {
  if (!aiLineRanges) {
    return findings;
  }
  const ranges = aiLineRanges.get(normalizeAbsolutePath(filePath));
  if (!ranges) {
    return findings;
  }
  return findings.filter((finding) => {
    const startLine = finding.line;
    const endLine = Math.max(startLine, finding.endLine ?? startLine);
    return ranges.some((range) => range.startLine <= endLine && range.endLine >= startLine);
  });
}

export function isAiCommit(commit: CommitFacts, mode: AiDetectionMode): boolean {
  const authorText = `${commit.authorName} ${commit.authorEmail}`;
  if (mode === "author") {
    return aiAuthorPattern.test(authorText);
  }
  if (mode === "message") {
    return matchesAiMessage(commit.message);
  }
  return aiAuthorPattern.test(authorText) || matchesAiMessage(commit.message);
}

function gitRange(baseRef?: string, headRef?: string): string {
  const base = baseRef?.trim();
  const head = headRef?.trim();
  if (base && head) {
    return `${base}...${head}`;
  }
  if (base) {
    return `${base}...HEAD`;
  }
  if (head) {
    return head;
  }
  return "HEAD~1...HEAD";
}

async function listChangedFiles(runner: GitRunner, cwd: string, range: string): Promise<string[]> {
  const output = await runner.run(["diff", "--name-only", "--diff-filter=ACMRTUXB", range], cwd);
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

async function aiLineRangesForFile(
  runner: GitRunner,
  cwd: string,
  range: string,
  headRef: string,
  relativeFile: string,
  mode: AiDetectionMode,
  commitCache: Map<string, Promise<CommitFacts>>
): Promise<AiLineRange[]> {
  const changedRanges = await addedLineRanges(runner, cwd, range, relativeFile);
  if (changedRanges.length === 0) {
    return [];
  }
  if (mode === "aggressive" && countLines(changedRanges) >= 50) {
    return changedRanges;
  }

  const lines = await blameChangedLines(runner, cwd, headRef, relativeFile, changedRanges);
  const aiLines: number[] = [];
  for (const line of lines) {
    if (await isAiBlameLine(line, mode, runner, cwd, commitCache)) {
      aiLines.push(line.line);
    }
  }
  return lineNumbersToRanges(aiLines);
}

async function addedLineRanges(runner: GitRunner, cwd: string, range: string, relativeFile: string): Promise<AiLineRange[]> {
  const output = await runner.run(["diff", "--unified=0", range, "--", relativeFile], cwd);
  const ranges: AiLineRange[] = [];
  for (const match of output.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const startLine = Number(match[1]);
    const lineCount = match[2] === undefined ? 1 : Number(match[2]);
    if (Number.isInteger(startLine) && Number.isInteger(lineCount) && startLine > 0 && lineCount > 0) {
      ranges.push({ startLine, endLine: startLine + lineCount - 1 });
    }
  }
  return mergeRanges(ranges);
}

async function blameChangedLines(
  runner: GitRunner,
  cwd: string,
  headRef: string,
  relativeFile: string,
  ranges: AiLineRange[]
): Promise<BlameLine[]> {
  const args = ["blame", "--line-porcelain"];
  for (const range of ranges) {
    args.push("-L", `${range.startLine},${range.endLine}`);
  }
  args.push(headRef, "--", relativeFile);
  return parseBlamePorcelain(await runner.run(args, cwd));
}

async function isAiBlameLine(
  line: BlameLine,
  mode: AiDetectionMode,
  runner: GitRunner,
  cwd: string,
  commitCache: Map<string, Promise<CommitFacts>>
): Promise<boolean> {
  if (mode === "author") {
    return isAiCommit(line, "author");
  }
  if (mode === "message") {
    return isAiCommit(await commitFactsForHash(runner, cwd, line.hash, commitCache), "message");
  }
  if (isAiCommit(line, "author")) {
    return true;
  }
  return isAiCommit(await commitFactsForHash(runner, cwd, line.hash, commitCache), "message");
}

function commitFactsForHash(
  runner: GitRunner,
  cwd: string,
  hash: string,
  cache: Map<string, Promise<CommitFacts>>
): Promise<CommitFacts> {
  const existing = cache.get(hash);
  if (existing) {
    return existing;
  }
  const request = runner.run(["show", "-s", "--format=%an%x00%ae%x00%B", hash], cwd).then(parseCommitFacts);
  cache.set(hash, request);
  return request;
}

function parseCommitFacts(output: string): CommitFacts {
  const [authorName = "", authorEmail = "", ...messageParts] = output.split("\x00");
  return {
    authorName: authorName.trim(),
    authorEmail: authorEmail.trim(),
    message: messageParts.join("\x00").trim()
  };
}

export function parseBlamePorcelain(output: string): BlameLine[] {
  const result: BlameLine[] = [];
  let hash: string | undefined;
  let line: number | undefined;
  let authorName = "";
  let authorEmail = "";
  for (const rawLine of output.split(/\r?\n/)) {
    const header = rawLine.match(/^(\^?[0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$/i);
    if (header) {
      hash = header[1].replace(/^\^/, "");
      line = Number(header[2]);
      authorName = "";
      authorEmail = "";
      continue;
    }
    if (rawLine.startsWith("author ")) {
      authorName = rawLine.slice("author ".length).trim();
      continue;
    }
    if (rawLine.startsWith("author-mail ")) {
      authorEmail = rawLine.slice("author-mail ".length).trim().replace(/^<|>$/g, "");
      continue;
    }
    if (rawLine.startsWith("\t") && hash && line !== undefined) {
      result.push({ hash, line, authorName, authorEmail, message: "" });
      hash = undefined;
      line = undefined;
    }
  }
  return result;
}

function countLines(ranges: AiLineRange[]): number {
  return ranges.reduce((total, range) => total + range.endLine - range.startLine + 1, 0);
}

function lineNumbersToRanges(lines: number[]): AiLineRange[] {
  const sorted = [...new Set(lines)].sort((left, right) => left - right);
  const ranges: AiLineRange[] = [];
  for (const line of sorted) {
    const previous = ranges[ranges.length - 1];
    if (previous && previous.endLine + 1 === line) {
      previous.endLine = line;
    } else {
      ranges.push({ startLine: line, endLine: line });
    }
  }
  return ranges;
}

function mergeRanges(ranges: AiLineRange[]): AiLineRange[] {
  const sorted = [...ranges].sort((left, right) => left.startLine - right.startLine || left.endLine - right.endLine);
  const merged: AiLineRange[] = [];
  for (const range of sorted) {
    const previous = merged[merged.length - 1];
    if (previous && range.startLine <= previous.endLine + 1) {
      previous.endLine = Math.max(previous.endLine, range.endLine);
    } else {
      merged.push({ ...range });
    }
  }
  return merged;
}

function matchesAiMessage(message: string): boolean {
  return aiMessagePatterns.some((pattern) => pattern.test(message));
}

function normalizeAbsolutePath(filePath: string): string {
  return path.resolve(filePath).replace(/\\/g, "/").toLowerCase();
}

function normalizeRelativePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}
