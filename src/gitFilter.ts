import { execFile } from "child_process";
import path from "path";
import { promisify } from "util";

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
  warning?: string;
}

interface CommitFacts {
  authorName: string;
  authorEmail: string;
  message: string;
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

    for (const file of candidates) {
      const relativeFile = normalizeRelativePath(path.relative(cwd, path.resolve(file)));
      if (await isAiTouchedFile(runner, cwd, range, relativeFile, options.aiDetection)) {
        aiFiles.push(file);
      }
    }

    return {
      files: aiFiles,
      scannedMode: "ai-code-scan"
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

async function isAiTouchedFile(
  runner: GitRunner,
  cwd: string,
  range: string,
  relativeFile: string,
  mode: AiDetectionMode
): Promise<boolean> {
  const commits = await commitsForFile(runner, cwd, range, relativeFile);
  if (commits.some((commit) => isAiCommit(commit, mode))) {
    return true;
  }
  if (mode !== "aggressive") {
    return false;
  }
  return (await addedLineCount(runner, cwd, range, relativeFile)) >= 50;
}

async function commitsForFile(runner: GitRunner, cwd: string, range: string, relativeFile: string): Promise<CommitFacts[]> {
  const output = await runner.run(["log", "--format=%an%x00%ae%x00%B%x1e", range, "--", relativeFile], cwd);
  return output
    .split("\x1e")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [authorName = "", authorEmail = "", ...messageParts] = entry.split("\x00");
      return {
        authorName,
        authorEmail,
        message: messageParts.join("\x00").trim()
      };
    });
}

async function addedLineCount(runner: GitRunner, cwd: string, range: string, relativeFile: string): Promise<number> {
  const output = await runner.run(["diff", "--numstat", range, "--", relativeFile], cwd);
  return output
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/)[0] ?? "0")
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value))
    .reduce((sum, value) => sum + value, 0);
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
