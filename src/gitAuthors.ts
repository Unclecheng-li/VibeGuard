import { execFile } from "child_process";
import path from "path";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface GitFileAuthor {
  name?: string;
  email?: string;
}

export interface GitAuthorRunner {
  run(args: string[], cwd: string): Promise<string>;
}

const defaultRunner: GitAuthorRunner = {
  async run(args: string[], cwd: string): Promise<string> {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 1024 * 1024
    });
    return stdout;
  }
};

export async function gitAuthorsForFiles(
  files: string[],
  cwd = process.cwd(),
  runner: GitAuthorRunner = defaultRunner
): Promise<Map<string, GitFileAuthor>> {
  const authors = new Map<string, GitFileAuthor>();
  const uniqueFiles = [...new Set(files.map((file) => normalizeAbsolutePath(file)))];
  for (const file of uniqueFiles) {
    const relativeFile = normalizeRelativePath(path.relative(cwd, file));
    try {
      const output = await runner.run(["log", "-1", "--format=%an%x00%ae", "--", relativeFile], cwd);
      const author = parseGitAuthor(output);
      if (author) {
        authors.set(file, author);
      }
    } catch {
      // Ignore per-file attribution failures; scans and findings storage should still succeed.
    }
  }
  return authors;
}

export function parseGitAuthor(output: string): GitFileAuthor | undefined {
  const [name = "", email = ""] = output.trim().split("\x00");
  const trimmedName = name.trim();
  const trimmedEmail = email.trim();
  if (!trimmedName && !trimmedEmail) {
    return undefined;
  }
  return {
    name: trimmedName || undefined,
    email: trimmedEmail || undefined
  };
}

export function normalizeAuthorFilePath(filePath: string): string {
  return normalizeAbsolutePath(filePath);
}

function normalizeAbsolutePath(filePath: string): string {
  return path.resolve(filePath).replace(/\\/g, "/").toLowerCase();
}

function normalizeRelativePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}
