import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { gitAuthorsForFiles, normalizeAuthorFilePath, parseGitAuthor, type GitAuthorRunner } from "../src/gitAuthors";

test("parses git author output", () => {
  assert.deepEqual(parseGitAuthor("Ada Lovelace\u0000ada@example.com\n"), {
    name: "Ada Lovelace",
    email: "ada@example.com"
  });
  assert.equal(parseGitAuthor("\n"), undefined);
});

test("loads git authors for files with a runner", async () => {
  const cwd = path.join(process.cwd(), "VibeGuardWorkspace");
  const file = path.join(cwd, "src", "demo.ts");
  const calls: string[][] = [];
  const runner: GitAuthorRunner = {
    async run(args: string[]): Promise<string> {
      calls.push(args);
      return "Grace Hopper\u0000grace@example.com\n";
    }
  };

  const authors = await gitAuthorsForFiles([file, file], cwd, runner);

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ["log", "-1", "--format=%an%x00%ae", "--", "src/demo.ts"]);
  assert.deepEqual(authors.get(normalizeAuthorFilePath(file)), {
    name: "Grace Hopper",
    email: "grace@example.com"
  });
});
