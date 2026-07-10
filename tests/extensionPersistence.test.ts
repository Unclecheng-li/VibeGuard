import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode findings persistence includes git author attribution", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /gitAuthorsForFiles/);
  assert.match(source, /resolveDocumentFindingAuthors/);
  assert.match(source, /findingAuthors/);
  assert.match(source, /recordScanRun\(\{/);
});
