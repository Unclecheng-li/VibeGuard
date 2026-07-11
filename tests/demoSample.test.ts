import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { scanSourceFile } from "../src/scanner";

test("demo sample continues to produce the findings shown in the CLI video", async () => {
  const filePath = path.resolve(process.cwd(), "demo", "unsafe-ai-sample.ts");
  const text = await fs.readFile(filePath, "utf8");
  const result = await scanSourceFile(
    { filePath, languageId: "typescript", text },
    { packageVerification: "seed", includeSast: true, now: 1 }
  );

  assert.deepEqual(
    result.findings.filter((finding) => !finding.dismissed).map((finding) => finding.detection_rule).sort(),
    ["hallucinated_package_npm", "hardcoded_secret_openai_key", "sast_xss_inner_html"]
  );
});
