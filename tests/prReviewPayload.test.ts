import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

const { buildPullRequestReviewPayload } = require(path.resolve(process.cwd(), "scripts", "create-pr-review-payload.cjs")) as {
  buildPullRequestReviewPayload: (
    report: unknown,
    changedFiles: unknown,
    commitId: string,
    limit: number,
    workspaceRoot: string,
    existingReviewComments?: unknown
  ) => {
    commit_id: string;
    event: string;
    comments: Array<{ path: string; line: number; side: string; body: string }>;
  };
};

test("builds bounded, de-duplicated PR review comments without source evidence", () => {
  const workspace = path.join(path.sep, "workspace");
  const report = {
    findings: [
      {
        file: path.join(workspace, "src", "app.ts"),
        line: 8,
        endLine: 9,
        severity: "high",
        detection_rule: "sql_injection",
        message: "Query interpolation accepts request input.",
        suggestion: "Use bound parameters.",
        evidence: "SELECT * FROM users WHERE id = ${req.query.id}",
        dismissed: false
      },
      {
        file: path.join(workspace, "src", "app.ts"),
        line: 8,
        endLine: 9,
        severity: "high",
        detection_rule: "sql_injection",
        message: "Duplicate finding.",
        evidence: "different source evidence",
        dismissed: false
      },
      {
        file: "src/ignored.ts",
        line: 4,
        severity: "critical",
        detection_rule: "hardcoded_secret",
        message: "Ignored finding.",
        dismissed: true
      },
      {
        file: "../outside.ts",
        line: 4,
        severity: "critical",
        detection_rule: "path_traversal",
        message: "Outside workspace.",
        dismissed: false
      },
      {
        file: "src/other.ts",
        line: 2,
        severity: "medium",
        detection_rule: "xss",
        message: "Unsafe HTML output.",
        dismissed: false
      }
    ]
  };

  const payload = buildPullRequestReviewPayload(
    report,
    [{ filename: "src/app.ts" }, { filename: "src/other.ts" }],
    "commit-sha",
    20,
    workspace
  );

  assert.equal(payload.commit_id, "commit-sha");
  assert.equal(payload.event, "COMMENT");
  assert.deepEqual(payload.comments.map((comment) => [comment.path, comment.line, comment.side]), [
    ["src/app.ts", 9, "RIGHT"],
    ["src/other.ts", 2, "RIGHT"]
  ]);
  assert.match(payload.comments[0].body, /Suggested remediation: Use bound parameters/);
  assert.doesNotMatch(payload.comments[0].body, /SELECT \* FROM users/);
  assert.doesNotMatch(JSON.stringify(payload), /ignored\.ts|outside\.ts/);
});

test("caps PR review comments to the configured upper bound", () => {
  const payload = buildPullRequestReviewPayload(
    {
      findings: Array.from({ length: 60 }, (_, index) => ({
        file: "src/app.ts",
        line: index + 1,
        severity: "low",
        detection_rule: `rule_${index}`,
        message: "Finding"
      }))
    },
    [{ filename: "src/app.ts" }],
    "commit-sha",
    100,
    path.join(path.sep, "workspace")
  );

  assert.equal(payload.comments.length, 50);
});

test("does not recreate an existing VibeGuard inline comment", () => {
  const workspace = path.join(path.sep, "workspace");
  const payload = buildPullRequestReviewPayload(
    {
      findings: [
        {
          file: "src/app.ts",
          line: 5,
          severity: "high",
          detection_rule: "sql_injection",
          message: "Query interpolation accepts request input."
        }
      ]
    },
    [{ filename: "src/app.ts" }],
    "commit-sha",
    20,
    workspace,
    [{ path: "src/app.ts", line: 5, body: "<!-- vibeguard-inline:sql_injection -->\nExisting comment" }]
  );

  assert.deepEqual(payload.comments, []);
});
