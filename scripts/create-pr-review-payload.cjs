"use strict";

const fs = require("fs");
const path = require("path");

function buildPullRequestReviewPayload(report, changedFiles, commitId, limit, workspaceRoot = process.cwd(), existingReviewComments = []) {
  const changed = new Set(
    (Array.isArray(changedFiles) ? changedFiles : [])
      .map((file) => (file && typeof file.filename === "string" ? file.filename.replace(/\\/g, "/") : undefined))
      .filter(Boolean)
  );
  const comments = [];
  const seen = new Set();
  const existing = existingReviewCommentKeys(existingReviewComments);
  const maxComments = Math.max(1, Math.min(Number.isInteger(limit) ? limit : 20, 50));
  const findings = report && Array.isArray(report.findings) ? report.findings : [];

  for (const finding of findings) {
    if (!finding || finding.dismissed === true || typeof finding.file !== "string") {
      continue;
    }
    const file = toRepositoryPath(finding.file, workspaceRoot);
    const line = Number.isInteger(finding.endLine) && finding.endLine > 0 ? finding.endLine : finding.line;
    if (!file || !changed.has(file) || !Number.isInteger(line) || line < 1) {
      continue;
    }
    const rule = reviewRuleId(finding.detection_rule);
    const key = `${file}:${line}:${rule}`;
    if (seen.has(key) || existing.has(key)) {
      continue;
    }
    seen.add(key);
    comments.push({
      path: file,
      line,
      side: "RIGHT",
      body: commentBody(finding, rule)
    });
    if (comments.length >= maxComments) {
      break;
    }
  }

  return {
    commit_id: commitId,
    event: "COMMENT",
    body: "VibeGuard inline security findings",
    comments
  };
}

function toRepositoryPath(filePath, workspaceRoot) {
  const normalized = filePath.replace(/\\/g, "/");
  const relative = path.isAbsolute(filePath) ? path.relative(workspaceRoot, filePath).replace(/\\/g, "/") : normalized.replace(/^\.\//, "");
  if (!relative || relative === ".." || relative.startsWith("../") || path.posix.isAbsolute(relative)) {
    return undefined;
  }
  return relative;
}

function commentBody(finding, rule) {
  const severity = typeof finding.severity === "string" ? finding.severity.toUpperCase() : "SECURITY";
  const message = compactText(finding.message, 700) || "VibeGuard detected a security finding.";
  const suggestion = compactText(finding.suggestion, 500);
  return `<!-- vibeguard-inline:${rule} -->\n**VibeGuard ${severity}** \`${rule}\`\n\n${message}${suggestion ? `\n\nSuggested remediation: ${suggestion}` : ""}`;
}

function reviewRuleId(value) {
  const normalized = typeof value === "string" ? value.replace(/[^a-zA-Z0-9_.-]+/g, "_").slice(0, 120) : "";
  return normalized || "vibeguard_finding";
}

function existingReviewCommentKeys(comments) {
  const keys = new Set();
  for (const comment of Array.isArray(comments) ? comments : []) {
    if (!comment || typeof comment.path !== "string" || !Number.isInteger(comment.line) || typeof comment.body !== "string") {
      continue;
    }
    const rule = comment.body.match(/<!--\s*vibeguard-inline:([^\s>]+)\s*-->/)?.[1];
    if (rule) {
      keys.add(`${comment.path.replace(/\\/g, "/")}:${comment.line}:${rule}`);
    }
  }
  return keys;
}

function compactText(value, maxLength) {
  if (typeof value !== "string") {
    return undefined;
  }
  const compact = value.replace(/[\r\n]+/g, " ").trim();
  return compact ? compact.slice(0, maxLength) : undefined;
}

function run() {
  const [reportPath, changedFilesPath, existingCommentsPath, commitId, limitValue, outputPath] = process.argv.slice(2);
  if (!reportPath || !changedFilesPath || !existingCommentsPath || !commitId || !outputPath) {
    throw new Error("Usage: create-pr-review-payload <report.json> <changed-files.json> <existing-comments.json> <commit-sha> <limit> <output.json>");
  }
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const changedFiles = JSON.parse(fs.readFileSync(changedFilesPath, "utf8"));
  const existingComments = JSON.parse(fs.readFileSync(existingCommentsPath, "utf8"));
  const limit = Number(limitValue);
  const payload = buildPullRequestReviewPayload(report, changedFiles, commitId, limit, process.cwd(), existingComments);
  fs.writeFileSync(outputPath, JSON.stringify(payload));
  process.stdout.write(String(payload.comments.length));
}

if (require.main === module) {
  try {
    run();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}

module.exports = { buildPullRequestReviewPayload, toRepositoryPath };
