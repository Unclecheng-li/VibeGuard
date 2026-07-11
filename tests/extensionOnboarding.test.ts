import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode extension exposes first-run cold-start onboarding", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /firstRunOnboardingKey/);
  assert.match(source, /maybeShowFirstRunOnboarding/);
  assert.match(source, /globalState\.update\(firstRunOnboardingKey, true\)/);
  assert.match(source, /Package-name cache sync runs in the background/);
  assert.match(source, /Sync Now/);
  assert.match(source, /VibeGuard: package sync \$\{percent\}%/);
  assert.match(source, /packageSyncProgress/);
  assert.match(source, /packageSyncTier/);
  assert.match(source, /Tier 2 full index/);
  assert.match(source, /syncConfiguredPackageIndexesInBackground/);
  assert.match(source, /workbench\.action\.openSettings/);
});

test("VSCode routes L3 fixes through a confirmation command", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /finding\.detection_layer === "L3"/);
  assert.match(source, /VibeGuard received this replacement from an LLM/);
  assert.match(source, /command: "vibeguard\.applyFix"/);
});

test("VSCode offers all verified package replacement candidates as quick fixes", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /allEditorFixesForFinding/);
  assert.match(source, /finding\.alternativeFixes/);
  assert.match(source, /workspaceEditForEdits\(document\.uri, fix\.edits\)/);
  assert.match(source, /index === 0 && finding\.detection_layer !== "L3"/);
});

test("VSCode critical package alerts let users choose a verified replacement", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /critical\.type === "hallucinated_package"/);
  assert.match(source, /Choose replacement/);
  assert.match(source, /pickPackageReplacement\(critical\)/);
  assert.match(source, /Choose VibeGuard package replacement/);
  assert.match(source, /applyFindingCodeFix\(finding, selected\.fix\)/);
});

test("VSCode findings sidebar exposes safe fixes without bypassing package or L3 review", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /registerCommand\("vibeguard\.applyFindingFix"/);
  assert.match(source, /applyFindingFixFromSidebar/);
  assert.match(source, /finding\.type === "hallucinated_package"/);
  assert.match(source, /await pickPackageReplacement\(finding\)/);
  assert.match(source, /vibeguardFindingFixable/);
});

test("VSCode rechecks finding evidence before a single fix edits a document", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /findingFixStillMatchesDocument\(document, finding, fix\)/);
  assert.match(source, /document\.getText\(findingRange\(finding\)\) === finding\.evidence/);
  assert.match(source, /redactedSecretFixStillMatchesSource\(finding, fix, document\.getText\(\)\)/);
  assert.match(source, /code changed after it was scanned/);
  assert.match(source, /finding\.fix === fix && l3FixStillMatchesDocument/);
});

test("VSCode reviews current L3 edits before applying a Pro file batch", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /registerCommand\("vibeguard\.applyAllProFixes"/);
  assert.match(source, /configuredLlmProvider\(loadedConfig\.config\) !== "vibeguard"/);
  assert.match(source, /pickReviewedL3Fixes/);
  assert.match(source, /Review VibeGuard Pro LLM Fixes/);
  assert.match(source, /l3FixStillMatchesDocument/);
  assert.match(source, /Apply reviewed fixes/);
});

test("VSCode keeps Pro credentials on the configured service origin", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /showSubscriptionStatus/);
  assert.match(source, /provider === "vibeguard" \? undefined : configuredOptionalString\("llmBaseUrl"\)/);
});

test("VSCode scans deployment files that can run pip install", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /"shellscript"/);
  assert.match(source, /"powershell"/);
  assert.match(source, /"yaml"/);
  assert.match(source, /"dockerfile"/);
  assert.match(source, /\*\*\/\{Dockerfile,dockerfile\}/);
});

test("VSCode defers remote package verification outside the realtime L1 path", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /realtimeRemoteVerificationDelayMs = 600/);
  assert.match(source, /remotePackageTimers/);
  assert.match(source, /deferRemotePackageVerification/);
  assert.match(source, /scheduleRemotePackageVerification\(document\)/);
  assert.match(source, /includeL2: true,[\s\S]{0,160}scheduleRemotePackageVerification: true/);
  assert.match(source, /includeL3: true,[\s\S]{0,160}scheduleRemotePackageVerification: true/);
  assert.match(source, /packageVerification: "remote"/);
  assert.match(source, /document\.version !== documentVersion/);
});

test("critical VSCode alerts provide local finding details before the user dismisses them", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /"Learn More"/);
  assert.match(source, /showFindingDetails\(critical\)/);
  assert.match(source, /Finding Details/);
  assert.match(source, /Rule: \$\{finding\.detection_rule\}/);
  assert.match(source, /Evidence: \$\{finding\.evidence\}/);
  assert.match(source, /Available fix: \$\{finding\.fix\.description\}/);
});
