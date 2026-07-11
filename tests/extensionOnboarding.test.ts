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
  assert.match(source, /workbench\.action\.openSettings/);
});

test("VSCode routes L3 fixes through a confirmation command", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /finding\.detection_layer === "L3"/);
  assert.match(source, /VibeGuard received this replacement from an LLM/);
  assert.match(source, /command: "vibeguard\.applyFix"/);
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
