import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  CredentialCommandError,
  deleteStoredLlmCredential,
  NativeLlmCredentialStore,
  readStoredLlmCredential,
  readNativeLlmCredential,
  storeLlmCredential,
  type CredentialCommandRunner
} from "../src/l3/credentials";
import { PinProtectedLlmCredentialStore } from "../src/l3/encryptedCredentials";

test("stores Windows LLM credentials as DPAPI ciphertext rather than plaintext", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-llm-credentials-"));
  const credentialPath = path.join(directory, "llm-credentials.dpapi.json");
  const calls: Array<{ command: string; args: string[]; input?: string }> = [];
  const runner: CredentialCommandRunner = {
    async run(command, args, input) {
      calls.push({ command, args, input });
      const script = args.at(-1) ?? "";
      if (script.includes("Protect(")) {
        return { stdout: Buffer.from(input ?? "", "utf8").toString("base64"), stderr: "", exitCode: 0 };
      }
      if (script.includes("Unprotect(")) {
        return { stdout: Buffer.from(input ?? "", "base64").toString("utf8"), stderr: "", exitCode: 0 };
      }
      throw new Error("Unexpected credential command.");
    }
  };
  const store = new NativeLlmCredentialStore({ platform: "win32", credentialFilePath: credentialPath, runner });

  await store.set("openai", "openai-secret-value");
  const raw = await fs.readFile(credentialPath, "utf8");

  assert.equal(raw.includes("openai-secret-value"), false);
  assert.equal(JSON.parse(raw).credentials.openai, Buffer.from("openai-secret-value").toString("base64"));
  assert.equal(calls[0].command, "powershell.exe");
  assert.equal(calls[0].input, "openai-secret-value");
  assert.equal(calls[0].args.some((arg) => arg.includes("openai-secret-value")), false);
  await store.set("openai", "rotated-openai-secret");
  const rotatedRaw = await fs.readFile(credentialPath, "utf8");
  assert.equal(rotatedRaw.includes("openai-secret-value"), false);
  assert.equal(rotatedRaw.includes("rotated-openai-secret"), false);
  assert.equal(await store.get("openai"), "rotated-openai-secret");
  assert.equal(await store.get("deepseek"), undefined);
  assert.equal(await store.delete("openai"), true);
  assert.equal(await store.delete("openai"), false);
  await assert.rejects(fs.access(credentialPath), /ENOENT/);
});

test("uses macOS Keychain and Linux Secret Service command protocols", async () => {
  const macCalls: Array<{ command: string; args: string[]; input?: string }> = [];
  const macRunner: CredentialCommandRunner = {
    async run(command, args, input) {
      macCalls.push({ command, args, input });
      if (args[0] === "find-generic-password") {
        return { stdout: "claude-key\n", stderr: "", exitCode: 0 };
      }
      return { stdout: "", stderr: "", exitCode: 0 };
    }
  };
  const macStore = new NativeLlmCredentialStore({ platform: "darwin", runner: macRunner });
  await macStore.set("claude", "claude-key");
  assert.equal(await macStore.get("claude"), "claude-key");
  assert.equal(await macStore.delete("claude"), true);
  assert.deepEqual(macCalls.map((call) => [call.command, call.args[0]]), [
    ["security", "add-generic-password"],
    ["security", "find-generic-password"],
    ["security", "delete-generic-password"]
  ]);
  assert.equal(macCalls[0].args.includes("VibeGuard"), true);
  assert.equal(macCalls[0].args.includes("llm_api_key.claude"), true);

  const linuxCalls: Array<{ command: string; args: string[]; input?: string }> = [];
  const linuxRunner: CredentialCommandRunner = {
    async run(command, args, input) {
      linuxCalls.push({ command, args, input });
      if (args[0] === "lookup") {
        return { stdout: "deepseek-key\n", stderr: "", exitCode: 0 };
      }
      return { stdout: "", stderr: "", exitCode: 0 };
    }
  };
  const linuxStore = new NativeLlmCredentialStore({ platform: "linux", runner: linuxRunner });
  await linuxStore.set("deepseek", "deepseek-key");
  assert.equal(await linuxStore.get("deepseek"), "deepseek-key");
  assert.equal(await linuxStore.delete("deepseek"), true);
  assert.deepEqual(linuxCalls.map((call) => [call.command, call.args[0]]), [
    ["secret-tool", "store"],
    ["secret-tool", "lookup"],
    ["secret-tool", "clear"]
  ]);
  assert.equal(linuxCalls[0].input, "deepseek-key");
  assert.equal(linuxCalls[0].args.includes("deepseek-key"), false);
});

test("treats missing native credential backends as optional for L3 fallback", async () => {
  const unavailableRunner: CredentialCommandRunner = {
    async run() {
      throw new CredentialCommandError("secret-tool", undefined);
    }
  };
  const store = new NativeLlmCredentialStore({ platform: "linux", runner: unavailableRunner });

  await assert.rejects(store.get("openai"), /secret-tool failed/);
  assert.equal(await readNativeLlmCredential("openai", store), undefined);
});

test("rejects empty, oversized, and local LLM credentials", async () => {
  const store = new NativeLlmCredentialStore({
    platform: "linux",
    runner: {
      async run() {
        return { stdout: "", stderr: "", exitCode: 0 };
      }
    }
  });

  await assert.rejects(store.set("openai", "  "), /must not be empty/);
  await assert.rejects(store.set("openai", "a".repeat(16 * 1024 + 1)), /must not exceed/);
  await assert.rejects(store.set("local", "anything"), /does not require/);
  assert.equal(await store.get("local"), undefined);
  assert.equal(await store.delete("local"), false);
});

test("falls back to AES-256-GCM credentials when a native store is unavailable", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-encrypted-credentials-"));
  const credentialPath = path.join(directory, "llm-credentials.aes.json");
  const fallback = new PinProtectedLlmCredentialStore({
    credentialFilePath: credentialPath,
    machineIdentifier: async () => "machine-one"
  });
  const unavailableNative = new NativeLlmCredentialStore({
    platform: "linux",
    runner: {
      async run() {
        throw new CredentialCommandError("secret-tool", 1);
      }
    }
  });
  const pin = "long-enough-test-pin";

  const source = await storeLlmCredential("openai", "openai-fallback-secret", {
    pin,
    nativeStore: unavailableNative,
    encryptedStore: fallback
  });
  const raw = await fs.readFile(credentialPath, "utf8");

  assert.equal(source, "encrypted");
  assert.equal(raw.includes("openai-fallback-secret"), false);
  assert.equal(raw.includes(pin), false);
  assert.equal(raw.includes("machine-one"), false);
  assert.equal((await readStoredLlmCredential("openai", { pin, nativeStore: unavailableNative, encryptedStore: fallback }))?.apiKey, "openai-fallback-secret");
  assert.equal((await readStoredLlmCredential("openai", { pin: "incorrect-pin", nativeStore: unavailableNative, encryptedStore: fallback })), undefined);
  await assert.rejects(fallback.get("openai", "incorrect-pin"), /could not be decrypted/);

  const otherMachine = new PinProtectedLlmCredentialStore({
    credentialFilePath: credentialPath,
    machineIdentifier: async () => "machine-two"
  });
  await assert.rejects(otherMachine.get("openai", pin), /could not be decrypted/);

  const deletion = await deleteStoredLlmCredential("openai", { nativeStore: unavailableNative, encryptedStore: fallback });
  assert.deepEqual(deletion, { nativeDeleted: false, encryptedDeleted: true });
  await assert.rejects(fs.access(credentialPath), /ENOENT/);
});

test("CLI refuses a plaintext LLM key argument without echoing it", () => {
  const accidentalKey = "accidental-plaintext-key";
  const result = spawnSync(process.execPath, [path.resolve(process.cwd(), "out", "src", "cli.js"), "llm-key", "set", accidentalKey], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /plaintext key arguments are not supported/);
  assert.equal(result.stderr.includes(accidentalKey), false);
  assert.equal(result.stdout.includes(accidentalKey), false);
});
