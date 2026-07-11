import { randomBytes } from "crypto";
import { spawn } from "child_process";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { PinProtectedLlmCredentialStore } from "./encryptedCredentials";

export type LlmCredentialProvider = "deepseek" | "claude" | "openai" | "local" | "vibeguard";

const supportedProviders = new Set<LlmCredentialProvider>(["deepseek", "claude", "openai", "local", "vibeguard"]);
const keychainService = "VibeGuard";
const windowsCredentialFileVersion = 1;
export const llmCredentialPinEnvironment = "VIBEGUARD_LLM_CREDENTIAL_PIN";

export interface CredentialCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface CredentialCommandRunner {
  run(command: string, args: string[], input?: string): Promise<CredentialCommandResult>;
}

export interface NativeLlmCredentialStoreOptions {
  platform?: NodeJS.Platform;
  credentialFilePath?: string;
  runner?: CredentialCommandRunner;
}

export interface StoredLlmCredentialOptions {
  pin?: string;
  nativeStore?: NativeLlmCredentialStore;
  encryptedStore?: PinProtectedLlmCredentialStore;
}

export type StoredLlmCredentialSource = "native" | "encrypted";

export interface StoredLlmCredential {
  apiKey: string;
  source: StoredLlmCredentialSource;
}

interface WindowsCredentialFile {
  version: number;
  credentials: Partial<Record<LlmCredentialProvider, string>>;
}

export class CredentialCommandError extends Error {
  constructor(
    readonly command: string,
    readonly exitCode: number | undefined,
    stderr?: string
  ) {
    super(`${command} failed${exitCode === undefined ? "" : ` with exit code ${exitCode}`}${stderr ? "." : ""}`);
    this.name = "CredentialCommandError";
  }
}

/**
 * Stores LLM credentials outside config.json. Windows binds ciphertext to the current OS user;
 * macOS and Linux delegate to their native secret stores.
 */
export class NativeLlmCredentialStore {
  private readonly platform: NodeJS.Platform;
  private readonly credentialFilePath: string;
  private readonly runner: CredentialCommandRunner;

  constructor(options: NativeLlmCredentialStoreOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.credentialFilePath = options.credentialFilePath ?? defaultWindowsCredentialFilePath();
    this.runner = options.runner ?? defaultCredentialCommandRunner;
  }

  async get(provider: LlmCredentialProvider): Promise<string | undefined> {
    validateProvider(provider);
    if (provider === "local") {
      return undefined;
    }
    if (this.platform === "win32") {
      return this.getWindowsCredential(provider);
    }
    if (this.platform === "darwin") {
      return this.getMacCredential(provider);
    }
    if (this.platform === "linux") {
      return this.getLinuxCredential(provider);
    }
    return undefined;
  }

  async set(provider: LlmCredentialProvider, apiKey: string): Promise<void> {
    validateProvider(provider);
    const secret = normalizeApiKey(apiKey);
    if (provider === "local") {
      throw new Error("Local Ollama does not require an API key.");
    }
    if (this.platform === "win32") {
      const credentials = await this.readWindowsCredentials();
      credentials.credentials[provider] = await this.protectWindowsCredential(secret);
      await this.writeWindowsCredentials(credentials);
      return;
    }
    if (this.platform === "darwin") {
      // The macOS security tool writes this value directly to the Keychain, never to config.json.
      await this.runner.run("security", ["add-generic-password", "-U", "-s", keychainService, "-a", credentialAccount(provider), "-w", secret]);
      return;
    }
    if (this.platform === "linux") {
      await this.runner.run(
        "secret-tool",
        ["store", "--label=VibeGuard LLM API key", "service", keychainService, "account", credentialAccount(provider)],
        secret
      );
      return;
    }
    throw new Error(`Native credential storage is not supported on ${this.platform}.`);
  }

  async delete(provider: LlmCredentialProvider): Promise<boolean> {
    validateProvider(provider);
    if (provider === "local") {
      return false;
    }
    if (this.platform === "win32") {
      const credentials = await this.readWindowsCredentials();
      if (!credentials.credentials[provider]) {
        return false;
      }
      delete credentials.credentials[provider];
      await this.writeWindowsCredentials(credentials);
      return true;
    }
    if (this.platform === "darwin") {
      try {
        await this.runner.run("security", ["delete-generic-password", "-s", keychainService, "-a", credentialAccount(provider)]);
        return true;
      } catch (error) {
        if (isMissingCredentialError(error)) {
          return false;
        }
        throw error;
      }
    }
    if (this.platform === "linux") {
      try {
        await this.runner.run("secret-tool", ["clear", "service", keychainService, "account", credentialAccount(provider)]);
        return true;
      } catch (error) {
        if (isMissingCredentialError(error)) {
          return false;
        }
        throw error;
      }
    }
    return false;
  }

  private async getWindowsCredential(provider: LlmCredentialProvider): Promise<string | undefined> {
    const credentials = await this.readWindowsCredentials();
    const ciphertext = credentials.credentials[provider];
    return ciphertext ? this.unprotectWindowsCredential(ciphertext) : undefined;
  }

  private async getMacCredential(provider: LlmCredentialProvider): Promise<string | undefined> {
    try {
      const result = await this.runner.run("security", ["find-generic-password", "-s", keychainService, "-a", credentialAccount(provider), "-w"]);
      return normalizeStoredApiKey(result.stdout);
    } catch (error) {
      if (isMissingCredentialError(error)) {
        return undefined;
      }
      throw error;
    }
  }

  private async getLinuxCredential(provider: LlmCredentialProvider): Promise<string | undefined> {
    try {
      const result = await this.runner.run("secret-tool", ["lookup", "service", keychainService, "account", credentialAccount(provider)]);
      return normalizeStoredApiKey(result.stdout);
    } catch (error) {
      if (isMissingCredentialError(error)) {
        return undefined;
      }
      throw error;
    }
  }

  private async protectWindowsCredential(secret: string): Promise<string> {
    const result = await this.runner.run("powershell.exe", powerShellArgs(windowsProtectScript), secret);
    const encoded = result.stdout.trim();
    if (!isBase64(encoded)) {
      throw new Error("Windows credential protection returned invalid data.");
    }
    return encoded;
  }

  private async unprotectWindowsCredential(ciphertext: string): Promise<string | undefined> {
    if (!isBase64(ciphertext)) {
      throw new Error("Stored Windows credential is invalid.");
    }
    const result = await this.runner.run("powershell.exe", powerShellArgs(windowsUnprotectScript), ciphertext);
    return normalizeStoredApiKey(result.stdout);
  }

  private async readWindowsCredentials(): Promise<WindowsCredentialFile> {
    try {
      const raw = await fs.readFile(this.credentialFilePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<WindowsCredentialFile>;
      if (parsed.version !== windowsCredentialFileVersion || !parsed.credentials || typeof parsed.credentials !== "object" || Array.isArray(parsed.credentials)) {
        throw new Error("Stored Windows credential metadata is invalid.");
      }
      const credentials: WindowsCredentialFile["credentials"] = {};
      for (const provider of supportedProviders) {
        const value = parsed.credentials[provider];
        if (value !== undefined) {
          if (typeof value !== "string" || !isBase64(value)) {
            throw new Error("Stored Windows credential metadata is invalid.");
          }
          credentials[provider] = value;
        }
      }
      return { version: windowsCredentialFileVersion, credentials };
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return { version: windowsCredentialFileVersion, credentials: {} };
      }
      throw error;
    }
  }

  private async writeWindowsCredentials(credentials: WindowsCredentialFile): Promise<void> {
    const entries = Object.entries(credentials.credentials);
    if (entries.length === 0) {
      try {
        await fs.unlink(this.credentialFilePath);
      } catch (error) {
        if (!isNodeError(error) || error.code !== "ENOENT") {
          throw error;
        }
      }
      return;
    }

    await fs.mkdir(path.dirname(this.credentialFilePath), { recursive: true });
    const temporaryPath = `${this.credentialFilePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      await fs.writeFile(temporaryPath, `${JSON.stringify(credentials)}\n`, { encoding: "utf8", mode: 0o600 });
      await fs.rename(temporaryPath, this.credentialFilePath);
    } finally {
      try {
        await fs.unlink(temporaryPath);
      } catch (error) {
        if (!isNodeError(error) || error.code !== "ENOENT") {
          throw error;
        }
      }
    }
  }
}

/** Reads a native credential without allowing a missing platform dependency to disable L3 fallback behavior. */
export async function readNativeLlmCredential(
  provider: LlmCredentialProvider,
  store = new NativeLlmCredentialStore()
): Promise<string | undefined> {
  try {
    return await store.get(provider);
  } catch {
    return undefined;
  }
}

/** Resolves native storage first, then the PIN-protected fallback when configured. */
export async function readStoredLlmCredential(
  provider: LlmCredentialProvider,
  options: StoredLlmCredentialOptions = {}
): Promise<StoredLlmCredential | undefined> {
  const nativeStore = options.nativeStore ?? new NativeLlmCredentialStore();
  try {
    const apiKey = await nativeStore.get(provider);
    if (apiKey) {
      return { apiKey, source: "native" };
    }
  } catch {
    // A missing or unavailable native service must not prevent an explicitly configured encrypted fallback.
  }

  const pin = options.pin ?? process.env[llmCredentialPinEnvironment];
  if (!pin) {
    return undefined;
  }
  try {
    const apiKey = await (options.encryptedStore ?? new PinProtectedLlmCredentialStore()).get(provider, pin);
    return apiKey ? { apiKey, source: "encrypted" } : undefined;
  } catch {
    return undefined;
  }
}

/** Persists a credential in native storage, with an encrypted PIN fallback only when native storage is unavailable. */
export async function storeLlmCredential(
  provider: LlmCredentialProvider,
  apiKey: string,
  options: StoredLlmCredentialOptions = {}
): Promise<StoredLlmCredentialSource> {
  const nativeStore = options.nativeStore ?? new NativeLlmCredentialStore();
  try {
    await nativeStore.set(provider, apiKey);
    return "native";
  } catch (error) {
    if (!isNativeCredentialServiceUnavailable(error)) {
      throw error;
    }
  }

  const pin = options.pin ?? process.env[llmCredentialPinEnvironment];
  if (!pin) {
    throw new Error(
      `Native credential storage is unavailable. Set ${llmCredentialPinEnvironment} or pass --pin-env before saving an encrypted fallback credential.`
    );
  }
  await (options.encryptedStore ?? new PinProtectedLlmCredentialStore()).set(provider, apiKey, pin);
  return "encrypted";
}

/** Removes any native and encrypted-fallback credentials without requiring the fallback PIN. */
export async function deleteStoredLlmCredential(
  provider: LlmCredentialProvider,
  options: StoredLlmCredentialOptions = {}
): Promise<{ nativeDeleted: boolean; encryptedDeleted: boolean }> {
  const nativeStore = options.nativeStore ?? new NativeLlmCredentialStore();
  let nativeDeleted = false;
  try {
    nativeDeleted = await nativeStore.delete(provider);
  } catch (error) {
    if (!isNativeCredentialServiceUnavailable(error)) {
      throw error;
    }
  }
  const encryptedDeleted = await (options.encryptedStore ?? new PinProtectedLlmCredentialStore()).delete(provider);
  return { nativeDeleted, encryptedDeleted };
}

/** Detects a fallback credential's presence without attempting to decrypt it. */
export async function hasEncryptedLlmCredential(
  provider: LlmCredentialProvider,
  encryptedStore = new PinProtectedLlmCredentialStore()
): Promise<boolean> {
  try {
    return await encryptedStore.has(provider);
  } catch {
    return false;
  }
}

export function defaultWindowsCredentialFilePath(): string {
  return path.join(os.homedir(), ".vibeguard", "llm-credentials.dpapi.json");
}

function credentialAccount(provider: LlmCredentialProvider): string {
  return `llm_api_key.${provider}`;
}

function validateProvider(provider: LlmCredentialProvider): void {
  if (!supportedProviders.has(provider)) {
    throw new Error("Unsupported LLM credential provider.");
  }
}

function normalizeApiKey(value: string): string {
  const key = value.trim();
  if (!key) {
    throw new Error("LLM API key must not be empty.");
  }
  if (key.length > 16 * 1024) {
    throw new Error("LLM API key must not exceed 16 KiB.");
  }
  return key;
}

function normalizeStoredApiKey(value: string): string | undefined {
  const key = value.trim();
  return key ? key : undefined;
}

function isBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function isMissingCredentialError(error: unknown): boolean {
  return error instanceof CredentialCommandError && (error.exitCode === 1 || error.exitCode === 44);
}

function isNativeCredentialServiceUnavailable(error: unknown): boolean {
  return (
    error instanceof CredentialCommandError ||
    (error instanceof Error && error.message.startsWith("Native credential storage is not supported"))
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function powerShellArgs(script: string): string[] {
  return ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script];
}

const windowsProtectScript = [
  "$ErrorActionPreference = 'Stop'",
  "Add-Type -AssemblyName System.Security",
  "$plain = [Console]::In.ReadToEnd()",
  "$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)",
  "$entropy = [System.Text.Encoding]::UTF8.GetBytes('VibeGuard:llm-api-key:v1')",
  "$cipher = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "[Console]::Out.Write([Convert]::ToBase64String($cipher))"
].join("; ");

const windowsUnprotectScript = [
  "$ErrorActionPreference = 'Stop'",
  "Add-Type -AssemblyName System.Security",
  "$encoded = [Console]::In.ReadToEnd()",
  "$cipher = [Convert]::FromBase64String($encoded)",
  "$entropy = [System.Text.Encoding]::UTF8.GetBytes('VibeGuard:llm-api-key:v1')",
  "$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($cipher, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
  "[Console]::Out.Write([System.Text.Encoding]::UTF8.GetString($plain))"
].join("; ");

const defaultCredentialCommandRunner: CredentialCommandRunner = {
  run(command: string, args: string[], input?: string): Promise<CredentialCommandResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(Buffer.from(chunk)));
      child.once("error", () => reject(new CredentialCommandError(command, undefined)));
      child.once("close", (exitCode) => {
        const output = Buffer.concat(stdout).toString("utf8");
        const errors = Buffer.concat(stderr).toString("utf8");
        if (exitCode !== 0) {
          reject(new CredentialCommandError(command, exitCode ?? undefined, errors));
          return;
        }
        resolve({ stdout: output, stderr: errors, exitCode: 0 });
      });
      child.stdin.end(input ?? "");
    });
  }
};
