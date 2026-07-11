import { execFile } from "child_process";
import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from "crypto";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { promisify } from "util";
import type { LlmCredentialProvider } from "./credentials";

const execFileAsync = promisify(execFile);
const encryptedCredentialFileVersion = 1;
const keyLength = 32;
const ivLength = 12;
const encryptionAlgorithm = "aes-256-gcm";
const encryptionContext = "VibeGuard LLM credential fallback v1";
const supportedProviders = new Set<LlmCredentialProvider>(["deepseek", "claude", "openai", "local", "vibeguard"]);

interface EncryptedCredential {
  iv: string;
  tag: string;
  ciphertext: string;
}

interface EncryptedCredentialFile {
  version: number;
  kdf: {
    algorithm: "scrypt";
    salt: string;
  };
  credentials: Partial<Record<LlmCredentialProvider, EncryptedCredential>>;
}

export interface PinProtectedLlmCredentialStoreOptions {
  credentialFilePath?: string;
  machineIdentifier?: () => Promise<string>;
}

/**
 * Last-resort encrypted storage for platforms where the native credential service is unavailable.
 * The encryption key is derived afresh from a user-provided PIN and a machine-specific identifier.
 */
export class PinProtectedLlmCredentialStore {
  private readonly credentialFilePath: string;
  private readonly machineIdentifier: () => Promise<string>;

  constructor(options: PinProtectedLlmCredentialStoreOptions = {}) {
    this.credentialFilePath = options.credentialFilePath ?? defaultEncryptedCredentialFilePath();
    this.machineIdentifier = options.machineIdentifier ?? defaultMachineIdentifier;
  }

  async get(provider: LlmCredentialProvider, pin: string): Promise<string | undefined> {
    validateProvider(provider);
    if (provider === "local") {
      return undefined;
    }
    const stored = await this.read();
    const credential = stored.credentials[provider];
    if (!credential) {
      return undefined;
    }
    const key = await this.deriveKey(pin, stored.kdf.salt);
    try {
      const decipher = createDecipheriv(encryptionAlgorithm, key, Buffer.from(credential.iv, "base64"));
      decipher.setAAD(Buffer.from(`${encryptionContext}:${provider}`, "utf8"));
      decipher.setAuthTag(Buffer.from(credential.tag, "base64"));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(credential.ciphertext, "base64")), decipher.final()]).toString("utf8");
      return normalizeApiKey(plaintext);
    } catch {
      throw new Error("Stored LLM credential could not be decrypted with the configured PIN.");
    }
  }

  async set(provider: LlmCredentialProvider, apiKey: string, pin: string): Promise<void> {
    validateProvider(provider);
    if (provider === "local") {
      throw new Error("Local Ollama does not require an API key.");
    }
    const key = normalizeApiKey(apiKey);
    const normalizedPin = normalizePin(pin);
    const stored = await this.read();
    const encryptionKey = await this.deriveKey(normalizedPin, stored.kdf.salt);
    const iv = randomBytes(ivLength);
    const cipher = createCipheriv(encryptionAlgorithm, encryptionKey, iv);
    cipher.setAAD(Buffer.from(`${encryptionContext}:${provider}`, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(key, "utf8"), cipher.final()]);
    stored.credentials[provider] = {
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64")
    };
    await this.write(stored);
  }

  async delete(provider: LlmCredentialProvider): Promise<boolean> {
    validateProvider(provider);
    if (provider === "local") {
      return false;
    }
    const stored = await this.read();
    if (!stored.credentials[provider]) {
      return false;
    }
    delete stored.credentials[provider];
    await this.write(stored);
    return true;
  }

  async has(provider: LlmCredentialProvider): Promise<boolean> {
    validateProvider(provider);
    if (provider === "local") {
      return false;
    }
    return Boolean((await this.read()).credentials[provider]);
  }

  private async deriveKey(pin: string, salt: string): Promise<Buffer> {
    const normalizedPin = normalizePin(pin);
    const machineIdentifier = await this.machineIdentifier();
    if (!machineIdentifier.trim()) {
      throw new Error("Could not determine a machine identifier for encrypted credential storage.");
    }
    return deriveKey(normalizedPin, machineIdentifier, Buffer.from(salt, "base64"));
  }

  private async read(): Promise<EncryptedCredentialFile> {
    try {
      const raw = await fs.readFile(this.credentialFilePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<EncryptedCredentialFile>;
      if (
        parsed.version !== encryptedCredentialFileVersion ||
        parsed.kdf?.algorithm !== "scrypt" ||
        typeof parsed.kdf.salt !== "string" ||
        !isBase64(parsed.kdf.salt) ||
        !parsed.credentials ||
        typeof parsed.credentials !== "object" ||
        Array.isArray(parsed.credentials)
      ) {
        throw new Error("Encrypted LLM credential metadata is invalid.");
      }
      const credentials: EncryptedCredentialFile["credentials"] = {};
      for (const provider of supportedProviders) {
        const credential = parsed.credentials[provider];
        if (credential !== undefined) {
          if (!isEncryptedCredential(credential)) {
            throw new Error("Encrypted LLM credential metadata is invalid.");
          }
          credentials[provider] = credential;
        }
      }
      return {
        version: encryptedCredentialFileVersion,
        kdf: { algorithm: "scrypt", salt: parsed.kdf.salt },
        credentials
      };
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return {
          version: encryptedCredentialFileVersion,
          kdf: { algorithm: "scrypt", salt: randomBytes(16).toString("base64") },
          credentials: {}
        };
      }
      throw error;
    }
  }

  private async write(stored: EncryptedCredentialFile): Promise<void> {
    if (Object.keys(stored.credentials).length === 0) {
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
      await fs.writeFile(temporaryPath, `${JSON.stringify(stored)}\n`, { encoding: "utf8", mode: 0o600 });
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

export function defaultEncryptedCredentialFilePath(): string {
  return path.join(os.homedir(), ".vibeguard", "llm-credentials.aes.json");
}

/** Reads a stable platform machine identifier without persisting it in the credential file. */
export async function defaultMachineIdentifier(): Promise<string> {
  try {
    if (process.platform === "linux") {
      const machineId = (await fs.readFile("/etc/machine-id", "utf8")).trim();
      if (machineId) {
        return machineId;
      }
    }
    if (process.platform === "win32") {
      const { stdout } = await execFileAsync("reg.exe", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]);
      const match = stdout.match(/MachineGuid\s+REG_\w+\s+([^\s]+)/i);
      if (match?.[1]) {
        return match[1];
      }
    }
    if (process.platform === "darwin") {
      const { stdout } = await execFileAsync("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]);
      const match = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (match?.[1]) {
        return match[1];
      }
    }
  } catch {
    // A host/user-derived value is intentionally only a last resort; the user PIN remains required.
  }
  return createHash("sha256").update(`${os.hostname()}\u0000${os.userInfo().username}`).digest("hex");
}

function deriveKey(pin: string, machineIdentifier: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(`${pin}\u0000${machineIdentifier}`, salt, keyLength, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(Buffer.from(key));
    });
  });
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

function normalizePin(value: string): string {
  if (value.length < 8) {
    throw new Error("LLM credential PIN must be at least 8 characters.");
  }
  if (value.length > 1024) {
    throw new Error("LLM credential PIN must not exceed 1024 characters.");
  }
  return value;
}

function isEncryptedCredential(value: unknown): value is EncryptedCredential {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const credential = value as Partial<EncryptedCredential>;
  if (
    typeof credential.iv !== "string" ||
    typeof credential.tag !== "string" ||
    typeof credential.ciphertext !== "string" ||
    !isBase64(credential.iv) ||
    !isBase64(credential.tag) ||
    !isBase64(credential.ciphertext)
  ) {
    return false;
  }
  return (
    Buffer.from(credential.iv, "base64").length === ivLength &&
    Buffer.from(credential.tag, "base64").length === 16 &&
    Buffer.from(credential.ciphertext, "base64").length > 0
  );
}

function isBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
