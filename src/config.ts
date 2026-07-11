import fs from "fs/promises";
import os from "os";
import path from "path";
import type { PackageRegistry, VibeGuardConfig } from "./types";
import { defaultConfig } from "./types";

export interface LoadedVibeGuardConfig {
  config: VibeGuardConfig;
  path: string;
  exists: boolean;
}

const registries: PackageRegistry[] = ["npm", "pypi", "cargo", "gomod", "maven"];
const packageVerificationModes = ["off", "seed", "remote"] as const;
const llmProviders = ["deepseek", "claude", "openai", "local", "vibeguard"] as const;

export function defaultConfigPath(): string {
  return path.join(os.homedir(), ".vibeguard", "config.json");
}

export function cloneDefaultConfig(): VibeGuardConfig {
  return {
    enabled: defaultConfig.enabled,
    detection_layers: { ...defaultConfig.detection_layers },
    package_verification: defaultConfig.package_verification,
    llm_provider: defaultConfig.llm_provider,
    llm_api_key_stored: defaultConfig.llm_api_key_stored,
    llm_api_key: defaultConfig.llm_api_key,
    dedup_with_existing_tools: defaultConfig.dedup_with_existing_tools,
    custom_rules: [...defaultConfig.custom_rules],
    ignored_findings: [...defaultConfig.ignored_findings],
    package_cache: {
      languages: [...defaultConfig.package_cache.languages],
      update_interval: defaultConfig.package_cache.update_interval,
      lightweight_mode: defaultConfig.package_cache.lightweight_mode,
      background_full_sync: defaultConfig.package_cache.background_full_sync
    },
    telemetry: defaultConfig.telemetry
  };
}

export async function loadConfig(filePath = defaultConfigPath()): Promise<LoadedVibeGuardConfig> {
  const resolvedPath = path.resolve(expandHome(filePath));
  try {
    const raw = await fs.readFile(resolvedPath, "utf8");
    return {
      config: parseConfig(raw, resolvedPath),
      path: resolvedPath,
      exists: true
    };
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return {
        config: cloneDefaultConfig(),
        path: resolvedPath,
        exists: false
      };
    }
    throw error;
  }
}

export async function ensureConfigFile(
  filePath = defaultConfigPath(),
  options: { force?: boolean } = {}
): Promise<{ path: string; created: boolean }> {
  const resolvedPath = path.resolve(expandHome(filePath));
  if (!options.force) {
    try {
      await fs.access(resolvedPath);
      return { path: resolvedPath, created: false };
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
  await fs.writeFile(resolvedPath, `${JSON.stringify(cloneDefaultConfig(), null, 2)}\n`, "utf8");
  return { path: resolvedPath, created: true };
}

export async function updateIgnoredFinding(
  findingId: string,
  action: "add" | "remove",
  filePath = defaultConfigPath()
): Promise<{ path: string; ignoredFindings: string[] }> {
  if (!findingId.trim()) {
    throw new Error("Finding id must not be empty.");
  }
  const resolvedPath = path.resolve(expandHome(filePath));
  const loaded = await loadConfig(resolvedPath);
  const ids = new Set(loaded.config.ignored_findings);
  if (action === "add") {
    ids.add(findingId.trim());
  } else {
    ids.delete(findingId.trim());
  }

  const nextConfig: VibeGuardConfig = {
    ...loaded.config,
    detection_layers: { ...loaded.config.detection_layers },
    custom_rules: [...loaded.config.custom_rules],
    ignored_findings: [...ids].sort(),
    package_cache: {
      ...loaded.config.package_cache,
      languages: [...loaded.config.package_cache.languages]
    }
  };
  await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
  await fs.writeFile(resolvedPath, `${JSON.stringify(nextConfig, null, 2)}\n`, "utf8");
  return {
    path: resolvedPath,
    ignoredFindings: nextConfig.ignored_findings
  };
}

export async function updateLlmApiKeyStored(
  stored: boolean,
  filePath = defaultConfigPath(),
  provider?: VibeGuardConfig["llm_provider"]
): Promise<{ path: string; llmApiKeyStored: boolean }> {
  const resolvedPath = path.resolve(expandHome(filePath));
  const loaded = await loadConfig(resolvedPath);
  const nextConfig: VibeGuardConfig = {
    ...loaded.config,
    detection_layers: { ...loaded.config.detection_layers },
    llm_provider: provider ?? loaded.config.llm_provider,
    llm_api_key_stored: stored,
    llm_api_key: null,
    custom_rules: [...loaded.config.custom_rules],
    ignored_findings: [...loaded.config.ignored_findings],
    package_cache: {
      ...loaded.config.package_cache,
      languages: [...loaded.config.package_cache.languages]
    }
  };
  await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
  await fs.writeFile(resolvedPath, `${JSON.stringify(nextConfig, null, 2)}\n`, "utf8");
  return {
    path: resolvedPath,
    llmApiKeyStored: nextConfig.llm_api_key_stored ?? false
  };
}

export function parseConfig(raw: string, sourceName = "config.json"): VibeGuardConfig {
  let value: unknown;
  try {
    value = JSON.parse(raw.replace(/^\uFEFF/, ""));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid VibeGuard config JSON in ${sourceName}: ${detail}`);
  }
  return normalizeConfig(value, sourceName);
}

export function resolveConfigRelativePath(inputPath: string, configPath = defaultConfigPath()): string {
  const expanded = expandHome(inputPath);
  if (path.isAbsolute(expanded)) {
    return path.resolve(expanded);
  }
  return path.resolve(path.dirname(path.resolve(expandHome(configPath))), expanded);
}

export function resolveConfigCustomRulePaths(config: VibeGuardConfig, configPath = defaultConfigPath()): string[] {
  return config.custom_rules.map((rulePath) => resolveConfigRelativePath(rulePath, configPath));
}

function normalizeConfig(value: unknown, sourceName: string): VibeGuardConfig {
  const config = cloneDefaultConfig();
  const input = expectPlainObject(value, "root", sourceName);
  if (input.detection_layers !== undefined) {
    expectPlainObject(input.detection_layers, "detection_layers", sourceName);
  }
  if (input.package_cache !== undefined) {
    expectPlainObject(input.package_cache, "package_cache", sourceName);
  }

  return {
    enabled: readBoolean(input, "enabled", config.enabled, sourceName),
    detection_layers: {
      l1: readBoolean(input, "detection_layers.l1", config.detection_layers.l1, sourceName),
      l2: readBoolean(input, "detection_layers.l2", config.detection_layers.l2, sourceName),
      l3: readBoolean(input, "detection_layers.l3", config.detection_layers.l3, sourceName)
    },
    package_verification: readEnum(
      input,
      "package_verification",
      config.package_verification,
      packageVerificationModes,
      sourceName
    ),
    llm_provider: readOptionalEnum(input, "llm_provider", config.llm_provider, llmProviders, sourceName),
    llm_api_key_stored: readBoolean(input, "llm_api_key_stored", config.llm_api_key_stored ?? false, sourceName),
    llm_api_key: readNull(input, "llm_api_key", config.llm_api_key ?? null, sourceName),
    dedup_with_existing_tools: readBoolean(
      input,
      "dedup_with_existing_tools",
      config.dedup_with_existing_tools,
      sourceName
    ),
    custom_rules: readStringArray(input, "custom_rules", config.custom_rules, sourceName),
    ignored_findings: readStringArray(input, "ignored_findings", config.ignored_findings, sourceName),
    package_cache: {
      languages: readRegistryArray(input, "package_cache.languages", config.package_cache.languages, sourceName),
      update_interval: readEnum(
        input,
        "package_cache.update_interval",
        config.package_cache.update_interval,
        ["daily", "weekly"],
        sourceName
      ),
      lightweight_mode: readBoolean(
        input,
        "package_cache.lightweight_mode",
        config.package_cache.lightweight_mode,
        sourceName
      ),
      background_full_sync: readBoolean(
        input,
        "package_cache.background_full_sync",
        config.package_cache.background_full_sync,
        sourceName
      )
    },
    telemetry: readBoolean(input, "telemetry", config.telemetry, sourceName)
  };
}

function readBoolean(source: Record<string, unknown>, key: string, fallback: boolean, sourceName: string): boolean {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be boolean.`);
  }
  return value;
}

function readNull(source: Record<string, unknown>, key: string, fallback: null, sourceName: string): null {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return fallback;
  }
  if (value !== null) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be null.`);
  }
  return null;
}

function readEnum<T extends string>(
  source: Record<string, unknown>,
  key: string,
  fallback: T,
  allowed: readonly T[],
  sourceName: string
): T {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be one of ${allowed.join(", ")}.`);
  }
  return value as T;
}

function readOptionalEnum<T extends string>(
  source: Record<string, unknown>,
  key: string,
  fallback: T | undefined,
  allowed: readonly T[],
  sourceName: string
): T | undefined {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be one of ${allowed.join(", ")}.`);
  }
  return value as T;
}

function readStringArray(
  source: Record<string, unknown>,
  key: string,
  fallback: string[],
  sourceName: string
): string[] {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return [...fallback];
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be an array of strings.`);
  }
  return [...value];
}

function readRegistryArray(
  source: Record<string, unknown>,
  key: string,
  fallback: PackageRegistry[],
  sourceName: string
): PackageRegistry[] {
  const value = getNestedValue(source, key);
  if (value === undefined) {
    return [...fallback];
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !registries.includes(item as PackageRegistry))) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must contain supported registries.`);
  }
  return [...value] as PackageRegistry[];
}

function expectPlainObject(value: unknown, key: string, sourceName: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid VibeGuard config in ${sourceName}: ${key} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function getNestedValue(source: Record<string, unknown>, dottedKey: string): unknown {
  const segments = dottedKey.split(".");
  let current: unknown = source;
  for (const segment of segments) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function expandHome(inputPath: string): string {
  if (inputPath === "~") {
    return os.homedir();
  }
  if (inputPath.startsWith("~/") || inputPath.startsWith("~\\")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }
  return inputPath;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
