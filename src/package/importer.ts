import fs from "fs/promises";

export interface ParsedPackageList {
  names: string[];
  format: "json-array" | "json-rows" | "json-packages" | "line-list";
}

export async function readPackageNameFile(filePath: string): Promise<ParsedPackageList> {
  return parsePackageNameList(await fs.readFile(filePath, "utf8"));
}

export function parsePackageNameList(raw: string): ParsedPackageList {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      names: [],
      format: "line-list"
    };
  }

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      const fromJson = parseJsonPackageList(parsed);
      if (fromJson) {
        return fromJson;
      }
    } catch {
      // Fall through to line-list parsing for .jsonl or imperfect exports.
    }
  }

  return {
    names: parseLineList(raw),
    format: "line-list"
  };
}

function parseJsonPackageList(value: unknown): ParsedPackageList | undefined {
  if (Array.isArray(value)) {
    return {
      names: value.filter(isString).map(cleanPackageName).filter(Boolean),
      format: "json-array"
    };
  }

  if (!value || typeof value !== "object") {
    return undefined;
  }

  const object = value as Record<string, unknown>;
  if (Array.isArray(object.rows)) {
    return {
      names: object.rows.map(rowPackageName).filter(isString),
      format: "json-rows"
    };
  }

  if (Array.isArray(object.packages)) {
    return {
      names: object.packages.filter(isString).map(cleanPackageName).filter(Boolean),
      format: "json-packages"
    };
  }

  return undefined;
}

function parseLineList(raw: string): string[] {
  const names: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const packageName = cleanPackageName(line.split("#")[0] ?? "");
    if (packageName) {
      names.push(packageName);
    }
  }
  return names;
}

function rowPackageName(value: unknown): string | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const row = value as Record<string, unknown>;
  if (isString(row.id)) {
    return cleanPackageName(row.id);
  }
  if (isString(row.key)) {
    return cleanPackageName(row.key);
  }
  return undefined;
}

function cleanPackageName(value: string): string {
  return value.trim().replace(/^"|"$/g, "");
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
