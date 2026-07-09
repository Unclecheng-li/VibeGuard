import type { PackageReference, PackageRegistry } from "../types";
import { extensionOf, positionAt } from "../utils";
import { packageAliases } from "./seedCatalog";

const nodeBuiltins = new Set([
  "assert",
  "buffer",
  "child_process",
  "cluster",
  "crypto",
  "dns",
  "events",
  "fs",
  "http",
  "https",
  "net",
  "os",
  "path",
  "process",
  "querystring",
  "readline",
  "stream",
  "string_decoder",
  "tls",
  "tty",
  "url",
  "util",
  "vm",
  "zlib"
]);

const pythonStdlib = new Set([
  "abc",
  "argparse",
  "asyncio",
  "base64",
  "collections",
  "contextlib",
  "csv",
  "dataclasses",
  "datetime",
  "decimal",
  "functools",
  "hashlib",
  "http",
  "importlib",
  "io",
  "itertools",
  "json",
  "logging",
  "math",
  "multiprocessing",
  "os",
  "pathlib",
  "pickle",
  "random",
  "re",
  "secrets",
  "shlex",
  "shutil",
  "sqlite3",
  "statistics",
  "string",
  "subprocess",
  "sys",
  "tempfile",
  "time",
  "typing",
  "urllib",
  "uuid",
  "xml"
]);

export function parsePackageReferences(filePath: string, text: string, languageId?: string): PackageReference[] {
  const normalized = filePath.replace(/\\/g, "/");
  const fileName = normalized.split("/").pop()?.toLowerCase() ?? "";
  const ext = extensionOf(filePath);

  if (fileName === "package.json") {
    return parsePackageJson(filePath, text);
  }
  if (fileName === "requirements.txt") {
    return parseRequirements(filePath, text);
  }
  if (fileName === "pyproject.toml") {
    return parsePyproject(filePath, text);
  }
  if (["js", "jsx", "ts", "tsx", "mjs", "cjs"].includes(ext) || ["javascript", "typescript", "javascriptreact", "typescriptreact"].includes(languageId ?? "")) {
    return parseJavaScriptImports(filePath, text);
  }
  if (ext === "py" || languageId === "python") {
    return parsePythonImports(filePath, text);
  }
  return [];
}

function parseJavaScriptImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const regexes = [
    /(?:import|export)\s+(?:type\s+)?(?:[^"'`]+?\s+from\s*)?["']([^"']+)["']/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g
  ];

  for (const regex of regexes) {
    regex.lastIndex = 0;
    for (const match of text.matchAll(regex)) {
      const specifier = match[1] ?? "";
      const packageName = normalizeNpmPackage(specifier);
      if (!packageName) {
        continue;
      }
      references.push(makeReference(filePath, text, "npm", packageName, specifier, match.index ?? 0, match[0], "import"));
    }
  }

  return dedupeReferences(references);
}

function parsePackageJson(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return references;
  }

  const root = parsed as Record<string, unknown>;
  for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    const dependencies = root[section];
    if (!dependencies || typeof dependencies !== "object") {
      continue;
    }
    for (const packageName of Object.keys(dependencies as Record<string, unknown>)) {
      const pattern = new RegExp(`"${escapeRegExp(packageName)}"\\s*:`, "g");
      const match = pattern.exec(text);
      const index = match?.index ?? text.indexOf(packageName);
      references.push(makeReference(filePath, text, "npm", packageName, packageName, index, packageName, "manifest"));
    }
  }

  return dedupeReferences(references);
}

function parsePythonImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const importRegex = /^\s*import\s+([A-Za-z_][A-Za-z0-9_.,\s]*)/gm;
  const fromRegex = /^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\b/gm;

  for (const match of text.matchAll(importRegex)) {
    const modules = (match[1] ?? "").split(",");
    for (const moduleName of modules) {
      const raw = moduleName.trim().split(/\s+as\s+/i)[0];
      addPythonReference(references, filePath, text, raw, match.index ?? 0, match[0], "import");
    }
  }

  for (const match of text.matchAll(fromRegex)) {
    addPythonReference(references, filePath, text, match[1] ?? "", match.index ?? 0, match[0], "import");
  }

  return dedupeReferences(references);
}

function parseRequirements(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const lineRegex = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?\s*(?:[<>=!~]=?.*)?$/gm;
  for (const match of text.matchAll(lineRegex)) {
    const fullLine = match[0].trim();
    if (!fullLine || fullLine.startsWith("#") || fullLine.startsWith("-")) {
      continue;
    }
    const packageName = normalizePypiPackage(match[1] ?? "");
    if (!packageName) {
      continue;
    }
    references.push(makeReference(filePath, text, "pypi", packageName, match[1] ?? "", match.index ?? 0, match[0], "manifest"));
  }
  return dedupeReferences(references);
}

function parsePyproject(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const dependencyRegex = /["']([A-Za-z0-9_.-]+)(?:\[[^\]]+])?(?:[<>=!~]=?[^"']*)?["']/g;
  for (const match of text.matchAll(dependencyRegex)) {
    const packageName = normalizePypiPackage(match[1] ?? "");
    if (!packageName) {
      continue;
    }
    references.push(makeReference(filePath, text, "pypi", packageName, match[1] ?? "", match.index ?? 0, match[0], "manifest"));
  }
  return dedupeReferences(references);
}

function addPythonReference(
  references: PackageReference[],
  filePath: string,
  text: string,
  rawModule: string,
  index: number,
  evidence: string,
  source: PackageReference["source"]
): void {
  const packageName = normalizePythonModule(rawModule);
  if (!packageName) {
    return;
  }
  references.push(makeReference(filePath, text, "pypi", packageName, rawModule, index, evidence, source));
}

function makeReference(
  _filePath: string,
  text: string,
  registry: PackageRegistry,
  packageName: string,
  rawSpecifier: string,
  index: number,
  evidence: string,
  source: PackageReference["source"]
): PackageReference {
  const quoteOffset = evidence.indexOf(rawSpecifier);
  const specifierIndex = quoteOffset === -1 ? index : index + quoteOffset;
  const start = positionAt(text, specifierIndex);
  const end = positionAt(text, specifierIndex + rawSpecifier.length);
  return {
    registry,
    packageName,
    rawSpecifier,
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    source
  };
}

function normalizeNpmPackage(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("#") || specifier.startsWith("node:")) {
    return undefined;
  }
  const withoutLoader = specifier.replace(/^!+/, "");
  const parts = withoutLoader.split("/");
  const packageName = withoutLoader.startsWith("@") ? `${parts[0]}/${parts[1] ?? ""}` : parts[0];
  if (!packageName || nodeBuiltins.has(packageName)) {
    return undefined;
  }
  return packageName;
}

function normalizePythonModule(raw: string): string | undefined {
  const first = raw.trim().split(".")[0];
  if (!first || pythonStdlib.has(first)) {
    return undefined;
  }
  return normalizePypiPackage(packageAliases[first] ?? first);
}

function normalizePypiPackage(raw: string): string | undefined {
  const packageName = raw.trim().replace(/_/g, "-").toLowerCase();
  if (!packageName || pythonStdlib.has(packageName)) {
    return undefined;
  }
  return packageName;
}

function dedupeReferences(references: PackageReference[]): PackageReference[] {
  const seen = new Set<string>();
  return references.filter((reference) => {
    const key = `${reference.registry}:${reference.packageName}:${reference.line}:${reference.column}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
