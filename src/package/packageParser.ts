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

const rustStdlib = new Set(["alloc", "core", "crate", "self", "std", "super"]);

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
  if (fileName === "cargo.toml") {
    return parseCargoToml(filePath, text);
  }
  if (fileName === "go.mod") {
    return parseGoMod(filePath, text);
  }
  if (fileName === "pom.xml") {
    return parsePomXml(filePath, text);
  }
  if (fileName === "build.gradle" || fileName === "build.gradle.kts") {
    return parseGradleBuild(filePath, text);
  }
  if (fileName.endsWith(".versions.toml")) {
    return parseGradleVersionCatalog(filePath, text);
  }
  if (
    ["sh", "bash", "zsh", "ps1", "yml", "yaml"].includes(ext) ||
    fileName === "dockerfile" ||
    ["shellscript", "powershell", "yaml", "dockerfile"].includes(languageId ?? "")
  ) {
    return parsePipInstallCommands(filePath, text);
  }
  if (["js", "jsx", "ts", "tsx", "mjs", "cjs"].includes(ext) || ["javascript", "typescript", "javascriptreact", "typescriptreact"].includes(languageId ?? "")) {
    return parseJavaScriptImports(filePath, text);
  }
  if (ext === "py" || languageId === "python") {
    return parsePythonImports(filePath, text);
  }
  if (ext === "rs" || languageId === "rust") {
    return parseRustImports(filePath, text);
  }
  if (ext === "go" || languageId === "go") {
    return parseGoImports(filePath, text);
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

  references.push(...parsePipInstallCommands(filePath, text));
  return dedupeReferences(references).sort((left, right) => left.line - right.line || left.column - right.column);
}

function parsePipInstallCommands(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const stringCommand = /\b(?:subprocess\.(?:run|call|check_call)|os\.system)\s*\(\s*["'](?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^"'\r\n]+)/gi;
  const arrayCommand = /\bsubprocess\.(?:run|call|check_call)\s*\(\s*\[\s*["']pip(?:3)?["']\s*,\s*["']install["']\s*,\s*["']([^"'\r\n]+)["']/gi;
  const notebookCommand = /^\s*!\s*(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^\r\n#]+)/gim;
  const scriptCommand = /^\s*(?:-\s+)?(?:run:\s*)?(?:RUN\s+)?(?:sudo\s+)?(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^\r\n#]+)/gim;

  for (const command of [stringCommand, arrayCommand, notebookCommand, scriptCommand]) {
    for (const match of text.matchAll(command)) {
      const argumentsText = match[1] ?? "";
      const matchIndex = match.index ?? 0;
      const argumentsOffset = match[0].indexOf(argumentsText);
      addPipArgumentReferences(
        references,
        filePath,
        text,
        argumentsText,
        matchIndex + Math.max(0, argumentsOffset)
      );
    }
  }
  return references;
}

function addPipArgumentReferences(
  references: PackageReference[],
  filePath: string,
  text: string,
  argumentsText: string,
  argumentsIndex: number
): void {
  const flagsWithValues = new Set(["-r", "--requirement", "-c", "--constraint", "-f", "--find-links", "--index-url", "--extra-index-url", "--trusted-host"]);
  let skipNext = false;
  const tokenRegex = /[^\s]+/g;
  for (const tokenMatch of argumentsText.matchAll(tokenRegex)) {
    const token = tokenMatch[0];
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (flagsWithValues.has(token)) {
      skipNext = true;
      continue;
    }
    if (token.startsWith("-")) {
      continue;
    }
    const packageMatch = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?(?:[<>=!~].*)?$/.exec(token);
    const rawPackageName = packageMatch?.[1];
    if (!rawPackageName) {
      continue;
    }
    const packageName = normalizePypiPackage(rawPackageName);
    if (!packageName) {
      continue;
    }
    const tokenIndex = tokenMatch.index ?? 0;
    references.push(
      makeReference(filePath, text, "pypi", packageName, rawPackageName, argumentsIndex + tokenIndex, rawPackageName, "install")
    );
  }
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

function parseCargoToml(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  let inDependencySection = false;
  const lineRegex = /^.*$/gm;

  for (const match of text.matchAll(lineRegex)) {
    const line = match[0];
    const lineStart = match.index ?? 0;
    const stripped = stripTomlComment(line).trim();
    if (!stripped) {
      continue;
    }
    const section = stripped.match(/^\[([^\]]+)]$/)?.[1];
    if (section) {
      inDependencySection = /^(?:workspace\.)?(?:dependencies|dev-dependencies|build-dependencies)$/.test(section)
        || /^target\.[^.]+(?:\.[^.]+)*\.(?:dependencies|dev-dependencies|build-dependencies)$/.test(section);
      continue;
    }
    if (!inDependencySection) {
      continue;
    }

    const dep = stripped.match(/^([A-Za-z0-9_-]+)\s*=/);
    const packageName = dep?.[1];
    if (!packageName) {
      continue;
    }
    const column = line.indexOf(packageName);
    references.push(
      makeReference(filePath, text, "cargo", packageName, packageName, lineStart + Math.max(0, column), line, "manifest")
    );
  }

  return dedupeReferences(references);
}

function parseRustImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const regexes = [
    /^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)::/gm,
    /^\s*extern\s+crate\s+([A-Za-z_][A-Za-z0-9_-]*)/gm
  ];

  for (const regex of regexes) {
    for (const match of text.matchAll(regex)) {
      const packageName = normalizeRustCrate(match[1] ?? "");
      if (!packageName) {
        continue;
      }
      references.push(makeReference(filePath, text, "cargo", packageName, match[1] ?? "", match.index ?? 0, match[0], "import"));
    }
  }

  return dedupeReferences(references);
}

function parseGoMod(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const lineRegex = /^\s*require\s+([^\s()]+)\s+v[^\s]+/gm;
  const blockRegex = /^\s*require\s*\(\s*([\s\S]*?)^\s*\)/gm;

  for (const match of text.matchAll(lineRegex)) {
    addGoReference(references, filePath, text, match[1] ?? "", match.index ?? 0, match[0], "manifest", false);
  }

  for (const block of text.matchAll(blockRegex)) {
    const blockStart = block.index ?? 0;
    const body = block[1] ?? "";
    const entryRegex = /^\s*([^\s()]+)\s+v[^\s/]+.*$/gm;
    for (const entry of body.matchAll(entryRegex)) {
      addGoReference(
        references,
        filePath,
        text,
        entry[1] ?? "",
        blockStart + (block[0].indexOf(entry[0]) ?? 0),
        entry[0],
        "manifest",
        false
      );
    }
  }

  return dedupeReferences(references);
}

function parseGoImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const importBlockRegex = /^\s*import\s*\(\s*([\s\S]*?)^\s*\)/gm;
  const singleImportRegex = /^\s*import\s+(?:[._A-Za-z0-9]+\s+)?["']([^"']+)["']/gm;

  for (const match of text.matchAll(singleImportRegex)) {
    addGoReference(references, filePath, text, match[1] ?? "", match.index ?? 0, match[0], "import", true);
  }

  for (const block of text.matchAll(importBlockRegex)) {
    const blockStart = block.index ?? 0;
    const body = block[1] ?? "";
    const stringRegex = /(?:[._A-Za-z0-9]+\s+)?["']([^"']+)["']/g;
    for (const entry of body.matchAll(stringRegex)) {
      addGoReference(
        references,
        filePath,
        text,
        entry[1] ?? "",
        blockStart + (block[0].indexOf(entry[0]) ?? 0),
        entry[0],
        "import",
        true
      );
    }
  }

  return dedupeReferences(references);
}

function parsePomXml(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const dependencyRegex = /<dependency\b[\s\S]*?<\/dependency>/gi;
  for (const match of text.matchAll(dependencyRegex)) {
    const block = match[0];
    const groupId = readXmlTag(block, "groupId");
    const artifactId = readXmlTag(block, "artifactId");
    if (!groupId || !artifactId || groupId.includes("${") || artifactId.includes("${")) {
      continue;
    }
    const packageName = normalizeMavenCoordinate(groupId, artifactId);
    const artifactOffset = block.indexOf(artifactId);
    references.push(
      makeReference(
        filePath,
        text,
        "maven",
        packageName,
        artifactId,
        (match.index ?? 0) + Math.max(0, artifactOffset),
        artifactId,
        "manifest"
      )
    );
  }
  return dedupeReferences(references);
}

function parseGradleBuild(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const dependencyRegex =
    /\b(?:api|annotationProcessor|classpath|compileOnly|implementation|runtimeOnly|testImplementation|testRuntimeOnly)\s*(?:\(\s*)?["']([^:"'\s]+):([^:"'\s]+)(?::[^"']+)?["']/g;

  for (const match of text.matchAll(dependencyRegex)) {
    const packageName = normalizeMavenCoordinate(match[1] ?? "", match[2] ?? "");
    const coordinateIndex = (match.index ?? 0) + Math.max(0, match[0].indexOf(match[1] ?? ""));
    references.push(makeReference(filePath, text, "maven", packageName, packageName, coordinateIndex, packageName, "manifest"));
  }

  return dedupeReferences(references);
}

/** Parses Gradle version-catalog libraries without trying to infer plugin or source-import coordinates. */
function parseGradleVersionCatalog(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  let inLibraries = false;
  const lineRegex = /^.*$/gm;

  for (const match of text.matchAll(lineRegex)) {
    const line = match[0];
    const lineStart = match.index ?? 0;
    const stripped = stripTomlComment(line).trim();
    if (!stripped) {
      continue;
    }
    const section = /^\[([^\]]+)]$/.exec(stripped)?.[1];
    if (section) {
      inLibraries = section.trim() === "libraries";
      continue;
    }
    if (!inLibraries) {
      continue;
    }
    const coordinate = readGradleVersionCatalogCoordinate(stripped);
    if (!coordinate) {
      continue;
    }
    const coordinateIndex = line.indexOf(coordinate);
    references.push(
      makeReference(
        filePath,
        text,
        "maven",
        coordinate,
        coordinate,
        lineStart + Math.max(0, coordinateIndex),
        coordinate,
        "manifest"
      )
    );
  }

  return dedupeReferences(references);
}

function readGradleVersionCatalogCoordinate(line: string): string | undefined {
  const module = /\bmodule\s*=\s*["']([^:"']+):([^:"']+)["']/.exec(line);
  if (module) {
    return normalizeMavenCoordinate(module[1] ?? "", module[2] ?? "");
  }
  const group = /\bgroup\s*=\s*["']([^"']+)["']/.exec(line)?.[1];
  const name = /\bname\s*=\s*["']([^"']+)["']/.exec(line)?.[1];
  if (group && name) {
    return normalizeMavenCoordinate(group, name);
  }
  const direct = /^\s*[A-Za-z0-9_.-]+\s*=\s*["']([^:"']+):([^:"']+)(?::[^"']+)?["']\s*$/.exec(line);
  return direct ? normalizeMavenCoordinate(direct[1] ?? "", direct[2] ?? "") : undefined;
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

function addGoReference(
  references: PackageReference[],
  filePath: string,
  text: string,
  rawModule: string,
  index: number,
  evidence: string,
  source: PackageReference["source"],
  inferRoot: boolean
): void {
  const packageName = normalizeGoModule(rawModule, inferRoot);
  if (!packageName) {
    return;
  }
  references.push(makeReference(filePath, text, "gomod", packageName, rawModule, index, evidence, source));
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

function normalizeRustCrate(raw: string): string | undefined {
  const crateName = raw.trim();
  if (!crateName || rustStdlib.has(crateName)) {
    return undefined;
  }
  return crateName;
}

function normalizeGoModule(raw: string, inferRoot: boolean): string | undefined {
  const modulePath = raw.trim();
  if (!modulePath || modulePath.startsWith(".") || !modulePath.split("/")[0]?.includes(".")) {
    return undefined;
  }
  if (!inferRoot) {
    return modulePath;
  }
  const parts = modulePath.split("/");
  if (parts[0] === "github.com" || parts[0] === "gitlab.com" || parts[0] === "bitbucket.org") {
    return parts.length >= 3 ? parts.slice(0, 3).join("/") : modulePath;
  }
  if ((parts[0] === "golang.org" || parts[0] === "google.golang.org") && parts[1] === "x") {
    return parts.length >= 3 ? parts.slice(0, 3).join("/") : modulePath;
  }
  return parts.length >= 2 ? parts.slice(0, 2).join("/") : modulePath;
}

function normalizeMavenCoordinate(groupId: string, artifactId: string): string {
  return `${groupId.trim()}:${artifactId.trim()}`;
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

function stripTomlComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (char === '"' && !inSingle && line[index - 1] !== "\\") {
      inDouble = !inDouble;
    } else if (char === "#" && !inSingle && !inDouble) {
      return line.slice(0, index);
    }
  }
  return line;
}

function readXmlTag(block: string, tagName: string): string | undefined {
  const match = new RegExp(`<${tagName}>\\s*([^<]+?)\\s*</${tagName}>`, "i").exec(block);
  return match?.[1]?.trim();
}
