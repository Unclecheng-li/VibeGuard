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

// Maven class lookup is only meaningful for external dependencies. These JVM
// platform namespaces are supplied by the JDK, Kotlin runtime, or Android SDK.
const jvmPlatformImportPrefixes = [
  "android.",
  "androidx.",
  "java.",
  "jdk.",
  "kotlin.",
  "sun.",
  "javax.accessibility.",
  "javax.annotation.processing.",
  "javax.crypto.",
  "javax.imageio.",
  "javax.lang.model.",
  "javax.management.",
  "javax.naming.",
  "javax.net.",
  "javax.print.",
  "javax.rmi.",
  "javax.script.",
  "javax.security.",
  "javax.smartcardio.",
  "javax.sound.",
  "javax.sql.",
  "javax.swing.",
  "javax.tools.",
  "javax.transaction.xa.",
  "javax.xml.catalog.",
  "javax.xml.crypto.",
  "javax.xml.datatype.",
  "javax.xml.namespace.",
  "javax.xml.parsers.",
  "javax.xml.stream.",
  "javax.xml.transform.",
  "javax.xml.validation.",
  "javax.xml.xpath.",
  "org.ietf.jgss.",
  "org.w3c.dom.",
  "org.xml.sax."
];

export function parsePackageReferences(filePath: string, text: string, languageId?: string): PackageReference[] {
  const normalized = filePath.replace(/\\/g, "/");
  const fileName = normalized.split("/").pop()?.toLowerCase() ?? "";
  const ext = extensionOf(filePath);

  if (fileName === "package.json") {
    return parsePackageJson(filePath, text);
  }
  if (isRequirementsManifestPath(filePath)) {
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
  if (["java", "kt", "kts"].includes(ext) || ["java", "kotlin"].includes(languageId ?? "")) {
    return parseJvmClassImports(filePath, text);
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

export function isRequirementsManifestPath(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  const fileName = normalizedPath.split("/").pop()?.toLowerCase() ?? "";
  if (/^requirements(?:[-_.][a-z0-9][a-z0-9_.-]*)?\.txt$/.test(fileName)) {
    return true;
  }
  return /(?:^|\/)requirements\/[^/]+\.txt$/i.test(normalizedPath);
}

function parseJavaScriptImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const codeMask = createJavaScriptCodeMask(text);
  const regexes = [
    /(?:import|export)\s+(?:type\s+)?(?:[^"'`]+?\s+from\s*)?["']([^"']+)["']/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g
  ];

  for (const regex of regexes) {
    regex.lastIndex = 0;
    for (const match of text.matchAll(regex)) {
      const matchIndex = match.index ?? 0;
      if (!codeMask[matchIndex]) {
        continue;
      }
      const specifier = match[1] ?? "";
      const packageName = normalizeNpmPackage(specifier);
      if (!packageName) {
        continue;
      }
      references.push(makeReference(filePath, text, "npm", packageName, specifier, matchIndex, match[0], "import"));
    }
  }

  return dedupeReferences(references);
}

function createJavaScriptCodeMask(text: string): Uint8Array {
  const codeMask = new Uint8Array(text.length);
  let index = 0;
  let state: "code" | "line-comment" | "block-comment" | "single-quote" | "double-quote" | "template" = "code";

  while (index < text.length) {
    const character = text[index];
    const next = text[index + 1];
    if (state === "code") {
      if (character === "/" && next === "/") {
        state = "line-comment";
        index += 2;
        continue;
      }
      if (character === "/" && next === "*") {
        state = "block-comment";
        index += 2;
        continue;
      }
      if (character === "'") {
        state = "single-quote";
        index += 1;
        continue;
      }
      if (character === '"') {
        state = "double-quote";
        index += 1;
        continue;
      }
      if (character === "`") {
        state = "template";
        index += 1;
        continue;
      }
      codeMask[index] = 1;
      index += 1;
      continue;
    }

    if (state === "line-comment") {
      if (character === "\n" || character === "\r") {
        state = "code";
      }
      index += 1;
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        state = "code";
        index += 2;
      } else {
        index += 1;
      }
      continue;
    }
    if (character === "\\") {
      index += 2;
      continue;
    }
    if ((state === "single-quote" && character === "'") || (state === "double-quote" && character === '"') || (state === "template" && character === "`")) {
      state = "code";
    }
    index += 1;
  }

  return codeMask;
}

function createPythonCodeMask(text: string): Uint8Array {
  const codeMask = new Uint8Array(text.length);
  let index = 0;
  let state: "code" | "line-comment" | "single-quote" | "double-quote" | "triple-single" | "triple-double" = "code";

  while (index < text.length) {
    const character = text[index];
    const triple = text.slice(index, index + 3);
    if (state === "code") {
      if (character === "#") {
        state = "line-comment";
        index += 1;
        continue;
      }
      if (triple === "'''") {
        state = "triple-single";
        index += 3;
        continue;
      }
      if (triple === '\"\"\"') {
        state = "triple-double";
        index += 3;
        continue;
      }
      if (character === "'") {
        state = "single-quote";
        index += 1;
        continue;
      }
      if (character === '"') {
        state = "double-quote";
        index += 1;
        continue;
      }
      codeMask[index] = 1;
      index += 1;
      continue;
    }

    if (state === "line-comment") {
      if (character === "\n" || character === "\r") {
        state = "code";
      }
      index += 1;
      continue;
    }
    if ((state === "triple-single" && triple === "'''") || (state === "triple-double" && triple === '\"\"\"')) {
      state = "code";
      index += 3;
      continue;
    }
    if (state === "triple-single" || state === "triple-double") {
      index += 1;
      continue;
    }
    if (character === "\\") {
      index += 2;
      continue;
    }
    if ((state === "single-quote" && character === "'") || (state === "double-quote" && character === '"')) {
      state = "code";
    }
    index += 1;
  }

  return codeMask;
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
    for (const [packageName, specifier] of Object.entries(dependencies as Record<string, unknown>)) {
      if (isLocalNpmSpecifier(specifier)) {
        continue;
      }
      const pattern = new RegExp(`"${escapeRegExp(packageName)}"\\s*:`, "g");
      const match = pattern.exec(text);
      const index = match?.index ?? text.indexOf(packageName);
      references.push(makeReference(filePath, text, "npm", packageName, packageName, index, packageName, "manifest"));
    }
  }

  return dedupeReferences(references);
}

function isLocalNpmSpecifier(value: unknown): boolean {
  if (typeof value !== "string") {
    return false;
  }
  const specifier = value.trim().toLowerCase();
  return ["workspace:", "file:", "link:", "portal:"].some((prefix) => specifier.startsWith(prefix));
}

function parsePythonImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const codeMask = createPythonCodeMask(text);
  const importRegex = /^[ \t]*import[ \t]+([A-Za-z_][A-Za-z0-9_., \t]*)/gm;
  const fromRegex = /^[ \t]*from[ \t]+([A-Za-z_][A-Za-z0-9_.]*)[ \t]+import\b/gm;

  for (const match of text.matchAll(importRegex)) {
    const matchIndex = match.index ?? 0;
    if (!codeMask[matchIndex]) {
      continue;
    }
    const modules = match[1] ?? "";
    const modulesOffset = /^[ \t]*import[ \t]+/.exec(match[0])?.[0].length ?? 0;
    let offset = 0;
    for (const moduleName of modules.split(",")) {
      const trimmedModule = moduleName.trimStart();
      const raw = trimmedModule.split(/\s+as\s+/i)[0] ?? "";
      if (raw) {
        addPythonReference(
          references,
          filePath,
          text,
          raw,
          matchIndex + modulesOffset + offset + moduleName.length - trimmedModule.length,
          raw,
          "import"
        );
      }
      offset += moduleName.length + 1;
    }
  }

  for (const match of text.matchAll(fromRegex)) {
    const matchIndex = match.index ?? 0;
    if (codeMask[matchIndex]) {
      const raw = match[1] ?? "";
      addPythonReference(
        references,
        filePath,
        text,
        raw,
        matchIndex + (/^[ \t]*from[ \t]+/.exec(match[0])?.[0].length ?? 0),
        raw,
        "import"
      );
    }
  }

  references.push(...parsePipInstallCommands(filePath, text, codeMask));
  return dedupeReferences(references).sort((left, right) => left.line - right.line || left.column - right.column);
}

function parsePipInstallCommands(filePath: string, text: string, codeMask?: Uint8Array): PackageReference[] {
  const references: PackageReference[] = [];
  const stringCommand = /\b(?:subprocess\.(?:run|call|check_call)|os\.system)\s*\(\s*["'](?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^"'\r\n]+)/gi;
  const arrayCommand = /\bsubprocess\.(?:run|call|check_call)\s*\(\s*\[\s*["']pip(?:3)?["']\s*,\s*["']install["']\s*,\s*([^\]\r\n]+)\]/gi;
  const notebookCommand = /^\s*!\s*(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^\r\n#]+)/gim;
  const scriptCommand = /^\s*(?:-\s+)?(?:run:\s*)?(?:RUN\s+)?(?:sudo\s+)?(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pip(?:3)?\s+install\s+([^\r\n#]+)/gim;

  for (const command of [stringCommand, notebookCommand, scriptCommand]) {
    for (const match of text.matchAll(command)) {
      const argumentsText = match[1] ?? "";
      const matchIndex = match.index ?? 0;
      if ((codeMask && !codeMask[matchIndex]) || hasUnquotedLineCommentBefore(text, matchIndex)) {
        continue;
      }
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

  for (const match of text.matchAll(arrayCommand)) {
    const argumentsText = match[1] ?? "";
    const matchIndex = match.index ?? 0;
    if ((codeMask && !codeMask[matchIndex]) || hasUnquotedLineCommentBefore(text, matchIndex)) {
      continue;
    }
    const argumentsOffset = match[0].indexOf(argumentsText);
    addPipArrayReferences(references, filePath, text, argumentsText, matchIndex + Math.max(0, argumentsOffset));
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
  let skipNext = false;
  const tokenRegex = /[^\s]+/g;
  for (const tokenMatch of argumentsText.matchAll(tokenRegex)) {
    const token = tokenMatch[0];
    skipNext = addPipPackageToken(
      references,
      filePath,
      text,
      token,
      argumentsIndex + (tokenMatch.index ?? 0),
      skipNext
    );
  }
}

function addPipArrayReferences(
  references: PackageReference[],
  filePath: string,
  text: string,
  argumentsText: string,
  argumentsIndex: number
): void {
  let skipNext = false;
  const quotedArgument = /["']([^"'\r\n]+)["']/g;
  for (const match of argumentsText.matchAll(quotedArgument)) {
    const token = match[1] ?? "";
    const tokenIndex = argumentsIndex + (match.index ?? 0) + 1;
    skipNext = addPipPackageToken(references, filePath, text, token, tokenIndex, skipNext);
  }
}

function addPipPackageToken(
  references: PackageReference[],
  filePath: string,
  text: string,
  token: string,
  tokenIndex: number,
  skipNext: boolean
): boolean {
  if (skipNext) {
    return false;
  }
  const flagsWithValues = new Set(["-r", "--requirement", "-c", "--constraint", "-f", "--find-links", "--index-url", "--extra-index-url", "--trusted-host"]);
  if (flagsWithValues.has(token)) {
    return true;
  }
  if (token.startsWith("-") || token.startsWith("#")) {
    return false;
  }
  const packageMatch = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?(?:[<>=!~].*)?$/.exec(token);
  const rawPackageName = packageMatch?.[1];
  if (!rawPackageName) {
    return false;
  }
  const packageName = normalizePypiPackage(rawPackageName);
  if (!packageName) {
    return false;
  }
  references.push(makeReference(filePath, text, "pypi", packageName, rawPackageName, tokenIndex, rawPackageName, "install"));
  return false;
}

function hasUnquotedLineCommentBefore(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  for (let cursor = lineStart; cursor < index; cursor += 1) {
    const character = text[cursor];
    const escaped = text[cursor - 1] === "\\";
    if (character === "'" && !inDoubleQuote && !escaped) {
      inSingleQuote = !inSingleQuote;
    } else if (character === '"' && !inSingleQuote && !escaped) {
      inDoubleQuote = !inDoubleQuote;
    } else if (character === "#" && !inSingleQuote && !inDoubleQuote) {
      return true;
    }
  }
  return false;
}

function parseRequirements(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const lineRegex = /^.*$/gm;
  for (const match of text.matchAll(lineRegex)) {
    const line = match[0];
    const fullLine = stripRequirementsComment(line).trim();
    if (!fullLine || fullLine.startsWith("#") || fullLine.startsWith("-")) {
      continue;
    }
    const rawPackageName = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?\s*(?:[<>=!~]=?.*)?$/.exec(fullLine)?.[1];
    const packageName = normalizePypiPackage(rawPackageName ?? "");
    if (!packageName) {
      continue;
    }
    const rawOffset = line.indexOf(rawPackageName ?? "");
    if (rawOffset === -1) {
      continue;
    }
    references.push(
      makeReference(
        filePath,
        text,
        "pypi",
        packageName,
        rawPackageName ?? "",
        (match.index ?? 0) + rawOffset,
        rawPackageName ?? "",
        "manifest"
      )
    );
  }
  return dedupeReferences(references);
}

function stripRequirementsComment(line: string): string {
  const commentOffset = line.search(/[ \t]#/);
  return commentOffset === -1 ? line : line.slice(0, commentOffset);
}

function parsePyproject(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  let section = "";
  let dependencyArrayOpen = false;
  const lineRegex = /^.*$/gm;

  for (const match of text.matchAll(lineRegex)) {
    const line = match[0];
    const lineStart = match.index ?? 0;
    const stripped = stripTomlComment(line).trim();
    if (!stripped) {
      continue;
    }
    const sectionHeader = /^\[([^\]]+)]$/.exec(stripped)?.[1];
    if (sectionHeader) {
      section = sectionHeader.trim().toLowerCase();
      dependencyArrayOpen = false;
      continue;
    }

    if (isPoetryDependencySection(section)) {
      const dependency = /^(?:["']?)([A-Za-z0-9_.-]+)(?:["']?)\s*=/.exec(stripped)?.[1];
      if (dependency && dependency.toLowerCase() !== "python") {
        addPyprojectDependencyReference(references, filePath, text, line, lineStart, dependency);
      }
    }

    if (dependencyArrayOpen || startsPyprojectDependencyArray(section, stripped)) {
      addPyprojectArrayReferences(references, filePath, text, line, lineStart);
      dependencyArrayOpen = !stripped.includes("]");
    }
  }
  return dedupeReferences(references);
}

function isPoetryDependencySection(section: string): boolean {
  return section === "tool.poetry.dependencies" || (section.startsWith("tool.poetry.group.") && section.endsWith(".dependencies"));
}

function startsPyprojectDependencyArray(section: string, line: string): boolean {
  if (!line.includes("=") || !line.includes("[")) {
    return false;
  }
  if (section === "project") {
    return /^dependencies\s*=/.test(line);
  }
  if (section === "build-system") {
    return /^requires\s*=/.test(line);
  }
  return section === "project.optional-dependencies";
}

function addPyprojectArrayReferences(
  references: PackageReference[],
  filePath: string,
  text: string,
  line: string,
  lineStart: number
): void {
  const dependencyRegex = /["']([A-Za-z0-9_.-]+)(?:\[[^\]]+])?(?:[<>=!~]=?[^"']*)?["']/g;
  for (const match of line.matchAll(dependencyRegex)) {
    const rawPackageName = match[1] ?? "";
    const packageName = normalizePypiPackage(rawPackageName);
    if (!packageName) {
      continue;
    }
    references.push(
      makeReference(filePath, text, "pypi", packageName, rawPackageName, lineStart + (match.index ?? 0), match[0], "manifest")
    );
  }
}

function addPyprojectDependencyReference(
  references: PackageReference[],
  filePath: string,
  text: string,
  line: string,
  lineStart: number,
  rawPackageName: string
): void {
  const packageName = normalizePypiPackage(rawPackageName);
  if (!packageName) {
    return;
  }
  const index = line.indexOf(rawPackageName);
  references.push(
    makeReference(filePath, text, "pypi", packageName, rawPackageName, lineStart + Math.max(0, index), rawPackageName, "manifest")
  );
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
    if (isCargoNonRegistryDependency(stripped)) {
      continue;
    }

    const dep = stripped.match(/^([A-Za-z0-9_-]+)\s*=/);
    const packageName = /\bpackage\s*=\s*["']([A-Za-z0-9_-]+)["']/.exec(stripped)?.[1] ?? dep?.[1];
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

function isCargoNonRegistryDependency(line: string): boolean {
  return /\b(?:path|git|registry)\s*=\s*["']/.test(line);
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

function parseJvmClassImports(filePath: string, text: string): PackageReference[] {
  const references: PackageReference[] = [];
  const importRegex = /^[ \t]*import[ \t]+(?!static\b)([A-Za-z_$][A-Za-z0-9_$.]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)(?:[ \t]+as[ \t]+[A-Za-z_$][A-Za-z0-9_$]*)?[ \t]*;?[ \t]*$/gm;
  for (const match of text.matchAll(importRegex)) {
    const className = match[1] ?? "";
    if (!isExternalJvmClassImport(className)) {
      continue;
    }
    const reference = makeReference(filePath, text, "maven", className, className, match.index ?? 0, match[0], "import");
    reference.mavenLookup = "class";
    references.push(reference);
  }
  return dedupeReferences(references);
}

function isExternalJvmClassImport(className: string): boolean {
  if (jvmPlatformImportPrefixes.some((prefix) => className.startsWith(prefix))) {
    return false;
  }
  const lastSegment = className.split(".").at(-1) ?? "";
  return /^[A-Z_$]/.test(lastSegment);
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
