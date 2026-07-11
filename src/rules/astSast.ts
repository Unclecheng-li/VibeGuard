import fs from "node:fs";
import path from "node:path";
import Parser = require("web-tree-sitter");

export interface AstSastCandidate {
  ruleId: string;
  index: number;
  endIndex: number;
  evidence: string;
}

export interface AstSastResult {
  candidates: AstSastCandidate[];
  handledRuleIds: ReadonlySet<string>;
}

type AstLanguage = "javascript" | "typescript" | "tsx" | "python";

interface LocalBinding {
  name: string;
  value: string;
  startIndex: number;
  scopeStartIndex: number;
  scopeEndIndex: number;
  tainted: boolean;
}

const javascriptRuleIds = new Set([
  "sast_sql_template_interpolation",
  "sast_sql_string_concat",
  "sast_sql_user_input_execute",
  "sast_xss_inner_html",
  "sast_xss_document_write",
  "sast_xss_dangerously_set_inner_html",
  "sast_ssrf_fetch_user_url",
  "sast_path_traversal_fs_user_input",
  "sast_command_injection_os_system",
  "sast_open_redirect_user_input",
  "sast_information_leakage_error_details"
]);

const pythonRuleIds = new Set([
  "sast_sql_python_f_string_execute",
  "sast_sql_user_input_execute",
  "sast_ssrf_fetch_user_url",
  "sast_path_traversal_fs_user_input",
  "sast_insecure_deserialization_pickle",
  "sast_insecure_deserialization_yaml",
  "sast_command_injection_os_system",
  "sast_open_redirect_user_input",
  "sast_information_leakage_error_details"
]);

const grammarFiles: Record<AstLanguage, string> = {
  javascript: "tree-sitter-javascript.wasm",
  typescript: "tree-sitter-typescript.wasm",
  tsx: "tree-sitter-tsx.wasm",
  python: "tree-sitter-python.wasm"
};

let parserInitialization: Promise<void> | undefined;
const grammars = new Map<AstLanguage, Promise<Parser.Language>>();

/**
 * Runs the high-volume JavaScript/TypeScript/Python L2 rules on Tree-sitter WASM syntax nodes.
 * Regex remains the fallback for languages without a grammar and incomplete edits.
 */
export async function detectAstSast(text: string, filePath: string, languageId?: string): Promise<AstSastResult> {
  const language = resolveLanguage(filePath, languageId);
  if (!language) {
    return emptyResult();
  }

  let parser: Parser | undefined;
  let tree: Parser.Tree | undefined;
  try {
    const grammar = await grammarFor(language);
    parser = new Parser();
    parser.setLanguage(grammar);
    tree = parser.parse(text);
    if (tree.rootNode.hasError()) {
      return emptyResult();
    }

    const candidates: AstSastCandidate[] = [];
    const seen = new Set<string>();
    const add = (ruleId: string, node: Parser.SyntaxNode): void => {
      const key = `${ruleId}:${node.startIndex}:${node.endIndex}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      candidates.push({
        ruleId,
        index: node.startIndex,
        endIndex: node.endIndex,
        evidence: node.text
      });
    };

    const bindings = collectTaintedLocalBindings(tree.rootNode, language);
    if (language === "python") {
      visit(tree.rootNode, (node) => analyzePythonNode(node, bindings, add));
    } else {
      visit(tree.rootNode, (node) => analyzeJavaScriptNode(node, bindings, add));
    }
    return {
      candidates,
      handledRuleIds: language === "python" ? pythonRuleIds : javascriptRuleIds
    };
  } catch {
    return emptyResult();
  } finally {
    tree?.delete();
    parser?.delete();
  }
}

function analyzeJavaScriptNode(
  node: Parser.SyntaxNode,
  bindings: readonly LocalBinding[],
  add: (ruleId: string, node: Parser.SyntaxNode) => void
): void {
  const text = node.text;
  if (node.type === "variable_declarator" || node.type === "assignment_expression") {
    if (/\b(?:query|sql|statement)\b\s*=\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+}[^`]*`/i.test(text)) {
      add("sast_sql_template_interpolation", node);
    }
    if (/\b(?:query|sql|statement)\b\s*=\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+/i.test(text)) {
      add("sast_sql_string_concat", node);
    }
    const left = node.childForFieldName("left")?.text ?? node.namedChildren[0]?.text ?? "";
    const right = node.childForFieldName("right")?.text ?? node.namedChildren[1]?.text ?? "";
    if (/\.(?:innerHTML|outerHTML)$/.test(left) && !isSanitizedHtml(right)) {
      add("sast_xss_inner_html", node);
    }
  }

  if (
    node.type === "jsx_attribute" &&
    /^\s*dangerouslySetInnerHTML\s*=/.test(text) &&
    hasJavaScriptUserInput(text, node, bindings) &&
    !isSanitizedHtml(text)
  ) {
    add("sast_xss_dangerously_set_inner_html", node);
  }

  if (node.type !== "call_expression") {
    return;
  }
  if (/^\s*document\.write\s*\(/.test(text)) {
    add("sast_xss_document_write", node);
  }
  if (isJavaScriptSqlExecution(text) && !hasBoundSqlParameters(text) && hasJavaScriptUserInput(text, node, bindings)) {
    add("sast_sql_user_input_execute", node);
  }
  if (isJavaScriptHttpRequest(text) && hasJavaScriptSsrfTarget(text, node, bindings)) {
    add("sast_ssrf_fetch_user_url", node);
  }
  if (
    /^\s*(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync)|open)\s*\(/i.test(text) &&
    hasJavaScriptUserInput(text, node, bindings)
  ) {
    add("sast_path_traversal_fs_user_input", node);
  }
  if (
    /^\s*(?:child_process\.)?exec(?:Sync)?\s*\(/i.test(text) &&
    (hasJavaScriptUserInput(text, node, bindings) || /\$\{/.test(text))
  ) {
    add("sast_command_injection_os_system", node);
  }
  if (/^\s*(?:res|response)\.redirect\s*\(/i.test(text) && hasJavaScriptUserInput(text, node, bindings)) {
    add("sast_open_redirect_user_input", node);
  }
  if (
    /^\s*(?:res|response)\.(?:send|json)\s*\([^;]*(?:err(?:or)?|exception)\.(?:stack|message)/i.test(text) ||
    /^\s*(?:res|response)\.status\s*\(\s*500\s*\)\.(?:send|json)\s*\([^;]*(?:err(?:or)?|exception)\.(?:stack|message)/i.test(text) ||
    exposesSensitiveErrorDetails(text)
  ) {
    add("sast_information_leakage_error_details", node);
  }
}

function analyzePythonNode(
  node: Parser.SyntaxNode,
  bindings: readonly LocalBinding[],
  add: (ruleId: string, node: Parser.SyntaxNode) => void
): void {
  const text = node.text;
  if (node.type === "return_statement" && exposesSensitiveErrorDetails(text)) {
    add("sast_information_leakage_error_details", node);
  }
  if (node.type !== "call") {
    return;
  }
  const interpolatedFString = /\bexecute\s*\([\s\S]*\bf["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{[^}]+}[^"']*["']/i.test(text);
  if (interpolatedFString) {
    add("sast_sql_python_f_string_execute", node);
  }
  if (!interpolatedFString && isPythonSqlExecution(text) && !hasBoundSqlParameters(text) && hasPythonUserInput(text, node, bindings)) {
    add("sast_sql_user_input_execute", node);
  }
  if (isPythonHttpRequest(text) && hasPythonSsrfTarget(text, node, bindings)) {
    add("sast_ssrf_fetch_user_url", node);
  }
  if (
    /^\s*(?:open|Path|send_file)\s*\(/.test(text) &&
    (hasPythonUserInput(text, node, bindings) || /\bparams?\s*\[/.test(text))
  ) {
    add("sast_path_traversal_fs_user_input", node);
  }
  if (/^\s*pickle\.loads?\s*\(/.test(text) && hasPythonUserInput(text, node, bindings)) {
    add("sast_insecure_deserialization_pickle", node);
  }
  if (/^\s*yaml\.load\s*\(/.test(text) && hasPythonUserInput(text, node, bindings) && !/SafeLoader/.test(text)) {
    add("sast_insecure_deserialization_yaml", node);
  }
  if (
    /^\s*(?:os\.system|subprocess\.(?:call|run|Popen|check_call|check_output))\s*\(/.test(text) &&
    (hasPythonUserInput(text, node, bindings) || /\{[^}]+}/.test(text))
  ) {
    add("sast_command_injection_os_system", node);
  }
  if (/^\s*redirect\s*\(/.test(text) && hasPythonUserInput(text, node, bindings)) {
    add("sast_open_redirect_user_input", node);
  }
  if (
    (/^\s*(?:traceback\.format_exc|str)\s*\(/.test(text) && /\b(?:err(?:or)?|exception|e)\b/i.test(text)) ||
    exposesSensitiveErrorDetails(text)
  ) {
    add("sast_information_leakage_error_details", node);
  }
}

function exposesSensitiveErrorDetails(text: string): boolean {
  const errorContext =
    /\b(?:err(?:or)?|exception)\.(?:stack|message)|\b(?:error|detail|message)\s*:|\bstatus\s*\(\s*5\d\d\s*\)|\b(?:catch|except)\b/i.test(
      text
    );
  const sensitiveField =
    /\b(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\s*:/i.test(text);
  const directSensitiveArgument =
    /\b(?:send|json)\s*\(\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)?(?:sql|query|stack|traceback|connection(?:string)?|database(?:url)?|api[_-]?key|secret|password|credential)\b/i.test(
      text
    );
  return errorContext && (sensitiveField || directSensitiveArgument);
}

function hasJavaScriptUserInput(text: string, node?: Parser.SyntaxNode, bindings: readonly LocalBinding[] = []): boolean {
  return /\breq\.(?:query|body|params)\b/i.test(text) || (node !== undefined && referencesTaintedBinding(text, node, bindings));
}

function hasPythonUserInput(text: string, node?: Parser.SyntaxNode, bindings: readonly LocalBinding[] = []): boolean {
  return (
    /\brequest\.(?:args|form|json)\b|\b(?:request|input|body|data)\b/i.test(text) ||
    (node !== undefined && referencesTaintedBinding(text, node, bindings))
  );
}

function isSanitizedHtml(text: string): boolean {
  return /\b(?:DOMPurify\s*\.\s*sanitize|sanitizeHtml|sanitize)\s*\(/i.test(text);
}

function isJavaScriptSqlExecution(text: string): boolean {
  return /^\s*(?:(?:this\s*\.\s*)?(?:db|database|pool|connection|conn|client|knex|sequelize|prisma|repository)\s*\.\s*)?(?:query|execute)\s*\(/i.test(
    text
  );
}

function isPythonSqlExecution(text: string): boolean {
  return /^\s*(?:(?:cursor|connection|conn|session|db|database)\s*\.\s*)?(?:execute|executemany)\s*\(/i.test(text);
}

function isJavaScriptHttpRequest(text: string): boolean {
  return /^\s*(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got(?:\.(?:get|post|put|patch|delete|head))?|undici\.request|(?:http|https)\.(?:get|request))\s*\(/i.test(
    text
  );
}

function isPythonHttpRequest(text: string): boolean {
  return /^\s*(?:(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)|urllib\.request\.urlopen|http\.get)\s*\(/i.test(text);
}

function hasJavaScriptSsrfTarget(text: string, node: Parser.SyntaxNode, bindings: readonly LocalBinding[]): boolean {
  const [firstArgument] = callArguments(text);
  if (!firstArgument) {
    return false;
  }
  const configurationCall = /^\s*(?:axios(?:\.request)?|(?:http|https)\.request)\s*\(/i.test(text);
  if (!configurationCall || !firstArgument.trim().startsWith("{")) {
    return hasJavaScriptUserInput(firstArgument, node, bindings);
  }
  for (const match of firstArgument.matchAll(/\b(?:url|uri|baseURL|host|hostname)\s*:\s*([^,}\n]+)/gi)) {
    if (hasJavaScriptUserInput(match[1] ?? "", node, bindings)) {
      return true;
    }
  }
  return false;
}

function hasPythonSsrfTarget(text: string, node: Parser.SyntaxNode, bindings: readonly LocalBinding[]): boolean {
  const argumentsText = callArguments(text);
  const target = /^\s*(?:requests|httpx)\.request\s*\(/i.test(text) ? argumentsText[1] : argumentsText[0];
  return Boolean(target && hasPythonUserInput(target, node, bindings));
}

function callArguments(text: string): string[] {
  const openIndex = text.indexOf("(");
  if (openIndex < 0) {
    return [];
  }
  const argumentsText: string[] = [];
  let startIndex = openIndex + 1;
  let depth = 0;
  let quote: string | undefined;
  let escaped = false;
  for (let index = startIndex; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = undefined;
      }
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "(" || character === "[" || character === "{") {
      depth += 1;
      continue;
    }
    if (character === ")" || character === "]" || character === "}") {
      if (character === ")" && depth === 0) {
        argumentsText.push(text.slice(startIndex, index).trim());
        return argumentsText.filter(Boolean);
      }
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (character === "," && depth === 0) {
      argumentsText.push(text.slice(startIndex, index).trim());
      startIndex = index + 1;
    }
  }
  return argumentsText.filter(Boolean);
}

function hasBoundSqlParameters(text: string): boolean {
  return /\b(?:query|execute|executemany)\s*\([\s\S]{0,500}?,\s*(?:\[|\(|\{)/i.test(text);
}

function collectTaintedLocalBindings(root: Parser.SyntaxNode, language: AstLanguage): LocalBinding[] {
  const bindings: LocalBinding[] = [];
  const assignmentTypes = language === "python" ? new Set(["assignment"]) : new Set(["variable_declarator", "assignment_expression"]);
  visit(root, (node) => {
    if (!assignmentTypes.has(node.type)) {
      return;
    }
    const assignment = parseSimpleAssignment(node.text, language);
    if (!assignment) {
      return;
    }
    const scope = enclosingScope(node, language);
    bindings.push({
      ...assignment,
      startIndex: node.startIndex,
      scopeStartIndex: scope.startIndex,
      scopeEndIndex: scope.endIndex,
      tainted: false
    });
  });

  let changed = true;
  while (changed) {
    changed = false;
    for (const binding of bindings) {
      if (binding.tainted) {
        continue;
      }
      const isSource = language === "python" ? isPythonTaintSource(binding.value) : isJavaScriptTaintSource(binding.value);
      if (isSource || referencesTaintedBindingAt(binding.value, binding, bindings)) {
        binding.tainted = true;
        changed = true;
      }
    }
  }
  return bindings;
}

function parseSimpleAssignment(text: string, language: AstLanguage): Pick<LocalBinding, "name" | "value"> | undefined {
  const identifier = language === "python" ? "[A-Za-z_][A-Za-z0-9_]*" : "[A-Za-z_$][A-Za-z0-9_$]*";
  const match = text.match(new RegExp(`^\\s*(${identifier})(?:\\s*:\\s*[^=]+)?\\s*=\\s*([\\s\\S]+)$`));
  if (!match) {
    return undefined;
  }
  return { name: match[1], value: match[2] };
}

function isJavaScriptTaintSource(value: string): boolean {
  return /\breq\.(?:query|body|params)\b/i.test(value);
}

function isPythonTaintSource(value: string): boolean {
  return /\brequest\.(?:args|form|json|data)\b|\b(?:raw_)?input\s*\(/i.test(value);
}

function referencesTaintedBinding(text: string, node: Parser.SyntaxNode, bindings: readonly LocalBinding[]): boolean {
  return referencesTaintedBindingAt(text, { startIndex: node.startIndex, ...scopeForNode(node) }, bindings);
}

function referencesTaintedBindingAt(
  text: string,
  context: Pick<LocalBinding, "startIndex" | "scopeStartIndex" | "scopeEndIndex">,
  bindings: readonly LocalBinding[]
): boolean {
  for (const name of identifiersIn(text)) {
    const binding = visibleBinding(name, context, bindings);
    if (binding?.tainted) {
      return true;
    }
  }
  return false;
}

function identifiersIn(text: string): Set<string> {
  return new Set(text.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []);
}

function visibleBinding(
  name: string,
  context: Pick<LocalBinding, "startIndex" | "scopeStartIndex" | "scopeEndIndex">,
  bindings: readonly LocalBinding[]
): LocalBinding | undefined {
  return bindings
    .filter(
      (binding) =>
        binding.name === name &&
        binding.startIndex < context.startIndex &&
        binding.scopeStartIndex <= context.scopeStartIndex &&
        binding.scopeEndIndex >= context.scopeEndIndex
    )
    .sort((left, right) => {
      const leftScopeSize = left.scopeEndIndex - left.scopeStartIndex;
      const rightScopeSize = right.scopeEndIndex - right.scopeStartIndex;
      return leftScopeSize - rightScopeSize || right.startIndex - left.startIndex;
    })[0];
}

function enclosingScope(node: Parser.SyntaxNode, language: AstLanguage): Parser.SyntaxNode {
  let current: Parser.SyntaxNode | null = node;
  const scopeTypes =
    language === "python"
      ? new Set(["module", "block", "function_definition", "class_definition", "for_statement", "while_statement", "if_statement", "try_statement", "with_statement"])
      : new Set([
          "program",
          "statement_block",
          "switch_body",
          "for_statement",
          "for_in_statement",
          "for_of_statement",
          "catch_clause",
          "arrow_function",
          "function_declaration",
          "function_expression",
          "method_definition"
        ]);
  while (current?.parent) {
    if (scopeTypes.has(current.type)) {
      return current;
    }
    current = current.parent;
  }
  return node.tree.rootNode;
}

function scopeForNode(node: Parser.SyntaxNode): Pick<LocalBinding, "scopeStartIndex" | "scopeEndIndex"> {
  let current: Parser.SyntaxNode | null = node;
  while (current?.parent) {
    if (
      [
        "module",
        "block",
        "program",
        "statement_block",
        "switch_body",
        "for_statement",
        "for_in_statement",
        "for_of_statement",
        "catch_clause",
        "arrow_function",
        "function_declaration",
        "function_expression",
        "method_definition",
        "class_definition",
        "while_statement",
        "if_statement",
        "try_statement",
        "with_statement"
      ].includes(current.type)
    ) {
      return { scopeStartIndex: current.startIndex, scopeEndIndex: current.endIndex };
    }
    current = current.parent;
  }
  return { scopeStartIndex: node.tree.rootNode.startIndex, scopeEndIndex: node.tree.rootNode.endIndex };
}

function visit(node: Parser.SyntaxNode, callback: (node: Parser.SyntaxNode) => void): void {
  callback(node);
  for (const child of node.namedChildren) {
    visit(child, callback);
  }
}

function resolveLanguage(filePath: string, languageId?: string): AstLanguage | undefined {
  const normalizedLanguageId = languageId?.toLowerCase();
  if (normalizedLanguageId === "python") {
    return "python";
  }
  if (normalizedLanguageId === "typescriptreact") {
    return "tsx";
  }
  if (normalizedLanguageId === "typescript") {
    return "typescript";
  }
  if (normalizedLanguageId === "javascript" || normalizedLanguageId === "javascriptreact") {
    return "javascript";
  }
  const extension = filePath.toLowerCase().split(".").at(-1);
  if (extension === "py") {
    return "python";
  }
  if (extension === "tsx") {
    return "tsx";
  }
  if (extension === "ts") {
    return "typescript";
  }
  if (["js", "jsx", "mjs", "cjs"].includes(extension ?? "")) {
    return "javascript";
  }
  return undefined;
}

function grammarFor(language: AstLanguage): Promise<Parser.Language> {
  const existing = grammars.get(language);
  if (existing) {
    return existing;
  }
  const grammar = initializeParser().then(() => Parser.Language.load(path.join(assetDirectory(), grammarFiles[language])));
  grammars.set(language, grammar);
  return grammar;
}

function initializeParser(): Promise<void> {
  if (!parserInitialization) {
    parserInitialization = Parser.init({
      locateFile: () => runtimeWasmPath()
    });
  }
  return parserInitialization;
}

function assetDirectory(): string {
  const bundled = path.join(__dirname, "tree-sitter");
  if (fs.existsSync(path.join(bundled, grammarFiles.javascript))) {
    return bundled;
  }
  return path.resolve(__dirname, "../../../node_modules/tree-sitter-wasms/out");
}

function runtimeWasmPath(): string {
  const bundled = path.join(assetDirectory(), "tree-sitter.wasm");
  if (fs.existsSync(bundled)) {
    return bundled;
  }
  return path.resolve(__dirname, "../../../node_modules/web-tree-sitter/tree-sitter.wasm");
}

function emptyResult(): AstSastResult {
  return {
    candidates: [],
    handledRuleIds: new Set()
  };
}
