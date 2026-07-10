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

const javascriptRuleIds = new Set([
  "sast_sql_template_interpolation",
  "sast_sql_string_concat",
  "sast_xss_inner_html",
  "sast_xss_document_write",
  "sast_ssrf_fetch_user_url",
  "sast_path_traversal_fs_user_input",
  "sast_command_injection_os_system",
  "sast_open_redirect_user_input",
  "sast_information_leakage_error_details"
]);

const pythonRuleIds = new Set([
  "sast_sql_python_f_string_execute",
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

  try {
    const grammar = await grammarFor(language);
    const parser = new Parser();
    parser.setLanguage(grammar);
    const tree = parser.parse(text);
    if (tree.rootNode.hasError()) {
      parser.delete();
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

    if (language === "python") {
      visit(tree.rootNode, (node) => analyzePythonNode(node, add));
    } else {
      visit(tree.rootNode, (node) => analyzeJavaScriptNode(node, add));
    }
    tree.delete();
    parser.delete();
    return {
      candidates,
      handledRuleIds: language === "python" ? pythonRuleIds : javascriptRuleIds
    };
  } catch {
    return emptyResult();
  }
}

function analyzeJavaScriptNode(node: Parser.SyntaxNode, add: (ruleId: string, node: Parser.SyntaxNode) => void): void {
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
    if (/\.(?:innerHTML|outerHTML)$/.test(left) && !/^\s*(?:DOMPurify|sanitizeHtml|sanitize)\b/i.test(right)) {
      add("sast_xss_inner_html", node);
    }
  }

  if (node.type !== "call_expression") {
    return;
  }
  if (/^\s*document\.write\s*\(/.test(text)) {
    add("sast_xss_document_write", node);
  }
  if (/^\s*(?:fetch|axios\.(?:get|post)|http\.get)\s*\(/i.test(text) && hasJavaScriptUserInput(text)) {
    add("sast_ssrf_fetch_user_url", node);
  }
  if (/^\s*(?:fs\.(?:readFile|readFileSync|createReadStream)|open)\s*\(/i.test(text) && hasJavaScriptUserInput(text)) {
    add("sast_path_traversal_fs_user_input", node);
  }
  if (/^\s*(?:child_process\.)?exec\s*\(/i.test(text) && (hasJavaScriptUserInput(text) || /\$\{/.test(text))) {
    add("sast_command_injection_os_system", node);
  }
  if (/^\s*(?:res|response)\.redirect\s*\(/i.test(text) && hasJavaScriptUserInput(text)) {
    add("sast_open_redirect_user_input", node);
  }
  if (
    /^\s*(?:res|response)\.(?:send|json)\s*\([^;]*(?:err(?:or)?|exception)\.(?:stack|message)/i.test(text) ||
    /^\s*(?:res|response)\.status\s*\(\s*500\s*\)\.(?:send|json)\s*\([^;]*(?:err(?:or)?|exception)\.(?:stack|message)/i.test(text)
  ) {
    add("sast_information_leakage_error_details", node);
  }
}

function analyzePythonNode(node: Parser.SyntaxNode, add: (ruleId: string, node: Parser.SyntaxNode) => void): void {
  if (node.type !== "call") {
    return;
  }
  const text = node.text;
  if (/\bexecute\s*\([\s\S]*\bf["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{[^}]+}[^"']*["']/i.test(text)) {
    add("sast_sql_python_f_string_execute", node);
  }
  if (/^\s*(?:requests\.(?:get|post)|http\.get)\s*\(/i.test(text) && hasPythonUserInput(text)) {
    add("sast_ssrf_fetch_user_url", node);
  }
  if (/^\s*(?:open|Path|send_file)\s*\(/.test(text) && (hasPythonUserInput(text) || /\bparams?\s*\[/.test(text))) {
    add("sast_path_traversal_fs_user_input", node);
  }
  if (/^\s*pickle\.loads?\s*\(/.test(text) && hasPythonUserInput(text)) {
    add("sast_insecure_deserialization_pickle", node);
  }
  if (/^\s*yaml\.load\s*\(/.test(text) && hasPythonUserInput(text) && !/SafeLoader/.test(text)) {
    add("sast_insecure_deserialization_yaml", node);
  }
  if (/^\s*(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(/.test(text) && (hasPythonUserInput(text) || /\{[^}]+}/.test(text))) {
    add("sast_command_injection_os_system", node);
  }
  if (/^\s*redirect\s*\(/.test(text) && hasPythonUserInput(text)) {
    add("sast_open_redirect_user_input", node);
  }
  if (/^\s*(?:traceback\.format_exc|str)\s*\(/.test(text) && /\b(?:err(?:or)?|exception|e)\b/i.test(text)) {
    add("sast_information_leakage_error_details", node);
  }
}

function hasJavaScriptUserInput(text: string): boolean {
  return /\breq\.(?:query|body|params)\b/i.test(text);
}

function hasPythonUserInput(text: string): boolean {
  return /\brequest\.(?:args|form|json)\b|\b(?:request|input|body|data)\b/i.test(text);
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
