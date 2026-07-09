import path from "path";
import * as vscode from "vscode";
import {
  appendIgnoreRule,
  defaultIgnoreRulesPath,
  ensureIgnoreRulesFile,
  expandHome,
  loadIgnoreRules
} from "./ignore";
import { JsonPackageCache } from "./package/cache";
import { PackageVerifier } from "./package/packageVerifier";
import { scanSourceFile } from "./scanner";
import type { Finding, Severity } from "./types";

const supportedLanguageIds = new Set([
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "python",
  "json",
  "toml"
]);

let diagnostics: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;
let packageVerifier: PackageVerifier;
const timers = new Map<string, NodeJS.Timeout>();
const findingsByUri = new Map<string, Finding[]>();
const popupSeen = new Set<string>();

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("vibeguard");
  output = vscode.window.createOutputChannel("VibeGuard");
  findingsProvider = new FindingsProvider(findingsByUri);
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 92);
  statusBar.command = "vibeguard.openReport";
  statusBar.text = "VibeGuard";
  statusBar.tooltip = "VibeGuard security findings";
  statusBar.show();

  const cachePath = path.join(context.globalStorageUri.fsPath, "package-cache.json");
  packageVerifier = new PackageVerifier({
    cache: new JsonPackageCache(cachePath)
  });

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,
    vscode.window.registerTreeDataProvider("vibeguardFindings", findingsProvider),
    vscode.commands.registerCommand("vibeguard.scanCurrentFile", () => scanCurrentFile()),
    vscode.commands.registerCommand("vibeguard.scanWorkspace", () => scanWorkspace()),
    vscode.commands.registerCommand("vibeguard.clearFindings", () => clearFindings()),
    vscode.commands.registerCommand("vibeguard.openReport", () => openReport()),
    vscode.commands.registerCommand("vibeguard.openIgnoreRules", () => openIgnoreRules()),
    vscode.commands.registerCommand("vibeguard.openFinding", (finding: Finding) => openFinding(finding)),
    vscode.commands.registerCommand("vibeguard.ignoreFinding", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "line")
    ),
    vscode.commands.registerCommand("vibeguard.ignoreRuleInFile", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "file")
    ),
    vscode.commands.registerCommand("vibeguard.ignoreRuleGlobally", (nodeOrFinding: TreeNode | Finding) =>
      ignoreFinding(resolveFindingArgument(nodeOrFinding), "global")
    ),
    vscode.commands.registerCommand("vibeguard.ignorePackage", (nodeOrFinding: TreeNode | Finding) =>
      ignorePackage(resolveFindingArgument(nodeOrFinding))
    ),
    vscode.workspace.onDidOpenTextDocument((document) => scheduleScan(document, 0)),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (configuration().get<boolean>("scanOnChange", true)) {
        scheduleScan(event.document, 180);
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (configuration().get<boolean>("scanOnSave", true)) {
        scheduleScan(document, 0);
      }
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        scheduleScan(editor.document, 0);
      }
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    scheduleScan(document, 0);
  }
}

export function deactivate(): void {
  for (const timer of timers.values()) {
    clearTimeout(timer);
  }
  timers.clear();
}

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage("VibeGuard: no active editor to scan.");
    return;
  }
  await scanDocument(editor.document);
}

async function scanWorkspace(): Promise<void> {
  const files = await vscode.workspace.findFiles(
    "**/*.{js,jsx,ts,tsx,mjs,cjs,py,json,toml,txt}",
    "**/{node_modules,.git,out,dist,build,coverage}/**",
    500
  );

  statusBar.text = "$(shield) VibeGuard scanning...";
  let scanned = 0;
  for (const uri of files) {
    const document = await vscode.workspace.openTextDocument(uri);
    await scanDocument(document);
    scanned += 1;
  }
  updateStatus();
  void vscode.window.showInformationMessage(`VibeGuard scanned ${scanned} files.`);
}

function clearFindings(): void {
  findingsByUri.clear();
  diagnostics.clear();
  findingsProvider.refresh();
  popupSeen.clear();
  updateStatus();
}

async function openReport(): Promise<void> {
  const allFindings = allCurrentFindings();
  output.clear();
  output.appendLine("VibeGuard Findings");
  output.appendLine("==================");
  if (allFindings.length === 0) {
    output.appendLine("No findings.");
  } else {
    for (const finding of allFindings) {
      output.appendLine(
        `${finding.severity.toUpperCase()} ${finding.file}:${finding.line}:${finding.column} ${finding.message}`
      );
      output.appendLine(`  Rule: ${finding.detection_rule} (${finding.detection_layer})`);
      output.appendLine(`  Evidence: ${finding.evidence}`);
      if (finding.suggestion) {
        output.appendLine(`  Suggestion: ${finding.suggestion}`);
      }
      output.appendLine("");
    }
  }
  output.show();
}

async function openIgnoreRules(): Promise<void> {
  const filePath = await ensureIgnoreRulesFile(ignoreRulesPath());
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
  await vscode.window.showTextDocument(document);
}

async function openFinding(finding: Finding): Promise<void> {
  const uri = vscode.Uri.file(finding.file);
  const document = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(document);
  const range = findingRange(finding);
  editor.selection = new vscode.Selection(range.start, range.end);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

function scheduleScan(document: vscode.TextDocument, delayMs: number): void {
  if (!isSupportedDocument(document)) {
    return;
  }
  const key = document.uri.toString();
  const existing = timers.get(key);
  if (existing) {
    clearTimeout(existing);
  }
  timers.set(
    key,
    setTimeout(() => {
      timers.delete(key);
      void scanDocument(document);
    }, delayMs)
  );
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  if (!isSupportedDocument(document) || !configuration().get<boolean>("enabled", true)) {
    return;
  }

  const packageVerification = configuration().get<"off" | "seed" | "remote">("packageVerification", "seed");
  const enableL2 = configuration().get<boolean>("enableL2", true);
  const ignoreRules = await loadIgnoreRules(ignoreRulesPath());
  const result = await scanSourceFile(
    {
      filePath: document.uri.fsPath,
      text: document.getText(),
      languageId: document.languageId
    },
    {
      packageVerification,
      includeSast: enableL2,
      packageVerifier,
      ignoreRules
    }
  );

  findingsByUri.set(document.uri.toString(), result.findings);
  diagnostics.set(document.uri, result.findings.filter((finding) => !finding.dismissed).map(findingToDiagnostic));
  findingsProvider.refresh();
  updateStatus();
  maybeShowCriticalPopup(document, result.findings);
}

function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(findingRange(finding), finding.message, toDiagnosticSeverity(finding.severity));
  diagnostic.code = finding.detection_rule;
  diagnostic.source = "VibeGuard";
  if (finding.suggestion) {
    diagnostic.message = `${finding.message} ${finding.suggestion}`;
  }
  return diagnostic;
}

function findingRange(finding: Finding): vscode.Range {
  const startLine = Math.max(0, finding.line - 1);
  const startColumn = Math.max(0, finding.column - 1);
  const endLine = Math.max(startLine, (finding.endLine ?? finding.line) - 1);
  const endColumn = Math.max(startColumn + 1, (finding.endColumn ?? finding.column + finding.evidence.length) - 1);
  return new vscode.Range(startLine, startColumn, endLine, endColumn);
}

function toDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    case "info":
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function maybeShowCriticalPopup(document: vscode.TextDocument, findings: Finding[]): void {
  if (!configuration().get<boolean>("showCriticalPopups", true)) {
    return;
  }
  const critical = findings.find((finding) => finding.severity === "critical" && !finding.dismissed && !popupSeen.has(finding.id));
  if (!critical) {
    return;
  }
  popupSeen.add(critical.id);
  const replace = critical.fix?.description;
  const actions = replace ? [replace, "Ignore", "Manage Ignore Rules"] : ["Ignore", "Manage Ignore Rules"];
  void vscode.window.showWarningMessage(`VibeGuard: ${critical.message}`, ...actions).then(async (choice) => {
    if (choice === replace && critical.fix) {
      const edit = new vscode.WorkspaceEdit();
      for (const textEdit of critical.fix.edits) {
        edit.replace(
          document.uri,
          new vscode.Range(
            textEdit.startLine - 1,
            textEdit.startColumn - 1,
            textEdit.endLine - 1,
            textEdit.endColumn - 1
          ),
          textEdit.newText
        );
      }
      await vscode.workspace.applyEdit(edit);
    } else if (choice === "Ignore") {
      await ignoreFinding(critical, "line");
      await scanDocument(document);
    } else if (choice === "Manage Ignore Rules") {
      await openIgnoreRules();
    }
  });
}

function updateStatus(): void {
  const findings = allCurrentFindings().filter((finding) => !finding.dismissed);
  if (findings.length === 0) {
    statusBar.text = "$(shield) VibeGuard: clean";
    statusBar.tooltip = "No VibeGuard findings";
    return;
  }

  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const high = findings.filter((finding) => finding.severity === "high").length;
  statusBar.text = `$(shield) VibeGuard: ${findings.length}`;
  statusBar.tooltip = `${findings.length} finding(s), ${critical} critical, ${high} high`;
}

function allCurrentFindings(): Finding[] {
  return [...findingsByUri.values()].flat().sort((a, b) => {
    const severityOrder: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4
    };
    return severityOrder[a.severity] - severityOrder[b.severity] || a.file.localeCompare(b.file) || a.line - b.line;
  });
}

async function ignoreFinding(finding: Finding | undefined, scope: "line" | "file" | "global"): Promise<void> {
  if (!finding) {
    return;
  }

  await appendIgnoreRule(
    {
      rule: finding.detection_rule,
      path: scope === "global" ? undefined : finding.file,
      line: scope === "line" ? finding.line : undefined,
      reason:
        scope === "line"
          ? "Ignored from VSCode finding"
          : scope === "file"
            ? "Ignored rule in this file from VSCode"
            : "Ignored rule globally from VSCode"
    },
    ignoreRulesPath()
  );
  await refreshOpenDocuments();
  void vscode.window.showInformationMessage("VibeGuard ignore rule added.");
}

async function ignorePackage(finding: Finding | undefined): Promise<void> {
  if (!finding || finding.type !== "hallucinated_package") {
    void vscode.window.showInformationMessage("VibeGuard: this finding is not a package finding.");
    return;
  }
  const registry = finding.detection_rule.replace(/^hallucinated_package_/, "") as "npm" | "pypi";
  await appendIgnoreRule(
    {
      package: finding.evidence,
      registry,
      reason: "Ignored package from VSCode"
    },
    ignoreRulesPath()
  );
  await refreshOpenDocuments();
  void vscode.window.showInformationMessage(`VibeGuard will ignore package "${finding.evidence}".`);
}

async function refreshOpenDocuments(): Promise<void> {
  for (const document of vscode.workspace.textDocuments) {
    if (isSupportedDocument(document)) {
      await scanDocument(document);
    }
  }
}

function resolveFindingArgument(nodeOrFinding: TreeNode | Finding | undefined): Finding | undefined {
  if (!nodeOrFinding) {
    return undefined;
  }
  if ("kind" in nodeOrFinding) {
    return nodeOrFinding.kind === "finding" ? nodeOrFinding.finding : undefined;
  }
  return nodeOrFinding;
}

function ignoreRulesPath(): string {
  const configured = configuration().get<string>("ignoreRulesPath", "").trim();
  return configured ? expandHome(configured) : defaultIgnoreRulesPath();
}

function isSupportedDocument(document: vscode.TextDocument): boolean {
  if (document.uri.scheme !== "file" && document.uri.scheme !== "untitled") {
    return false;
  }
  if (supportedLanguageIds.has(document.languageId)) {
    return true;
  }
  return /(?:package\.json|requirements\.txt|pyproject\.toml)$/i.test(document.fileName);
}

function configuration(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("vibeguard");
}

class FindingsProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly emitter = new vscode.EventEmitter<TreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly store: Map<string, Finding[]>) {}

  refresh(): void {
    this.emitter.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element.kind === "group") {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.Expanded);
      item.contextValue = "vibeguardSeverityGroup";
      return item;
    }

    const item = new vscode.TreeItem(`${element.finding.message} (${path.basename(element.finding.file)}:${element.finding.line})`);
    item.description = element.finding.dismissed ? `${element.finding.severity} dismissed` : element.finding.severity;
    item.tooltip = element.finding.dismissed
      ? `${element.finding.dismissed_reason ?? "Dismissed"}\n${element.finding.suggestion ?? element.finding.evidence}`
      : element.finding.suggestion ?? element.finding.evidence;
    item.command = {
      command: "vibeguard.openFinding",
      title: "Open Finding",
      arguments: [element.finding]
    };
    item.contextValue = "vibeguardFinding";
    item.iconPath = element.finding.dismissed ? new vscode.ThemeIcon("pass") : severityIcon(element.finding.severity);
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    const findings = [...this.store.values()].flat();
    if (!element) {
      return (["critical", "high", "medium", "low", "info"] as Severity[])
        .map((severity) => ({
          kind: "group" as const,
          severity,
          label: `${capitalize(severity)} (${findings.filter((finding) => finding.severity === severity).length})`
        }))
        .filter((group) => !group.label.endsWith("(0)"));
    }
    if (element.kind === "group") {
      return findings
        .filter((finding) => finding.severity === element.severity)
        .map((finding) => ({
          kind: "finding" as const,
          finding
        }));
    }
    return [];
  }
}

type TreeNode =
  | {
      kind: "group";
      severity: Severity;
      label: string;
    }
  | {
      kind: "finding";
      finding: Finding;
    };

function severityIcon(severity: Severity): vscode.ThemeIcon {
  if (severity === "critical" || severity === "high") {
    return new vscode.ThemeIcon("error");
  }
  if (severity === "medium") {
    return new vscode.ThemeIcon("warning");
  }
  return new vscode.ThemeIcon("info");
}

function capitalize(value: string): string {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}
