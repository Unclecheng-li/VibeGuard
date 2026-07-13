import type * as vscode from "vscode";
import type { Finding, L3ReviewOutcome, LlmProvider, Severity } from "../types";

export interface L3PanelConfig {
  provider: LlmProvider;
  model: string;
  hasApiKey: boolean;
  remoteReviewApproved: boolean;
  endpoint: string;
}

export interface PanelFinding {
  id: string;
  severity: Severity;
  ruleId: string;
  message: string;
  file: string;
  line: number;
  evidence: string;
  suggestion?: string;
  hasFix: boolean;
}

export interface L3PanelReviewResult {
  outcome: L3ReviewOutcome;
  findings: PanelFinding[];
  stale: boolean;
}

export interface L3PanelHost {
  activeDocument(): vscode.TextDocument | undefined;
  config(document: vscode.TextDocument): Promise<L3PanelConfig>;
  approveRemoteReview(config: L3PanelConfig): Promise<boolean>;
  review(document: vscode.TextDocument, signal: AbortSignal): Promise<L3PanelReviewResult>;
  finding(document: vscode.TextDocument, findingId: string): Finding | undefined;
  openFinding(finding: Finding): Promise<void>;
  applyFindingFix(finding: Finding): Promise<void>;
  ignoreFinding(finding: Finding, scope: "line" | "file" | "global"): Promise<void>;
  configureApiKey(): Promise<void>;
  openSettings(): Promise<void>;
}

export type PanelRequest =
  | { type: "scan" }
  | { type: "cancelScan"; scanId: string }
  | { type: "openFinding"; findingId: string }
  | { type: "applyFix"; findingId: string }
  | { type: "ignoreFinding"; findingId: string; scope: "line" | "file" | "global" }
  | { type: "configureApiKey" }
  | { type: "openSettings" };

export type PanelMessage =
  | { type: "state"; config?: L3PanelConfig; findings: PanelFinding[]; status: PanelStatus; detail?: string; outcome?: L3ReviewOutcome }
  | { type: "scanStarted"; scanId: string }
  | { type: "scanComplete"; scanId: string; outcome: L3ReviewOutcome; findings: PanelFinding[] }
  | { type: "scanCancelled"; scanId: string }
  | { type: "scanError"; scanId: string; code: "notConfigured" | "consentRequired" | "remoteFailed"; message: string };

export type PanelStatus = "ready" | "scanning" | "complete" | "cancelled" | "error" | "notConfigured";

export function panelFinding(finding: Finding): PanelFinding {
  return {
    id: finding.id,
    severity: finding.severity,
    ruleId: finding.detection_rule,
    message: finding.message,
    file: finding.file,
    line: finding.line,
    evidence: finding.evidence,
    suggestion: finding.suggestion,
    hasFix: Boolean(finding.fix)
  };
}

export function parsePanelRequest(value: unknown): PanelRequest | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const input = value as Record<string, unknown>;
  if (input.type === "scan" || input.type === "configureApiKey" || input.type === "openSettings") {
    return { type: input.type };
  }
  if (input.type === "cancelScan" && isId(input.scanId)) {
    return { type: "cancelScan", scanId: input.scanId };
  }
  if ((input.type === "openFinding" || input.type === "applyFix") && isId(input.findingId)) {
    return { type: input.type, findingId: input.findingId };
  }
  if (input.type === "ignoreFinding" && isId(input.findingId) && isIgnoreScope(input.scope)) {
    return { type: "ignoreFinding", findingId: input.findingId, scope: input.scope };
  }
  return undefined;
}

function isId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 200;
}

function isIgnoreScope(value: unknown): value is "line" | "file" | "global" {
  return value === "line" || value === "file" || value === "global";
}
