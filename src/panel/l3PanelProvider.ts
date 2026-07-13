import { randomUUID } from "node:crypto";
import * as vscode from "vscode";
import type { Finding, L3ReviewOutcome } from "../types";
import { l3PanelHtml } from "./l3PanelHtml";
import {
  type L3PanelConfig,
  type L3PanelHost,
  type PanelRequest,
  type PanelFinding,
  type PanelMessage,
  type PanelStatus,
  parsePanelRequest
} from "./l3PanelTypes";

export class L3PanelProvider implements vscode.WebviewViewProvider, vscode.Disposable {
  private view: vscode.WebviewView | undefined;
  private readonly disposables: vscode.Disposable[] = [];
  private scan: { id: string; controller: AbortController; document: vscode.TextDocument } | undefined;
  private findings: PanelFinding[] = [];
  private findingsDocument: vscode.TextDocument | undefined;
  private config: L3PanelConfig | undefined;
  private status: PanelStatus = "ready";
  private detail: string | undefined;
  private scanRequested = false;
  private preparingScan = false;

  constructor(private readonly host: L3PanelHost) {}

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: []
    };
    webviewView.webview.html = l3PanelHtml(webviewView.webview, randomUUID().replace(/-/g, ""));
    this.disposables.push(
      webviewView.webview.onDidReceiveMessage((message) => {
        const request = parsePanelRequest(message);
        if (request) {
          void this.handle(request);
        }
      }),
      webviewView.onDidDispose(() => {
        if (this.view === webviewView) {
          this.scan?.controller.abort();
          this.view = undefined;
        }
      })
    );
    void this.refresh();
    if (this.scanRequested) {
      this.scanRequested = false;
      void this.startScan();
    }
  }

  async triggerScan(): Promise<void> {
    if (!this.view) {
      this.scanRequested = true;
      await vscode.commands.executeCommand("workbench.view.extension.vibeguard");
      return;
    }
    await this.startScan();
  }

  dispose(): void {
    this.scan?.controller.abort();
    for (const disposable of this.disposables.splice(0)) {
      disposable.dispose();
    }
  }

  cancelDocument(document: vscode.TextDocument): void {
    if (this.scan?.document.uri.toString() === document.uri.toString()) {
      this.scan.controller.abort();
    }
  }

  private async handle(request: PanelRequest): Promise<void> {
    switch (request.type) {
      case "scan":
        await this.startScan();
        return;
      case "cancelScan":
        if (this.scan?.id === request.scanId) {
          this.scan.controller.abort();
        }
        return;
      case "openFinding":
        await this.withFinding(request.findingId, (finding) => this.host.openFinding(finding));
        return;
      case "applyFix":
        await this.withFinding(request.findingId, async (finding) => {
          await this.host.applyFindingFix(finding);
          this.findings = this.findings.filter((candidate) => candidate.id !== finding.id);
          this.sendState();
        });
        return;
      case "ignoreFinding":
        await this.withFinding(request.findingId, async (finding) => {
          await this.host.ignoreFinding(finding, request.scope);
          this.findings = this.findings.filter((candidate) => candidate.id !== finding.id);
          this.sendState();
        });
        return;
      case "configureApiKey":
        await this.host.configureApiKey();
        await this.refresh();
        return;
      case "openSettings":
        await this.host.openSettings();
        return;
    }
  }

  private async startScan(): Promise<void> {
    if (this.scan || this.preparingScan) {
      return;
    }
    this.preparingScan = true;
    try {
      await this.startScanInternal();
    } catch {
      this.status = "error";
      this.detail = "The review could not be prepared. Check the VibeGuard output channel for details.";
      this.sendState();
    } finally {
      this.preparingScan = false;
    }
  }

  private async startScanInternal(): Promise<void> {
    if (this.scan) {
      return;
    }
    const document = this.host.activeDocument();
    if (!document) {
      this.status = "error";
      this.detail = "Open a supported file before starting an AI deep scan.";
      this.sendState();
      return;
    }
    this.config = await this.host.config(document);
    if (!this.config.hasApiKey) {
      this.status = "notConfigured";
      this.detail = "Configure an API key for the selected provider before running a remote review.";
      this.sendState();
      return;
    }
    if (this.config.provider !== "local" && !this.config.remoteReviewApproved) {
      const approved = await this.host.approveRemoteReview(this.config);
      if (!approved) {
        this.status = "ready";
        this.detail = "Remote review was not started.";
        this.sendState();
        return;
      }
      this.config = await this.host.config(document);
    }

    const scan = {
      id: randomUUID(),
      controller: new AbortController(),
      document
    };
    this.scan = scan;
    this.status = "scanning";
    this.detail = `Reviewing the current file with ${this.config.model}.`;
    this.post({ type: "scanStarted", scanId: scan.id });
    this.sendState();

    try {
      const result = await this.host.review(document, scan.controller.signal);
      if (this.scan?.id !== scan.id) {
        return;
      }
      this.scan = undefined;
      if (result.stale) {
        this.status = "cancelled";
        this.detail = "The file changed while the review was running, so its result was discarded.";
        this.post({ type: "scanCancelled", scanId: scan.id });
        this.sendState();
        return;
      }
      if (result.outcome.status === "cancelled") {
        this.status = "cancelled";
        this.detail = "The review was cancelled.";
        this.post({ type: "scanCancelled", scanId: scan.id });
        this.sendState();
        return;
      }
      if (result.outcome.status === "notConfigured" || result.outcome.status === "consentRequired" || result.outcome.status === "failed") {
        const code = result.outcome.errorCode ?? "remoteFailed";
        const message = statusMessage(result.outcome.status);
        this.status = result.outcome.status === "notConfigured" ? "notConfigured" : "error";
        this.detail = message;
        this.post({ type: "scanError", scanId: scan.id, code, message });
        this.sendState();
        return;
      }
      this.findings = result.findings;
      this.findingsDocument = document;
      this.status = "complete";
      this.detail = result.outcome.status === "localFallback" ? "Remote review failed; local semantic analysis was used instead." : undefined;
      this.post({ type: "scanComplete", scanId: scan.id, outcome: result.outcome, findings: result.findings });
      this.sendState(result.outcome);
    } catch {
      if (this.scan?.id === scan.id) {
        this.scan = undefined;
        this.status = "error";
        this.detail = "The review could not be completed. Check the VibeGuard output channel for details.";
        this.post({ type: "scanError", scanId: scan.id, code: "remoteFailed", message: this.detail });
        this.sendState();
      }
    }
  }

  private async withFinding(findingId: string, action: (finding: Finding) => Promise<void>): Promise<void> {
    const document = this.scan?.document ?? this.findingsDocument ?? this.host.activeDocument();
    if (!document) {
      return;
    }
    const finding = this.host.finding(document, findingId);
    if (finding) {
      await action(finding);
    }
  }

  private async refresh(): Promise<void> {
    const document = this.host.activeDocument();
    if (!document) {
      this.config = undefined;
      this.findings = [];
      this.findingsDocument = undefined;
      this.status = "ready";
      this.detail = "Open a supported file to review it with AI.";
      this.sendState();
      return;
    }
    this.config = await this.host.config(document);
    this.sendState();
  }

  private sendState(outcome?: L3ReviewOutcome): void {
    this.post({
      type: "state",
      config: this.config,
      findings: this.findings,
      status: this.status,
      detail: this.detail,
      outcome
    });
  }

  private post(message: PanelMessage): void {
    void this.view?.webview.postMessage(message);
  }
}

function statusMessage(status: "notConfigured" | "consentRequired" | "failed"): string {
  if (status === "notConfigured") {
    return "Configure an API key for the selected provider before running a remote review.";
  }
  if (status === "consentRequired") {
    return "Remote review requires your approval before code is sent to the selected provider.";
  }
  return "The remote review failed and no local result is available. Check the VibeGuard output channel for details.";
}
