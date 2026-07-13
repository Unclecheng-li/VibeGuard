import type { Webview } from "vscode";

export function l3PanelHtml(webview: Webview, nonce: string): string {
  const csp = [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`
  ].join("; ");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>VibeGuard AI Deep Scan</title>
  <style nonce="${nonce}">
    :root { color: var(--vscode-foreground); font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); }
    body { margin: 0; padding: 12px; background: var(--vscode-sideBar-background); color: var(--vscode-sideBar-foreground); }
    header { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 12px; }
    h1 { font-size: 14px; font-weight: 600; margin: 0; }
    button { min-height: 28px; border: 1px solid var(--vscode-button-border, transparent); border-radius: 3px; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); cursor: pointer; font: inherit; padding: 4px 8px; }
    button:hover { background: var(--vscode-button-secondaryHoverBackground); }
    button.primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
    button.primary:hover { background: var(--vscode-button-hoverBackground); }
    button:disabled { cursor: default; opacity: 0.55; }
    #controls { display: flex; gap: 6px; margin-bottom: 12px; }
    #summary { border-top: 1px solid var(--vscode-sideBarSectionHeader-border); border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border); padding: 10px 0; }
    .meta { color: var(--vscode-descriptionForeground); font-size: 12px; line-height: 18px; overflow-wrap: anywhere; }
    .status { display: flex; align-items: center; gap: 6px; font-weight: 600; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--vscode-testing-iconPassed); flex: none; }
    .scanning .dot { background: var(--vscode-progressBar-background); animation: pulse 1s ease-in-out infinite; }
    .error .dot { background: var(--vscode-testing-iconFailed); }
    @keyframes pulse { 50% { opacity: 0.35; } }
    #notice { margin: 10px 0 0; color: var(--vscode-descriptionForeground); line-height: 18px; }
    #findings-title { display: block; margin: 14px 0 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    #findings { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--vscode-sideBarSectionHeader-border); }
    .finding { padding: 10px 0; border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border); }
    .finding-head { display: flex; align-items: baseline; gap: 6px; }
    .severity { font-size: 11px; font-weight: 700; }
    .severity.critical, .severity.high { color: var(--vscode-testing-iconFailed); }
    .severity.medium { color: var(--vscode-editorWarning-foreground); }
    .severity.low, .severity.info { color: var(--vscode-editorInfo-foreground); }
    .rule { color: var(--vscode-descriptionForeground); font-size: 11px; overflow-wrap: anywhere; }
    .message { margin: 4px 0; line-height: 18px; overflow-wrap: anywhere; }
    .location { color: var(--vscode-descriptionForeground); font-size: 12px; overflow-wrap: anywhere; }
    .actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .actions button { min-height: 24px; padding: 2px 6px; font-size: 12px; }
    #empty { margin: 12px 0; color: var(--vscode-descriptionForeground); line-height: 18px; }
  </style>
</head>
<body>
  <header><h1>AI Deep Scan</h1><button id="settings" title="Open VibeGuard settings">Settings</button></header>
  <div id="controls"><button id="scan" class="primary">Scan with AI</button><button id="configure" hidden>Configure API Key</button><button id="cancel" hidden>Cancel</button></div>
  <section id="summary" aria-live="polite">
    <div id="status" class="status"><span class="dot"></span><span>Ready</span></div>
    <div id="model" class="meta">Select a supported file to review.</div>
    <div id="stats" class="meta"></div>
    <div id="notice" hidden></div>
  </section>
  <strong id="findings-title">Findings</strong>
  <p id="empty">No AI review has run for the current file.</p>
  <ul id="findings" hidden></ul>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const elements = {
      scan: document.getElementById('scan'), configure: document.getElementById('configure'), cancel: document.getElementById('cancel'), settings: document.getElementById('settings'),
      status: document.getElementById('status'), model: document.getElementById('model'), stats: document.getElementById('stats'),
      notice: document.getElementById('notice'), findings: document.getElementById('findings'), empty: document.getElementById('empty')
    };
    let currentScanId;
    function send(message) { vscode.postMessage(message); }
    function statusLabel(status) {
      return ({ ready: 'Ready', scanning: 'Scanning', complete: 'Complete', cancelled: 'Cancelled', error: 'Review failed', notConfigured: 'Configure L3' })[status] || 'Ready';
    }
    function renderState(message) {
      const status = message.status || 'ready';
      elements.status.className = 'status ' + (status === 'scanning' ? 'scanning' : status === 'error' || status === 'notConfigured' ? 'error' : '');
      elements.status.lastChild.textContent = statusLabel(status);
      const config = message.config;
      elements.model.textContent = config ? ('Provider: ' + config.provider + ' - Model: ' + config.model) : 'Select a supported file to review.';
      const outcome = message.outcome;
      const parts = [];
      if (outcome) {
        parts.push('Source: ' + outcome.status);
        parts.push((outcome.elapsedMs / 1000).toFixed(2) + 's');
        if (outcome.usage && (outcome.usage.tokensIn !== undefined || outcome.usage.tokensOut !== undefined)) {
          parts.push('Tokens: ' + (outcome.usage.tokensIn ?? '?') + ' in / ' + (outcome.usage.tokensOut ?? '?') + ' out');
        }
      }
      elements.stats.textContent = parts.join(' - ');
      elements.notice.hidden = !message.detail;
      elements.notice.textContent = message.detail || '';
      elements.scan.disabled = status === 'scanning';
      elements.configure.hidden = !(config && !config.hasApiKey);
      elements.cancel.hidden = status !== 'scanning';
      renderFindings(message.findings || []);
    }
    function renderFindings(findings) {
      elements.findings.replaceChildren();
      elements.findings.hidden = findings.length === 0;
      elements.empty.hidden = findings.length > 0;
      if (findings.length === 0) return;
      for (const finding of findings) {
        const item = document.createElement('li'); item.className = 'finding';
        const head = document.createElement('div'); head.className = 'finding-head';
        const severity = document.createElement('span'); severity.className = 'severity ' + finding.severity; severity.textContent = finding.severity.toUpperCase();
        const rule = document.createElement('span'); rule.className = 'rule'; rule.textContent = 'L3 - ' + finding.ruleId;
        head.append(severity, rule);
        const message = document.createElement('div'); message.className = 'message'; message.textContent = finding.message;
        const location = document.createElement('div'); location.className = 'location'; location.textContent = finding.file + ':' + finding.line;
        const actions = document.createElement('div'); actions.className = 'actions';
        actions.append(actionButton('Open', 'openFinding', finding.id));
        if (finding.hasFix) actions.append(actionButton('Review & Apply Fix', 'applyFix', finding.id));
        actions.append(actionButton('Ignore', 'ignoreFinding', finding.id));
        item.append(head, message, location, actions); elements.findings.append(item);
      }
    }
    function actionButton(label, type, findingId) {
      const button = document.createElement('button'); button.textContent = label;
      button.addEventListener('click', () => {
        if (type === 'ignoreFinding') send({ type, findingId, scope: 'line' }); else send({ type, findingId });
      });
      return button;
    }
    elements.scan.addEventListener('click', () => send({ type: 'scan' }));
    elements.configure.addEventListener('click', () => send({ type: 'configureApiKey' }));
    elements.cancel.addEventListener('click', () => currentScanId && send({ type: 'cancelScan', scanId: currentScanId }));
    elements.settings.addEventListener('click', () => send({ type: 'openSettings' }));
    window.addEventListener('message', (event) => {
      const message = event.data;
      if (!message || typeof message.type !== 'string') return;
      if (message.type === 'scanStarted') { currentScanId = message.scanId; renderState({ status: 'scanning', findings: [] }); return; }
      if (message.type === 'scanComplete') { currentScanId = undefined; renderState({ status: 'complete', findings: message.findings, outcome: message.outcome }); return; }
      if (message.type === 'scanCancelled') { currentScanId = undefined; renderState({ status: 'cancelled', findings: [], detail: 'The review was cancelled.' }); return; }
      if (message.type === 'scanError') { currentScanId = undefined; renderState({ status: message.code === 'notConfigured' ? 'notConfigured' : 'error', findings: [], detail: message.message }); return; }
      if (message.type === 'state') renderState(message);
    });
  </script>
</body>
</html>`;
}
