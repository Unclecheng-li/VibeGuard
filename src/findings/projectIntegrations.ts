export interface ProjectIntegrationsDashboardOptions {
  title?: string;
}

/** Renders the admin-only browser workflow for scoped CI ingest credentials. */
export function formatProjectIntegrationsDashboard(options: ProjectIntegrationsDashboardOptions = {}): string {
  const title = options.title ?? "VibeGuard Project Integrations";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --blue: #2266cc;
      --blue-hover: #174d9e;
      --red: #bd2828;
      --red-hover: #962020;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      line-height: 1.45;
    }
    main { width: min(1040px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 40px; }
    header { display: flex; align-items: flex-end; justify-content: space-between; gap: 18px; margin-bottom: 28px; }
    h1, h2, p { margin: 0; }
    h1 { font-size: 30px; font-weight: 760; letter-spacing: 0; }
    h2 { font-size: 16px; font-weight: 720; }
    .meta { color: var(--muted); font-size: 13px; }
    .back-link { color: var(--blue); font-size: 13px; font-weight: 650; text-decoration: none; }
    .back-link:hover { text-decoration: underline; }
    section { border-top: 1px solid var(--line); padding: 20px 0; }
    section:last-of-type { border-bottom: 1px solid var(--line); }
    form { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; margin-top: 12px; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; font-weight: 650; }
    input, textarea {
      width: 100%; height: 38px; border: 1px solid #aeb8c6; border-radius: 6px; background: var(--panel);
      color: var(--ink); font: inherit; padding: 0 10px;
    }
    textarea { min-height: 220px; padding: 10px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; line-height: 1.45; }
    input:focus, textarea:focus { outline: 2px solid #9fc2f5; outline-offset: 1px; border-color: var(--blue); }
    button {
      min-height: 38px; border: 1px solid var(--blue); border-radius: 6px; background: var(--blue); color: #fff;
      cursor: pointer; font: inherit; font-size: 13px; font-weight: 700; padding: 0 12px; white-space: nowrap;
    }
    button:hover { background: var(--blue-hover); border-color: var(--blue-hover); }
    button.secondary { background: var(--panel); color: var(--blue); }
    button.secondary:hover { background: #edf4ff; }
    button.danger { background: var(--panel); border-color: #dc9d9d; color: var(--red); }
    button.danger:hover { background: #fff0f0; border-color: var(--red-hover); color: var(--red-hover); }
    .table-wrap { overflow-x: auto; margin-top: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 11px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
    th { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .project, code { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    .project { overflow-wrap: anywhere; }
    .actions { display: flex; justify-content: flex-end; gap: 8px; }
    .token-output {
      display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 10px; align-items: center; margin-top: 12px;
      padding: 12px; border: 1px solid #8ecbac; border-radius: 6px; background: #f2fbf6;
    }
    .token-output code { min-width: 0; overflow-wrap: anywhere; color: #075a35; font-size: 13px; }
    .workflow-output { position: relative; margin-top: 12px; border: 1px solid var(--line); border-radius: 6px; background: #f9fafc; }
    .workflow-output pre { margin: 0; overflow-x: auto; padding: 14px 14px 52px; font: 12px/1.5 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    .workflow-output button { position: absolute; right: 10px; bottom: 10px; }
    .rules-form { grid-template-columns: minmax(0, 1fr); }
    .rules-actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
    #status { min-height: 20px; margin-top: 10px; color: var(--muted); font-size: 13px; }
    #status.error { color: var(--red); }
    .empty { color: var(--muted); padding: 18px 8px; font-size: 13px; }
    @media (max-width: 640px) {
      main { width: min(100% - 24px, 1040px); padding-top: 20px; }
      header { align-items: flex-start; flex-direction: column; }
      form, .token-output { grid-template-columns: 1fr; }
      .actions { justify-content: flex-start; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>${escapeHtml(title)}</h1>
        <p class="meta">Project-scoped CI credentials</p>
      </div>
      <a class="back-link" href="/">Security dashboard</a>
    </header>

    <section aria-labelledby="create-heading">
      <h2 id="create-heading">Create Credential</h2>
      <form id="create-form">
        <label>Project identifier<input id="project-input" name="project" autocomplete="off" maxlength="256" required></label>
        <button type="submit">Create credential</button>
      </form>
      <p id="status" role="status" aria-live="polite"></p>
    </section>

    <section id="token-section" hidden aria-labelledby="token-heading">
      <h2 id="token-heading">New Credential</h2>
      <div class="token-output">
        <code id="token-value"></code>
        <button id="copy-token" class="secondary" type="button">Copy token</button>
      </div>
    </section>

    <section id="workflow-section" hidden aria-labelledby="workflow-heading">
      <h2 id="workflow-heading">GitHub Action</h2>
      <div class="workflow-output">
        <pre><code id="workflow-value"></code></pre>
        <button id="copy-workflow" class="secondary" type="button">Copy workflow</button>
      </div>
    </section>

    <section aria-labelledby="rules-heading">
      <h2 id="rules-heading">Project Custom Rules</h2>
      <form id="rules-form" class="rules-form">
        <label>Project identifier<input id="rules-project-input" name="project" autocomplete="off" maxlength="256" required></label>
        <label>Rules YAML<textarea id="rules-yaml-input" name="yaml" spellcheck="false" required></textarea></label>
        <div class="rules-actions">
          <button id="insert-rule-template" class="secondary" type="button">Insert template</button>
          <button type="submit">Save rules</button>
        </div>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Project</th><th>Rules</th><th>Updated</th><th></th></tr></thead>
          <tbody id="rules-body"></tbody>
        </table>
      </div>
      <div id="rules-empty" class="empty" hidden>No project custom rules configured.</div>
    </section>

    <section aria-labelledby="projects-heading">
      <h2 id="projects-heading">Project Credentials</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Project</th><th>Created</th><th>Last rotated</th><th></th></tr></thead>
          <tbody id="projects-body"></tbody>
        </table>
      </div>
      <div id="empty" class="empty" hidden>No project credentials configured.</div>
    </section>
  </main>
  <script>
    const form = document.getElementById("create-form");
    const projectInput = document.getElementById("project-input");
    const status = document.getElementById("status");
    const projectsBody = document.getElementById("projects-body");
    const empty = document.getElementById("empty");
    const tokenSection = document.getElementById("token-section");
    const tokenValue = document.getElementById("token-value");
    const copyToken = document.getElementById("copy-token");
    const workflowSection = document.getElementById("workflow-section");
    const workflowValue = document.getElementById("workflow-value");
    const copyWorkflow = document.getElementById("copy-workflow");
    const rulesForm = document.getElementById("rules-form");
    const rulesProjectInput = document.getElementById("rules-project-input");
    const rulesYamlInput = document.getElementById("rules-yaml-input");
    const insertRuleTemplate = document.getElementById("insert-rule-template");
    const rulesBody = document.getElementById("rules-body");
    const rulesEmpty = document.getElementById("rules-empty");

    function setStatus(message, error) {
      status.textContent = message;
      status.classList.toggle("error", Boolean(error));
    }

    async function request(path, init) {
      const response = await fetch(path, Object.assign({ credentials: "same-origin" }, init));
      if (!response.ok) {
        const detail = (await response.text()).trim();
        throw new Error(detail || "Request failed.");
      }
      return response.json();
    }

    async function requestText(path) {
      const response = await fetch(path, { credentials: "same-origin" });
      if (!response.ok) {
        const detail = (await response.text()).trim();
        throw new Error(detail || "Request failed.");
      }
      return response.text();
    }

    function timestamp(value) {
      const date = new Date(value);
      return Number.isNaN(date.valueOf()) ? "Unknown" : date.toLocaleString();
    }

    function actionButton(label, className, onClick) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.className = className;
      button.addEventListener("click", onClick);
      return button;
    }

    function renderProjects(projects) {
      projectsBody.replaceChildren();
      empty.hidden = projects.length !== 0;
      for (const project of projects) {
        const row = document.createElement("tr");
        const projectCell = document.createElement("td");
        projectCell.className = "project";
        projectCell.textContent = project.project;
        const createdCell = document.createElement("td");
        createdCell.textContent = timestamp(project.createdAt);
        const updatedCell = document.createElement("td");
        updatedCell.textContent = timestamp(project.updatedAt);
        const actionCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(
          actionButton("Rotate", "secondary", () => rotate(project.project)),
          actionButton("Revoke", "danger", () => revoke(project.project))
        );
        actionCell.append(actions);
        row.append(projectCell, createdCell, updatedCell, actionCell);
        projectsBody.append(row);
      }
    }

    function renderRules(projects) {
      rulesBody.replaceChildren();
      rulesEmpty.hidden = projects.length !== 0;
      for (const project of projects) {
        const row = document.createElement("tr");
        const projectCell = document.createElement("td");
        projectCell.className = "project";
        projectCell.textContent = project.project;
        const countCell = document.createElement("td");
        countCell.textContent = String(project.ruleCount);
        const updatedCell = document.createElement("td");
        updatedCell.textContent = timestamp(project.updatedAt);
        const actionCell = document.createElement("td");
        const actions = document.createElement("div");
        actions.className = "actions";
        actions.append(
          actionButton("Edit", "secondary", () => editRules(project.project)),
          actionButton("Delete", "danger", () => deleteRules(project.project))
        );
        actionCell.append(actions);
        row.append(projectCell, countCell, updatedCell, actionCell);
        rulesBody.append(row);
      }
    }

    function showCredential(credential) {
      tokenValue.textContent = credential.token;
      tokenSection.hidden = false;
      workflowValue.textContent = workflowSnippet(credential.project);
      workflowSection.hidden = false;
      setStatus(credential.created ? "Credential created." : "Credential rotated.");
    }

    function workflowSnippet(project) {
      const endpoint = new URL("/api/ingest", window.location.origin).toString();
      const rulesEndpoint = new URL("/api/project-rules/download", window.location.origin);
      rulesEndpoint.searchParams.set("project", project);
      return [
        "name: VibeGuard Security Scan",
        "on: [pull_request]",
        "jobs:",
        "  scan:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: vibeguard/action@v1",
        "        with:",
        "          findings_project: " + JSON.stringify(project),
        "          findings_endpoint: " + endpoint,
        "          findings_token_env: VIBEGUARD_FINDINGS_INGEST_TOKEN",
        "          findings_rules_endpoint: " + rulesEndpoint.toString(),
        "        env:",
        "          VIBEGUARD_FINDINGS_INGEST_TOKEN: $" + "{{ secrets.VIBEGUARD_FINDINGS_INGEST_TOKEN }}"
      ].join("\\n");
    }

    async function loadProjects() {
      try {
        const projects = await request("/api/projects");
        renderProjects(projects);
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not load project credentials.", true);
      }
    }

    async function loadRules() {
      try {
        renderRules(await request("/api/project-rules"));
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not load project custom rules.", true);
      }
    }

    async function issue(project, rotate) {
      const credential = await request("/api/projects", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ project, rotate })
      });
      showCredential(credential);
      await loadProjects();
    }

    async function rotate(project) {
      if (!window.confirm("Rotate this project credential? Existing CI jobs will stop uploading until updated.")) {
        return;
      }
      try {
        await issue(project, true);
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not rotate credential.", true);
      }
    }

    async function revoke(project) {
      if (!window.confirm("Revoke this project credential? Existing CI jobs will stop uploading.")) {
        return;
      }
      try {
        await request("/api/projects?project=" + encodeURIComponent(project), { method: "DELETE" });
        if (tokenSection.hidden === false) {
          tokenSection.hidden = true;
          tokenValue.textContent = "";
          workflowSection.hidden = true;
          workflowValue.textContent = "";
        }
        setStatus("Credential revoked.");
        await loadProjects();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not revoke credential.", true);
      }
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const project = projectInput.value.trim();
      if (!project) {
        return;
      }
      try {
        await issue(project, false);
        projectInput.value = "";
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not create credential.", true);
      }
    });

    async function editRules(project) {
      try {
        const endpoint = "/api/project-rules/download?project=" + encodeURIComponent(project);
        rulesProjectInput.value = project;
        rulesYamlInput.value = await requestText(endpoint);
        rulesYamlInput.focus();
        setStatus("Loaded project custom rules.");
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not load project custom rules.", true);
      }
    }

    async function deleteRules(project) {
      if (!window.confirm("Delete this project's custom rules? CI scans will use only local rules afterward.")) {
        return;
      }
      try {
        await request("/api/project-rules?project=" + encodeURIComponent(project), { method: "DELETE" });
        if (rulesProjectInput.value.trim() === project) {
          rulesYamlInput.value = "";
        }
        setStatus("Project custom rules deleted.");
        await loadRules();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not delete project custom rules.", true);
      }
    }

    rulesForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const project = rulesProjectInput.value.trim();
      const yaml = rulesYamlInput.value;
      if (!project || !yaml.trim()) {
        return;
      }
      try {
        await request("/api/project-rules", {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ project, yaml })
        });
        setStatus("Project custom rules saved.");
        await loadRules();
      } catch (error) {
        setStatus(error instanceof Error ? error.message : "Could not save project custom rules.", true);
      }
    });

    insertRuleTemplate.addEventListener("click", () => {
      rulesYamlInput.value = [
        "rules:",
        "  - id: company_example_rule",
        "    pattern: example-insecure-setting",
        "    severity: medium",
        "    type: insecure_config",
        "    layer: L1",
        "    message: Replace this setting with the approved company configuration.",
        "    languages: [javascript, typescript]"
      ].join("\\n") + "\\n";
      rulesYamlInput.focus();
    });

    copyToken.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(tokenValue.textContent || "");
        copyToken.textContent = "Copied";
        window.setTimeout(() => { copyToken.textContent = "Copy token"; }, 1500);
      } catch {
        setStatus("Could not copy credential.", true);
      }
    });

    copyWorkflow.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(workflowValue.textContent || "");
        copyWorkflow.textContent = "Copied";
        window.setTimeout(() => { copyWorkflow.textContent = "Copy workflow"; }, 1500);
      } catch {
        setStatus("Could not copy workflow.", true);
      }
    });

    void loadProjects();
    void loadRules();
  </script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
