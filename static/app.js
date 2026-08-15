const form = document.querySelector("#run-form");
const promptEl = document.querySelector("#prompt");
const runBtn = document.querySelector("#run-btn");
const clearBtn = document.querySelector("#clear-btn");
const responsePane = document.querySelector("#response-pane");
const steeringList = document.querySelector("#steering-list");
const auditBody = document.querySelector("#audit-body");
const auditEmpty = document.querySelector("#audit-empty");
const auditCount = document.querySelector("#audit-count");
const scenarioList = document.querySelector("#scenario-list");
const vendorList = document.querySelector("#vendor-list");
const blockedList = document.querySelector("#blocked-list");
const identifierList = document.querySelector("#identifier-list");
const statusStamp = document.querySelector("#status-stamp");
const statusValue = document.querySelector("#status-value");
const modelName = document.querySelector("#model-name");

function setStatus(state) {
  statusStamp.dataset.state = state;
  statusValue.textContent = state;
}

function setResponse(text, state) {
  responsePane.dataset.state = state;
  responsePane.classList.toggle("empty", state === "empty");
  if (state === "empty") {
    responsePane.innerHTML = `<p class="empty-copy">${text}</p>`;
    return;
  }
  if (state === "loading") {
    responsePane.textContent = "";
    return;
  }
  responsePane.textContent = text;
}

function renderSteering(events) {
  steeringList.replaceChildren();
  for (const event of events || []) {
    const li = document.createElement("li");
    li.className = `event ${event.event || ""}`;
    const flag = event.event === "BLOCKED" ? "BLOCK" : "ALLOW";
    li.innerHTML = `
      <span class="event-flag">${flag}</span>
      <div>
        <p class="event-rule">${event.rule || "Steering"}</p>
        <p class="event-meta">${event.tool || "agent"}</p>
        <p class="event-reason">${event.reason || "PHI check passed."}</p>
      </div>
    `;
    steeringList.append(li);
  }
}

function renderAudit(entries) {
  auditBody.replaceChildren();
  const rows = entries || [];
  auditEmpty.hidden = rows.length > 0;
  auditCount.textContent = rows.length
    ? `${rows.length} ${rows.length === 1 ? "entry" : "entries"}`
    : "No entries yet.";

  for (const entry of rows) {
    const tr = document.createElement("tr");
    if (entry.blocked) tr.className = "blocked-row";
    const inputs = JSON.stringify(entry.inputs_sanitized || {}, null, 2);
    tr.innerHTML = `
      <td data-label="Time">${entry.timestamp || ""}</td>
      <td data-label="Status"><span class="status ${entry.blocked ? "blocked" : "allowed"}">${entry.blocked ? "BLOCK" : "ALLOW"}</span></td>
      <td data-label="Tool"><code>${entry.tool || ""}</code></td>
      <td data-label="Action">${entry.action || ""}</td>
      <td data-label="Masked inputs">
        <details class="audit-inputs">
          <summary>Show</summary>
          <pre class="mono">${inputs}</pre>
        </details>
      </td>
    `;
    auditBody.append(tr);
  }
}

function applyRun(data) {
  const status = data.status || (data.ok ? "READY" : "ERROR");
  setStatus(status);
  const paneState = !data.ok ? "error" : status === "BLOCKED" ? "blocked" : "ready";
  setResponse(data.response || "No response.", paneState);
  renderSteering(data.steering || []);
  renderAudit(data.audit || []);
}

function renderConfig(config) {
  if (config.model) modelName.textContent = config.model;
  scenarioList.replaceChildren();
  for (const scenario of config.scenarios || []) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "scenario";
    button.dataset.prompt = scenario.prompt;
    button.innerHTML = `
      <span class="chip ${scenario.outcome === "BLOCK" ? "chip-block" : "chip-allow"}">${scenario.outcome}</span>
      <span>${scenario.label}</span>
    `;
    button.addEventListener("click", () => {
      for (const item of scenarioList.querySelectorAll(".scenario")) {
        item.setAttribute("aria-pressed", "false");
      }
      button.setAttribute("aria-pressed", "true");
      promptEl.value = scenario.prompt;
      promptEl.focus();
    });
    scenarioList.append(button);
  }

  vendorList.replaceChildren();
  for (const vendor of config.vendors || []) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${vendor.name}</span><code>${vendor.id}</code>`;
    vendorList.append(li);
  }

  blockedList.replaceChildren();
  for (const channel of config.blocked_channels || []) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${channel}</span><code>blocked</code>`;
    blockedList.append(li);
  }

  identifierList.replaceChildren();
  for (const item of config.identifiers || []) {
    const li = document.createElement("li");
    li.textContent = item;
    identifierList.append(li);
  }

  renderAudit(config.audit || []);

  if (config.last && config.last.response) {
    promptEl.value = config.last.prompt || promptEl.value;
    applyRun({
      ok: config.last.ok,
      status: config.last.status,
      response: config.last.response,
      steering: config.last.steering,
      audit: config.audit,
    });
  }

  if (!config.configured) {
    setStatus("ERROR");
    setResponse(
      "API key not configured. Add OPENCODE_GO_API_KEY to .env, then restart the server.",
      "error"
    );
    runBtn.disabled = true;
  }
}

async function loadConfig() {
  const res = await fetch("/api/config");
  renderConfig(await res.json());
}

async function runPrompt() {
  const prompt = promptEl.value.trim();
  if (!prompt) {
    promptEl.focus();
    return;
  }
  setStatus("RUNNING");
  setResponse("", "loading");
  runBtn.disabled = true;
  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });
    applyRun(await res.json());
  } catch (error) {
    setStatus("ERROR");
    setResponse(String(error), "error");
  } finally {
    runBtn.disabled = false;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runPrompt();
});

promptEl.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    event.preventDefault();
    runPrompt();
  }
});

clearBtn.addEventListener("click", async () => {
  promptEl.value = "";
  renderSteering([]);
  setStatus("READY");
  setResponse(
    "Run a scenario or type a request. The steering log will show ALLOW or BLOCK.",
    "empty"
  );
  await fetch("/api/clear", { method: "POST" });
  renderAudit([]);
  for (const item of scenarioList.querySelectorAll(".scenario")) {
    item.setAttribute("aria-pressed", "false");
  }
  promptEl.focus();
});

loadConfig();
