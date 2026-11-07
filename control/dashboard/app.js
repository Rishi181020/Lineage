(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);

  // Agent output and tool input can hold attacker-written text, so everything goes in as text nodes.
  function el(tag, props = {}, ...kids) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (key === "class") node.className = value;
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const kid of kids.flat()) {
      if (kid !== null && kid !== undefined && kid !== false) node.append(kid);
    }
    return node;
  }

  let operatorToken = "lineage-operator-dev";
  try { operatorToken = localStorage.getItem("lineage_operator_token") || operatorToken; } catch {}

  async function api(path, options = {}) {
    const resp = await fetch(path, {
      ...options,
      headers: { Authorization: `Bearer ${operatorToken}`, ...(options.body ? { "Content-Type": "application/json" } : {}) },
    });
    if (resp.status === 401) {
      $("#auth").hidden = false;
      throw new Error("Lineage rejected the operator token.");
    }
    const text = await resp.text();
    if (!resp.ok) {
      let detail = text;
      try { detail = JSON.parse(text).detail || text; } catch {}
      throw new Error(typeof detail === "string" ? detail : `Lineage returned ${resp.status}.`);
    }
    return text ? JSON.parse(text) : null;
  }
  const post = (path, body) => api(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });

  $("#auth").addEventListener("submit", (event) => {
    event.preventDefault();
    operatorToken = $("#token").value.trim();
    try { localStorage.setItem("lineage_operator_token", operatorToken); } catch {}
    $("#auth").hidden = true;
    start();
  });

  /* ---------- setup state ---------- */

  async function checkSystem() {
    const button = $("#setup button");
    if (button) { button.disabled = true; button.textContent = "Checking…"; }
    let system;
    try {
      system = await api("/admin/system");
    } catch (error) {
      system = { model: { ready: false, problem: error.message }, runner: { ready: true } };
    }
    const problems = [system.model, system.runner].filter((part) => !part.ready).map((part) => part.problem);
    const banner = $("#setup");
    banner.hidden = !problems.length;
    banner.replaceChildren(
      el("span", {}, el("strong", {}, "Agents can't start yet. "), problems.join(" ")),
      el("button", { class: "btn", type: "button", onclick: checkSystem }, "Check again"));
    $("#start").disabled = problems.length > 0;
    if (system.runner.workspace) {
      $("#workspace").textContent = `Works on a copy of ${system.runner.workspace}. Your files aren't changed.`;
    }
    const models = system.model.models || [];
    $("#model-field").hidden = !models.length;
    const current = $("#model").value;
    $("#model").replaceChildren(...models.map((id) => el("option", { value: id }, id)));
    if (models.length) $("#model").value = models.includes(current) ? current : system.model.default;
  }

  /* ---------- agents ---------- */

  const S = { runs: [], selected: null, events: [] };

  $("#new-agent").addEventListener("submit", async (event) => {
    event.preventDefault();
    const task = $("#task").value.trim();
    if (!task) return;
    const error = $("#start-error");
    error.hidden = true;
    $("#start").disabled = true;
    $("#start").textContent = "Starting…";
    try {
      const run = await post("/admin/agents", { task, model: $("#model").value });
      S.selected = run.run_id;
      $("#task").value = "";
      await refresh();
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
    }
    $("#start").disabled = false;
    $("#start").textContent = "Start agent";
  });

  async function refresh() {
    S.runs = (await api("/admin/runs")).reverse();
    if (!S.selected && S.runs.length) S.selected = S.runs[0].run_id;
    S.events = S.selected ? await api(`/admin/runs/${S.selected}/events`) : [];
    render();
  }

  function pendingApprovals(events) {
    const resolved = new Set(events.filter((e) => e.type === "approval_resolved").map((e) => e.payload.approval_id));
    return events.filter((e) => e.type === "approval_needed" && !resolved.has(e.payload.approval_id));
  }

  const STATUS_WORD = { active: "Running", finished: "Finished", revoked: "Revoked", killed: "Killed by tripwire", stopped: "Stopped" };

  function render() {
    renderList();
    renderAgent();
  }

  function renderList() {
    const list = $("#agents");
    if (!S.runs.length) return list.replaceChildren(el("li", { class: "empty" }, "No agents yet."));
    list.replaceChildren(...S.runs.map((run) => el("li", {}, el("button", {
      type: "button",
      "aria-current": run.run_id === S.selected ? "true" : undefined,
      onclick: () => { S.selected = run.run_id; refresh().catch(showError); },
    },
      el("span", { class: "task" }, run.task || "Untitled"),
      el("span", { class: "meta" },
        el("span", { class: `pill ${run.status}` }, STATUS_WORD[run.status] || run.status),
        run.replay ? el("span", { class: "pill" }, "Replay") : null,
        new Date(run.created_at).toLocaleTimeString())))));
  }

  function summarizeTool(name, input = {}) {
    if (input.command) return { kind: "Run", what: input.command };
    if (name?.startsWith("mcp__")) {
      const [, server, tool] = name.split("__");
      const args = Object.values(input).join(" ");
      return { kind: "Tool", what: `${server}.${tool}${args ? ` ${args}` : ""}` };
    }
    const target = input.file_path || input.path || input.pattern || input.url || input.query;
    const verb = { Read: "Read", Edit: "Edit", Write: "Write", Grep: "Search", Glob: "Search", WebFetch: "Fetch", WebSearch: "Search" }[name];
    return { kind: verb || "Tool", what: target ? String(target) : name || "unknown tool" };
  }

  const cleanReason = (reason = "") =>
    reason.replace(/ at \d{4}-\d{2}-\d{2}T[^ ]+/, "").replace(/"(pkg:npm:|host:|path:|mcp:)/g, '"').replace(/^Lineage (L\w+|T\d|K0|S1|I1|C\d): /, "");

  const OUTCOME = { allow: "Allowed", ask: "Needs you", deny: "Blocked" };

  function row(kind, what, { outcome, why, cls, prose } = {}) {
    return el("li", { class: `row ${cls || ""}` },
      el("span", { class: "kind" }, kind),
      el("span", { class: `what ${prose ? "prose" : ""}` }, what),
      outcome ? el("span", { class: `outcome ${outcome}` }, OUTCOME[outcome]) : el("span"),
      why ? el("span", { class: "why" }, why) : null);
  }

  /** One feed row per thing a person cares about; lower-level events stay out of the way. */
  function feedRow(event, headless) {
    const p = event.payload || {};
    switch (event.type) {
      case "verdict": {
        // In the web app, "ask" shows as an approval card and then the answer.
        if (p.decision === "ask" && headless) return null;
        if (p.tool_name || p.tool_input) {
          const tool = summarizeTool(p.tool_name, p.tool_input);
          return row(tool.kind, tool.what, {
            outcome: p.decision, cls: p.decision === "deny" ? "deny" : "",
            why: p.decision === "allow" ? null : `${cleanReason(p.reason)}${p.rule_id ? ` (rule ${p.rule_id})` : ""}`,
          });
        }
        return row("Network", `${p.host || ""}${p.path || ""}`, { outcome: p.decision, cls: "deny", why: cleanReason(p.reason) });
      }
      case "span":
        return p.tier === "untrusted"
          ? row("Read", [el("mark", {}, "Outside content"), `${p.source.replace(/^mcp__(\w+?)__/, "$1.")}: ${p.excerpt.replace(/\\+n/g, " ").replace(/\\+"/g, '"')}`], { cls: "outside" })
          : null;
      case "agent_text": return row("Agent", p.text, { prose: true });
      case "model_error":
        return row("Model", `AWS Bedrock refused the request (${p.status})`, { outcome: "deny", cls: "deny", why: p.message });
      case "approval_needed": {
        const tool = summarizeTool(p.tool_name, p.tool_input);
        return row(tool.kind, tool.what, { outcome: "ask", why: `${cleanReason(p.reason)}${p.rule_id ? ` (rule ${p.rule_id})` : ""}` });
      }
      case "approval_resolved":
        return row("You", p.decision === "allow" ? "Approved the request." : p.reason, { prose: true });
      case "tripwire":
        return row("Tripwire", `A stand-in key headed for ${p.host}${p.path}`, { outcome: "deny", cls: "deny", why: "The real key never left. The agent was stopped." });
      case "custody_attach": return row("Key", `Real key attached for ${p.method} ${p.host}${p.path}`);
      case "egress_block": return row("Network", p.host, { outcome: "deny", why: `Rule ${p.rule}` });
      case "status":
        return p.status === "finished" ? null : row("Status", STATUS_WORD[p.status] || p.status, { prose: true });
      default: return null;
    }
  }

  function approvalCard(event) {
    const p = event.payload;
    const tool = summarizeTool(p.tool_name, p.tool_input);
    const answer = (decision) => async (click) => {
      click.currentTarget.parentElement.querySelectorAll("button").forEach((b) => { b.disabled = true; });
      try {
        await post(`/admin/runs/${S.selected}/approvals/${p.approval_id}`, { decision });
      } catch (error) {
        showError(error);
      }
      refresh().catch(showError);
    };
    return el("section", { class: "needs", "aria-label": "Waiting for your decision" },
      el("h3", {}, "The agent needs your decision"),
      el("code", { class: "cmd" }, `${tool.kind}: ${tool.what}`),
      el("p", {}, `${cleanReason(p.reason)}${p.rule_id ? ` (rule ${p.rule_id})` : ""}`),
      el("div", { class: "btn-row" },
        el("button", { class: "btn danger-solid", type: "button", onclick: answer("deny") }, "Block"),
        el("button", { class: "btn", type: "button", onclick: answer("allow") }, "Approve")));
  }

  function diffView(diff) {
    return el("pre", { class: "diff", tabindex: "0" }, diff.split("\n").map((line) => {
      const cls = line.startsWith("diff --git") ? "file" : line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : "";
      return el("span", { class: cls }, line || " ");
    }));
  }

  function renderAgent() {
    const main = $("#agent");
    const run = S.runs.find((item) => item.run_id === S.selected);
    if (!run) {
      main.replaceChildren(el("div", { class: "blank" },
        el("h2", {}, "Start your first agent"),
        el("p", {}, "Describe a task on the left. Claude Code runs it in a sealed sandbox, and you'll see every action here. Risky ones wait for your decision.")));
      return;
    }
    const nearBottom = main.scrollHeight - main.scrollTop - main.clientHeight < 160;
    const previousScroll = main.scrollTop;
    const events = S.events;
    const pending = pendingApprovals(events);
    const active = run.status === "active";

    const rows = events.map((event) => feedRow(event, run.headless)).filter(Boolean);
    const done = events.filter((e) => e.type === "agent_done").pop();
    const changes = events.filter((e) => e.type === "agent_changes").pop();
    const key = run.placeholders?.[0]?.value;
    const stateWord = pending.length ? "Waiting for you" : STATUS_WORD[run.status] || run.status;

    main.replaceChildren(...[
      el("header", { class: "agent-head" },
        el("div", {},
          el("h2", {}, run.task || "Untitled"),
          el("div", { class: "state" },
            el("span", { class: `pill ${pending.length ? "waiting" : run.status}` }, stateWord),
            key ? el("span", {}, "Holds stand-in key ", el("code", {}, `${key.slice(0, 24)}…`)) : null)),
        active ? el("button", { class: "btn danger", type: "button", onclick: () => revoke(run) }, "Revoke agent") : null),
      pending.map(approvalCard),
      rows.length || active
        ? el("ol", { class: "feed", "aria-live": "polite" }, rows,
            active && !pending.length ? el("li", { class: "working" }, "Working…") : null)
        : null,
      done ? el("section", { class: "section" },
        el("h3", {}, done.payload.ok ? "Result" : "It didn't finish"),
        el("div", { class: `result ${done.payload.ok ? "" : "failed"}` },
          done.payload.text || (done.payload.ok ? "Done." : "No details were reported."),
          done.payload.duration_ms ? el("small", {}, costLine(done.payload)) : null,
          done.payload.logs ? el("pre", {}, done.payload.logs) : null)) : null,
      changes ? el("section", { class: "section" },
        el("h3", {}, "What it changed"),
        el("p", { class: "hint", style: "margin-bottom:.5rem" }, "These changes are in the agent's copy. Your folder hasn't changed."),
        diffView(changes.payload.diff)) : null,
    ].flat().filter(Boolean));

    main.scrollTop = nearBottom ? main.scrollHeight : previousScroll;
  }

  function costLine({ duration_ms: ms, cost_usd: cost }) {
    const seconds = Math.round(ms / 1000);
    return `${seconds}s${typeof cost === "number" ? `, about $${cost.toFixed(2)}` : ""}`;
  }

  async function revoke(run) {
    if (!confirm(`Revoke this agent? It stops now and can't be restarted.\n\n${run.task}`)) return;
    try {
      await post(`/admin/runs/${run.run_id}/revoke`);
      await refresh();
    } catch (error) {
      showError(error);
    }
  }

  function showError(error) {
    const notice = $("#start-error");
    notice.textContent = error.message;
    notice.hidden = false;
  }

  /* ---------- live updates ---------- */

  let refreshQueued = false;
  function queueRefresh() {
    if (refreshQueued) return;
    refreshQueued = true;
    setTimeout(() => {
      refreshQueued = false;
      refresh().catch(showError);
    }, 150);
  }

  // EventSource can't send an Authorization header, so the stream is read with fetch.
  let streaming = false;
  async function stream() {
    if (streaming) return;
    streaming = true;
    for (;;) {
      try {
        const resp = await fetch("/admin/stream", { headers: { Authorization: `Bearer ${operatorToken}` } });
        if (!resp.ok) throw new Error(String(resp.status));
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const chunks = buffer.split("\n\n");
          buffer = chunks.pop();
          if (chunks.some((chunk) => chunk.includes("data: "))) queueRefresh();
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }

  function start() {
    checkSystem();
    refresh().catch(showError);
    stream();
  }
  start();
})();
