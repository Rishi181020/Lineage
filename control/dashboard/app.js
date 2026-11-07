(() => {
  const tokenInput = document.getElementById("token");
  tokenInput.value = localStorage.getItem("lineage_operator_token") || "lineage-operator-dev";
  tokenInput.addEventListener("change", () => {
    localStorage.setItem("lineage_operator_token", tokenInput.value);
    boot();
  });

  let selected = null;
  let runs = [];

  function authHeaders() {
    return { Authorization: `Bearer ${tokenInput.value}` };
  }

  async function refreshRuns() {
    const resp = await fetch("/admin/runs", { headers: authHeaders() });
    if (!resp.ok) throw new Error("auth failed");
    runs = await resp.json();
    const list = document.getElementById("run-list");
    list.innerHTML = "";
    for (const run of runs) {
      const el = document.createElement("div");
      el.className = "run" + (selected === run.run_id ? " selected" : "");
      el.innerHTML = `
        <div><strong>${run.run_id}</strong> · ${run.status}${run.replay ? " · REPLAY" : ""}</div>
        <div>${run.task || "(no task)"}</div>
        <div>mode=${run.mode} jti=${(run.token_jti || "").slice(0, 8)}…</div>
        <div>mcp: ${(run.mcp_allow || []).join(", ")}</div>
        <button data-act="select">Select</button>
        <button data-act="revoke">Revoke</button>
        <button data-act="stop">Stop</button>
      `;
      el.querySelector('[data-act="select"]').onclick = () => {
        selected = run.run_id;
        paintTrifecta(run);
        paintCustody(run);
        refreshRuns();
      };
      el.querySelector('[data-act="revoke"]').onclick = () =>
        fetch(`/admin/runs/${run.run_id}/revoke`, { method: "POST", headers: authHeaders() }).then(refreshRuns);
      el.querySelector('[data-act="stop"]').onclick = () =>
        fetch(`/admin/runs/${run.run_id}/stop`, { method: "POST", headers: authHeaders() }).then(refreshRuns);
      list.appendChild(el);
    }
    if (selected) {
      const current = runs.find((r) => r.run_id === selected);
      if (current) {
        paintTrifecta(current);
        paintCustody(current);
      }
    }
  }

  function paintTrifecta(run) {
    for (const leg of ["untrusted", "private", "external"]) {
      document.getElementById(`leg-${leg}`).classList.toggle("on", !!(run.legs || {})[leg]);
    }
    document.getElementById("strict").classList.toggle("on", !!run.strict);
  }

  function paintCustody(run) {
    const lines = (run.placeholders || []).map(
      (p) => `${p.binding_id}: ${p.value}`
    );
    document.getElementById("custody-view").textContent =
      lines.join("\n") || "No placeholders";
  }

  function appendEvent(ev) {
    const row = document.createElement("div");
    const decision = (ev.payload && ev.payload.decision) || "";
    row.className = `row ${ev.type} ${decision}`;
    if (ev.replay) row.classList.add("replay");
    row.textContent = `${ev.run_id} · ${ev.type} · ${JSON.stringify(ev.payload).slice(0, 180)}`;
    row.onclick = () => {
      document.getElementById("chain-view").textContent = JSON.stringify(ev, null, 2);
    };
    const feed = document.getElementById("events");
    feed.prepend(row);
  }

  function connectStream() {
    // EventSource cannot set Authorization; use fetch streaming.
    fetch("/admin/stream", { headers: authHeaders() }).then(async (resp) => {
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const chunks = buf.split("\n\n");
        buf = chunks.pop();
        for (const chunk of chunks) {
          const line = chunk.split("\n").find((l) => l.startsWith("data: "));
          if (!line) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            appendEvent(ev);
            if (ev.run_id) {
              selected = selected || ev.run_id;
              refreshRuns();
            }
          } catch (_) {}
        }
      }
    }).catch(() => setTimeout(connectStream, 2000));
  }

  async function boot() {
    try {
      await refreshRuns();
      connectStream();
    } catch (err) {
      document.getElementById("run-list").textContent = String(err);
    }
  }

  // Serve static assets: FastAPI needs routes — fallback fetch relative works if mounted.
  boot();
  setInterval(refreshRuns, 5000);
})();
