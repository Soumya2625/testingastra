(() => {
  const $ = (selector) => document.querySelector(selector);
  let apiKey = "";
  let selectedScan = null;
  let currentFindings = [];
  let conversationId = null;
  let pollTimer = null;
  const labels = { secrets: "Secret Detection", iac: "IaC Misconfiguration", sast: "Static Analysis" };

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(path, { ...options, headers });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
  }

  function showMessage(message, isError = true) {
    const target = $("#scan-message");
    target.textContent = message;
    target.style.color = isError ? "var(--red)" : "var(--teal)";
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[char]);
  }

  async function refreshConfig() {
    try {
      const config = await api("/api/config");
      $("#gemini-status").textContent = config.gemini_configured ? `Gemini · ${config.model}` : "Gemini not configured";
      $("#gemini-status").className = `pill ${config.gemini_configured ? "ready" : "offline"}`;
    } catch (error) {
      $("#gemini-status").textContent = error.message;
      $("#gemini-status").className = "pill offline";
    }
  }

  async function refreshHistory() {
    if (!apiKey) return;
    try {
      const scans = await api("/api/scans");
      const selectedRepository = $("#filter-repository").value;
      const repositories = [...new Set(scans.map((scan) => scan.repository))];
      $("#filter-repository").innerHTML = '<option value="">All repositories</option>' +
        repositories.map((repository) => `<option value="${escapeHtml(repository)}">${escapeHtml(repository)}</option>`).join("");
      $("#filter-repository").value = repositories.includes(selectedRepository) ? selectedRepository : "";
      $("#scan-history").innerHTML = scans.length ? scans.map((scan) => `
        <button class="history-item ${scan.id === selectedScan ? "active" : ""}" data-scan="${escapeHtml(scan.id)}">
          <span><b>${escapeHtml(scan.repository)}</b><small>${escapeHtml(scan.branch)} · ${new Date(scan.started_at).toLocaleString()}</small></span>
          <span class="history-status">${escapeHtml(scan.status.replaceAll("_", " "))}</span>
        </button>`).join("") : '<span class="empty">No scans yet.</span>';
      document.querySelectorAll(".history-item").forEach((item) => item.addEventListener("click", () => loadScan(item.dataset.scan)));
    } catch (error) {
      showMessage(error.message);
    }
  }

  async function loadScan(id) {
    selectedScan = id;
    conversationId = sessionStorage.getItem(`astra-chat:${id}`);
    $("#chat-messages").innerHTML = conversationId
      ? '<div class="chat-message assistant">Loading saved conversation…</div>'
      : '<div class="chat-message assistant">Ask a question about this scan. Responses are based on scanner findings.</div>';
    try {
      const data = await api(`/api/scans/${encodeURIComponent(id)}`);
      const scan = data.scan;
      currentFindings = data.findings;
      $("#active-scan").classList.toggle("hidden", !["queued", "running"].includes(scan.status));
      $("#result-context").textContent = `${scan.repository} · ${scan.branch} · ${scan.status.replaceAll("_", " ")}`;
      $("#duration").textContent = `Duration: ${scan.duration_seconds == null ? "—" : `${scan.duration_seconds.toFixed(1)}s`} · Scanned files: ${scan.scanned_files} · Status: ${scan.status.replaceAll("_", " ")}`;
      if (scan.commit_sha) $("#duration").textContent += ` · Commit: ${scan.commit_sha.slice(0, 12)}`;
      if (scan.error) $("#duration").textContent += ` · Error: ${scan.error}`;
      $("#download-report").disabled = false;
      $("#stat-total").textContent = currentFindings.length;
      for (const severity of ["critical", "high", "medium", "low"]) {
        $(`#stat-${severity}`).textContent = currentFindings.filter((finding) => finding.severity === severity).length;
      }
      $("#stat-files").textContent = scan.scanned_files ?? "—";
      const statuses = typeof scan.scanner_status === "string" ? JSON.parse(scan.scanner_status || "{}") : scan.scanner_status;
      $("#scanner-progress").innerHTML = Object.entries(statuses || {}).map(([name, status]) => {
        const state = String(status).split(":")[0];
        const detail = String(status).includes(":") ? ` — ${String(status).slice(String(status).indexOf(":") + 1).trim()}` : "";
        return `<span class="progress-item ${escapeHtml(state)}">${escapeHtml(labels[name] || name)}: ${escapeHtml(state)}${escapeHtml(detail)}</span>`;
      }).join("");
      renderFindings();
      if (conversationId && !["queued", "running"].includes(scan.status)) {
        try {
          const saved = await api(`/api/scans/${encodeURIComponent(id)}/chat/${encodeURIComponent(conversationId)}`);
          $("#chat-messages").innerHTML = saved.messages.map((message) =>
            `<div class="chat-message ${message.role === "user" ? "user" : "assistant"}">${escapeHtml(message.text)}</div>`).join("");
        } catch (error) {
          sessionStorage.removeItem(`astra-chat:${id}`);
          conversationId = null;
          $("#chat-messages").innerHTML = `<div class="chat-message assistant error">${escapeHtml(error.message)}</div>`;
        }
      }
      await refreshHistory();
      if (["queued", "running"].includes(scan.status)) {
        $("#active-scan").classList.remove("hidden");
        $("#active-title").textContent = scan.status === "queued" ? "Scan queued" : "Scan in progress";
        $("#active-meta").textContent = `${scan.repository} · ${scan.branch}`;
        if (pollTimer) clearTimeout(pollTimer);
        pollTimer = setTimeout(() => loadScan(id), 2500);
      } else if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
    } catch (error) {
      showMessage(error.message);
    }
  }

  function renderFindings() {
    const severity = $("#filter-severity").value;
    const scanner = $("#filter-scanner").value;
    const status = $("#filter-status").value;
    const repository = $("#filter-repository").value;
    const file = $("#filter-file").value.trim().toLowerCase();
    const findings = currentFindings.filter((item) =>
      (!severity || item.severity === severity) && (!scanner || item.scanner === scanner) &&
      (!status || item.status === status) && (!repository || repository === $("#result-context").textContent.split(" · ")[0]) &&
      (!file || item.file_path.toLowerCase().includes(file)));
    $("#finding-list").classList.toggle("empty", !findings.length);
    $("#finding-list").innerHTML = findings.length ? findings.map((item) => `
      <button class="finding-row" data-finding="${escapeHtml(item.finding_id)}">
        <span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
        <span class="finding-main"><b>${escapeHtml(item.description)}</b><small>${escapeHtml(item.file_path)}${item.line ? `:${escapeHtml(item.line)}` : ""} · ${escapeHtml(item.rule_id)}</small></span>
        <span class="finding-meta">${escapeHtml(labels[item.scanner] || item.scanner)}</span>
        <span class="finding-meta">${escapeHtml(item.status.replaceAll("_", " "))}</span>
      </button>`).join("") : `<span class="empty">${selectedScan ? "No findings match these filters." : "No scan selected yet."}</span>`;
    document.querySelectorAll(".finding-row").forEach((row) => row.addEventListener("click", () => {
      const finding = currentFindings.find((item) => item.finding_id === row.dataset.finding);
      if (finding) showFinding(finding);
    }));
  }

  function showFinding(item) {
    $("#finding-detail").innerHTML = `
      <div class="eyebrow">${escapeHtml(labels[item.scanner] || item.scanner)} · ${escapeHtml(item.rule_id)}</div>
      <h2 class="detail-title">${escapeHtml(item.description)}</h2>
      <div class="detail-grid">
        <div class="detail-field"><label>Severity</label><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span></div>
        <div class="detail-field"><label>Verification</label><span>${escapeHtml(item.verification_status)}</span></div>
        <div class="detail-field"><label>File and line</label><span>${escapeHtml(item.file_path)}${item.line ? `:${escapeHtml(item.line)}` : ""}</span></div>
        <div class="detail-field"><label>Confidence · CWE</label><span>${escapeHtml(item.confidence)}${item.cwe ? ` · ${escapeHtml(item.cwe)}` : ""}</span></div>
        ${item.resource ? `<div class="detail-field"><label>Resource</label><span>${escapeHtml(item.resource)}</span></div>` : ""}
        ${item.evidence ? `<div class="detail-field"><label>Masked evidence</label><span>${escapeHtml(item.evidence)}</span></div>` : ""}
      </div>
      <div class="detail-section"><h4>Finding</h4><p>${escapeHtml(item.description)} ${item.verification_status === "potential" ? "This is a potential risk and requires manual verification." : ""}</p></div>
      <div class="detail-section"><h4>Recommended remediation</h4><p>${escapeHtml(item.remediation)}</p></div>
      <label class="detail-status">Finding status: <select id="finding-status">${["open", "in_progress", "resolved", "accepted_risk"].map((state) => `<option value="${state}" ${item.status === state ? "selected" : ""}>${state.replaceAll("_", " ")}</option>`).join("")}</select></label>`;
    $("#finding-dialog").showModal();
    $("#finding-status").addEventListener("change", async (event) => {
      try {
        await api(`/api/scans/${encodeURIComponent(selectedScan)}/findings/${encodeURIComponent(item.finding_id)}`, {
          method: "PATCH", body: JSON.stringify({ status: event.target.value }),
        });
        item.status = event.target.value;
        renderFindings();
      } catch (error) {
        showMessage(error.message);
      }
    });
  }

  async function startScan() {
    if (!apiKey) {
      apiKey = window.prompt("Enter the Astra API key (held in memory only):") || "";
      if (!apiKey) return;
    }
    const scanners = Object.fromEntries([...document.querySelectorAll("[data-scanner]")].map((input) => [input.dataset.scanner, input.checked]));
    const request = {
      repository: $("#repository").value.trim(),
      branch: $("#branch").value.trim(),
      repository_token: $("#repo-token").value || null,
      scanners,
    };
    $("#start-scan").disabled = true;
    showMessage("Creating scan…", false);
    try {
      const result = await api("/api/scans", { method: "POST", body: JSON.stringify(request) });
      $("#repo-token").value = "";
      selectedScan = result.scan_id;
      await loadScan(result.scan_id);
      showMessage("Scan created.", false);
    } catch (error) {
      showMessage(error.message);
      if (error.message.includes("API key")) apiKey = "";
    } finally {
      $("#start-scan").disabled = false;
    }
  }

  async function sendChat(question) {
    if (!apiKey) {
      apiKey = window.prompt("Enter the Astra API key (held in memory only):") || "";
      if (!apiKey) return;
    }
    if (!selectedScan) {
      $("#chat-messages").insertAdjacentHTML("beforeend", '<div class="chat-message error">Select a completed scan first.</div>');
      return;
    }
    const messages = $("#chat-messages");
    messages.querySelector(".chat-empty")?.remove();
    messages.insertAdjacentHTML("beforeend", `<div class="chat-message user">${escapeHtml(question)}</div><div class="chat-loading">Analyzing sanitized scan findings…</div>`);
    messages.scrollTop = messages.scrollHeight;
    $("#chat-input").disabled = true;
    try {
      const response = await api(`/api/scans/${encodeURIComponent(selectedScan)}/chat`, {
        method: "POST", body: JSON.stringify({ question, conversation_id: conversationId }),
      });
      conversationId = response.conversation_id;
      sessionStorage.setItem(`astra-chat:${selectedScan}`, conversationId);
      messages.querySelector(".chat-loading")?.remove();
      messages.insertAdjacentHTML("beforeend", `<div class="chat-message assistant">${escapeHtml(response.answer)}</div>`);
    } catch (error) {
      messages.querySelector(".chat-loading")?.remove();
      messages.insertAdjacentHTML("beforeend", `<div class="chat-message assistant error">${escapeHtml(error.message)}</div>`);
    } finally {
      $("#chat-input").disabled = false;
      messages.scrollTop = messages.scrollHeight;
    }
  }

  $("#start-scan").addEventListener("click", startScan);
  $("#refresh-scans").addEventListener("click", refreshHistory);
  $("#download-report").addEventListener("click", async () => {
    if (!selectedScan) return;
    try {
      const report = await api(`/api/scans/${encodeURIComponent(selectedScan)}/report`);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `astra-scan-${selectedScan}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (error) {
      showMessage(error.message);
    }
  });
  $("#filter-severity").addEventListener("change", renderFindings);
  $("#filter-scanner").addEventListener("change", renderFindings);
  $("#filter-status").addEventListener("change", renderFindings);
  $("#filter-file").addEventListener("input", renderFindings);
  $("#filter-repository").addEventListener("change", async () => {
    if (!apiKey) return;
    const scans = await api("/api/scans");
    const selected = scans.find((scan) => scan.repository === $("#filter-repository").value);
    if (selected) await loadScan(selected.id);
    else renderFindings();
  });
  $("#cancel-scan").addEventListener("click", async () => {
    if (!selectedScan) return;
    try { await api(`/api/scans/${encodeURIComponent(selectedScan)}/cancel`, { method: "POST" }); }
    catch (error) { showMessage(error.message); }
  });
  $("#assistant-toggle").addEventListener("click", () => {
    const panel = $("#assistant");
    const expanded = panel.classList.toggle("expanded") || window.innerWidth > 850;
    $("#assistant-toggle").setAttribute("aria-expanded", String(expanded));
    $("#assistant-chevron").textContent = expanded ? "−" : "+";
  });
  $("#chat-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = $("#chat-input");
    const question = input.value.trim();
    if (question) {
      input.value = "";
      sendChat(question);
    }
  });
  document.querySelectorAll(".suggestion").forEach((button) => button.addEventListener("click", () => sendChat(button.textContent)));
  if (window.innerWidth <= 850) {
    $("#assistant").classList.remove("expanded");
    $("#assistant-toggle").setAttribute("aria-expanded", "false");
    $("#assistant-chevron").textContent = "+";
  }
  refreshConfig();
})();
