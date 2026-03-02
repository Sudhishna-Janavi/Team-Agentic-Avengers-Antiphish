const API_BASE = "http://127.0.0.1:8000";

const tips = [
  {
    title: "Check Domain Shape",
    body: "Look for extra subdomains and misspelled brand names before entering credentials.",
  },
  {
    title: "Never Trust Urgency",
    body: "Phishing links often force urgency like account suspension or immediate verification.",
  },
  {
    title: "Preview Before Click",
    body: "Hover links from messages and emails. Compare the true destination with expected domain.",
  },
  {
    title: "Report Fast",
    body: "Early reporting helps responders flag malicious patterns faster.",
  },
];

const state = {
  lastScannedUrl: "",
  reports: [],
};

const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const riskGauge = document.getElementById("risk-gauge");
const riskScore = document.getElementById("risk-score");
const riskLabel = document.getElementById("risk-label");
const resultUrl = document.getElementById("result-url");
const reasonList = document.getElementById("reason-list");
const apiStatus = document.getElementById("api-status");
const reportCount = document.getElementById("report-count");
const openReport = document.getElementById("open-report");
const reportModal = document.getElementById("report-modal");
const reportForm = document.getElementById("report-form");
const cancelReport = document.getElementById("cancel-report");
const reportUrl = document.getElementById("report-url");
const refreshIntel = document.getElementById("refresh-intel");
const intelBody = document.getElementById("intel-body");
const confidencePill = document.getElementById("confidence-pill");
const explainSummary = document.getElementById("explain-summary");
const contributors = document.getElementById("contributors");
const refreshDashboard = document.getElementById("refresh-dashboard");
const kpiTotal = document.getElementById("kpi-total");
const kpiReporter = document.getElementById("kpi-reporter");
const kpiDomain = document.getElementById("kpi-domain");
const reporterBars = document.getElementById("reporter-bars");
const domainBars = document.getElementById("domain-bars");
const hourlyBars = document.getElementById("hourly-bars");
const alertsList = document.getElementById("alerts-list");
const streamStatus = document.getElementById("stream-status");
const demoButtons = document.querySelectorAll(".demo-btn");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function colorForScore(score) {
  if (score >= 67) return "var(--danger)";
  if (score >= 34) return "var(--accent-2)";
  return "var(--accent)";
}

function readableRiskLabel(label) {
  if (label === "high") return "High Risk";
  if (label === "medium") return "Medium Risk";
  return "Low Risk";
}

function setGauge(score) {
  const pct = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  const color = colorForScore(pct);
  riskGauge.style.background = `conic-gradient(${color} ${pct}%, #143147 ${pct}%)`;
  riskScore.textContent = `${pct}%`;
}

function setReasons(messages) {
  if (!messages.length) {
    reasonList.innerHTML = "<li>No signals returned.</li>";
    return;
  }
  reasonList.innerHTML = messages.map((msg) => `<li>${escapeHtml(msg)}</li>`).join("");
}

function renderSignalCards(signals) {
  contributors.innerHTML = "";

  if (!signals.length) {
    contributors.innerHTML = "<p>No signal details available.</p>";
    return;
  }

  signals.forEach((signal) => {
    const card = document.createElement("article");
    const sev = String(signal.severity || "info").toLowerCase();
    const impact = sev === "high" ? "high" : sev === "medium" ? "medium" : "low";
    card.className = "signal-card";
    card.innerHTML = `
      <div class="signal-head">
        <span class="signal-name">${escapeHtml(String(signal.id || "signal"))}</span>
        <span class="impact-pill impact-${impact}">${escapeHtml(sev)}</span>
      </div>
      <p class="signal-note">${escapeHtml(String(signal.message || ""))}</p>
    `;
    contributors.appendChild(card);
  });
}

function updateLocalReportCount() {
  reportCount.textContent = `Reports: ${state.reports.length}`;
  kpiTotal.textContent = String(state.reports.length);
}

function renderLocalIntel() {
  if (!state.reports.length) {
    intelBody.innerHTML = '<tr><td colspan="5">No reports yet.</td></tr>';
    return;
  }

  intelBody.innerHTML = state.reports
    .slice()
    .reverse()
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.time)}</td>
        <td>${escapeHtml(item.url)}</td>
        <td>${escapeHtml(item.reason)}</td>
        <td>${escapeHtml(item.reporterType)}</td>
        <td>${escapeHtml(item.reporterUser)}</td>
      </tr>
    `
    )
    .join("");
}

function setLegacySectionsState() {
  streamStatus.textContent = "Stream: unavailable in minimal backend";
  streamStatus.style.borderColor = "#5f7f98";
  alertsList.innerHTML = "<li>Live stream is disabled in this minimal backend.</li>";

  refreshIntel.disabled = true;
  refreshIntel.textContent = "Local Feed";

  refreshDashboard.disabled = true;
  refreshDashboard.textContent = "Local Only";

  kpiReporter.textContent = "n/a";
  kpiDomain.textContent = "n/a";
  reporterBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
  domainBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
  hourlyBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
}

async function fetchJson(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!res.ok) {
    const text = await res.text();
    let message = text || `Request failed: ${res.status}`;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed.detail === "string") {
        message = parsed.detail;
      }
    } catch {
      // keep fallback text
    }
    throw new Error(message);
  }

  return res.json();
}

async function checkHealth() {
  try {
    const data = await fetchJson("/api/health");
    if (data.ok) {
      apiStatus.textContent = "API: online";
      apiStatus.style.borderColor = "#00d2b8";
      return;
    }
    throw new Error("Health check failed");
  } catch {
    apiStatus.textContent = "API: offline (start backend)";
    apiStatus.style.borderColor = "#ff5d5d";
  }
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  scanBtn.disabled = true;
  scanBtn.textContent = "Analyzing...";

  try {
    const data = await fetchJson("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ url }),
    });

    state.lastScannedUrl = String(data.normalizedUrl || data.url || url);

    resultUrl.textContent = state.lastScannedUrl;
    setGauge(data.riskScore);
    riskLabel.textContent = readableRiskLabel(String(data.riskLabel || "low"));

    const signals = Array.isArray(data.signals) ? data.signals : [];
    setReasons(signals.map((signal) => signal.message || signal.id || "Signal triggered"));
    renderSignalCards(signals);

    const actions = Array.isArray(data.recommendedActions)
      ? data.recommendedActions.map((item) => item.label).filter(Boolean)
      : [];
    explainSummary.textContent = actions.length
      ? `Recommended: ${actions.join(" ")}`
      : "No recommendations returned.";
    confidencePill.textContent = `Risk: ${readableRiskLabel(String(data.riskLabel || "low"))}`;

    openReport.disabled = false;
    openReport.textContent = data.riskLabel === "low" ? "Report Anyway" : "Report This URL";
  } catch (error) {
    riskLabel.textContent = "Scan failed";
    reasonList.innerHTML = `<li>${escapeHtml(error.message)}</li>`;
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Analyze";
  }
});

openReport.addEventListener("click", () => {
  reportUrl.value = state.lastScannedUrl || urlInput.value.trim();
  reportModal.showModal();
});

cancelReport.addEventListener("click", () => {
  reportModal.close();
});

reportForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const form = new FormData(reportForm);
  const userReason = String(form.get("reason") || "").trim();
  const reporterType = String(form.get("reporter_type") || "user").trim();
  const reporterName = String(form.get("reporter_name") || "").trim() || "anonymous";
  const evidence = String(form.get("evidence") || "").trim();

  const notesParts = [userReason, evidence].filter(Boolean);
  const payload = {
    url: String(form.get("url") || "").trim(),
    reason: "phishing_or_scam",
    notes: notesParts.join(" | ") || null,
  };

  try {
    const report = await fetchJson("/api/report", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    state.reports.push({
      id: report.reportId,
      time: new Date(report.timestamp).toISOString().slice(0, 19).replace("T", " "),
      url: payload.url,
      reason: payload.reason,
      reporterType,
      reporterUser: reporterName,
    });

    updateLocalReportCount();
    renderLocalIntel();

    reportModal.close();
    reportForm.reset();
  } catch (error) {
    alert(`Could not submit report: ${error.message}`);
  }
});

demoButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    urlInput.value = btn.dataset.url || "";
    scanForm.requestSubmit();
  });
});

(function renderTips() {
  const host = document.getElementById("tips-grid");
  const tpl = document.getElementById("tip-template");
  tips.forEach((tip) => {
    const node = tpl.content.cloneNode(true);
    node.querySelector("h3").textContent = tip.title;
    node.querySelector("p").textContent = tip.body;
    host.appendChild(node);
  });
})();

(async function boot() {
  setGauge(0);
  riskLabel.textContent = "Awaiting Scan";
  updateLocalReportCount();
  renderLocalIntel();
  setLegacySectionsState();
  await checkHealth();
})();
