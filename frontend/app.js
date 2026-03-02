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
    body: "Early reporting helps banks and responders block campaigns faster and warn others.",
  },
];

const state = {
  lastScannedUrl: "",
  eventSource: null,
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

function colorForRisk(score) {
  if (score >= 0.8) return "var(--danger)";
  if (score >= 0.5) return "var(--accent-2)";
  return "var(--accent)";
}

function labelForRisk(score) {
  if (score >= 0.8) return "Likely Phishing";
  if (score >= 0.5) return "Suspicious";
  return "Safe";
}

function setGauge(score) {
  const pct = Math.max(0, Math.min(100, Math.round(score * 100)));
  const color = colorForRisk(score);
  riskGauge.style.background = `conic-gradient(${color} ${pct}%, #143147 ${pct}%)`;
  riskScore.textContent = `${pct}%`;
  riskLabel.textContent = labelForRisk(score);
}

function setReasons(reasons) {
  if (!reasons.length) {
    reasonList.innerHTML = "<li>No signals returned.</li>";
    return;
  }
  reasonList.innerHTML = reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
}

function humanizeSignalName(signal) {
  return String(signal)
    .split("_")
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(" ");
}

function renderContributors(items) {
  contributors.innerHTML = "";
  if (!items.length) {
    contributors.innerHTML = "<p>No contributor signals available yet.</p>";
    return;
  }

  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "signal-card";
    card.innerHTML = `
      <div class="signal-head">
        <span class="signal-name">${escapeHtml(humanizeSignalName(item.signal))}</span>
        <span class="impact-pill impact-${escapeHtml(item.impact)}">${escapeHtml(item.impact)}</span>
      </div>
      <p class="signal-note">${escapeHtml(item.note)}</p>
      <span class="signal-weight">weight: ${Number(item.weight).toFixed(4)}</span>
    `;
    contributors.appendChild(card);
  });
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
      // keep message
    }
    throw new Error(message);
  }

  return res.json();
}

async function checkHealth() {
  try {
    await fetchJson("/health");
    apiStatus.textContent = "API: online";
    apiStatus.style.borderColor = "#00d2b8";
  } catch {
    apiStatus.textContent = "API: offline (start backend)";
    apiStatus.style.borderColor = "#ff5d5d";
  }
}

async function refreshStats() {
  try {
    const data = await fetchJson("/api/v1/stats");
    reportCount.textContent = `Reports: ${data.reports_total}`;
  } catch {
    reportCount.textContent = "Reports: unknown";
  }
}

function renderIntel(items) {
  if (!items.length) {
    intelBody.innerHTML = "<tr><td colspan=\"5\">No reports yet.</td></tr>";
    return;
  }

  intelBody.innerHTML = items
    .map(
      (item) => `
      <tr>
        <td>${new Date(item.created_at).toISOString().slice(0, 19).replace("T", " ")}</td>
        <td>${escapeHtml(item.url)}</td>
        <td>${escapeHtml(item.reason)}</td>
        <td>${escapeHtml(item.reporter_type)}</td>
        <td>${escapeHtml(item.reporter_user || "anonymous")}</td>
      </tr>
    `
    )
    .join("");
}

function renderBars(host, items, labelKey, valueKey) {
  const tpl = document.getElementById("bar-template");
  host.innerHTML = "";
  if (!items.length) {
    host.innerHTML = "<p class=\"modal-help\">No data yet.</p>";
    return;
  }

  const maxValue = Math.max(...items.map((item) => Number(item[valueKey] || 0)), 1);
  items.forEach((item) => {
    const node = tpl.content.cloneNode(true);
    const label = String(item[labelKey]);
    const value = Number(item[valueKey] || 0);
    const pct = Math.round((value / maxValue) * 100);

    node.querySelector(".bar-label").textContent = label;
    node.querySelector(".bar-value").textContent = String(value);
    node.querySelector(".bar-fill").style.width = `${pct}%`;
    host.appendChild(node);
  });
}

async function refreshDashboardStats() {
  try {
    const data = await fetchJson("/api/v1/dashboard-stats");
    kpiTotal.textContent = String(data.reports_total ?? 0);
    kpiReporter.textContent = data.reporters?.[0]?.reporter_type ?? "-";
    kpiDomain.textContent = data.top_domains?.[0]?.domain ?? "-";

    renderBars(reporterBars, data.reporters || [], "reporter_type", "count");
    renderBars(domainBars, data.top_domains || [], "domain", "count");
    renderBars(hourlyBars, data.hourly_trend || [], "hour_utc", "count");
  } catch {
    reporterBars.innerHTML = "<p class=\"modal-help\">Could not load dashboard data.</p>";
    domainBars.innerHTML = "<p class=\"modal-help\">Could not load dashboard data.</p>";
    hourlyBars.innerHTML = "<p class=\"modal-help\">Could not load dashboard data.</p>";
  }
}

async function refreshIntelFeed() {
  try {
    const items = await fetchJson("/api/v1/intel-feed?limit=12");
    renderIntel(items);
  } catch {
    intelBody.innerHTML = "<tr><td colspan=\"5\">Could not load intel feed.</td></tr>";
  }
}

function prependAlert(item) {
  const noData = alertsList.querySelector("li")?.textContent === "No live alerts yet.";
  if (noData) alertsList.innerHTML = "";

  const li = document.createElement("li");
  li.className = "alert-item";
  li.innerHTML = `
    <div class="alert-url">${escapeHtml(item.url)}</div>
    <div class="alert-meta">${escapeHtml(item.reporter_type)} by ${escapeHtml(item.reporter_user || "anonymous")} at ${new Date(item.created_at).toISOString()}</div>
    <div class="alert-reason">${escapeHtml(item.reason)}</div>
  `;
  alertsList.prepend(li);

  while (alertsList.children.length > 10) {
    alertsList.removeChild(alertsList.lastElementChild);
  }
}

function connectAlertStream() {
  if (state.eventSource) state.eventSource.close();
  const stream = new EventSource(`${API_BASE}/api/v1/alerts/stream`);
  state.eventSource = stream;

  streamStatus.textContent = "Stream: connecting...";
  streamStatus.style.borderColor = "#ffb703";

  stream.onopen = () => {
    streamStatus.textContent = "Stream: connected";
    streamStatus.style.borderColor = "#00d2b8";
  };

  stream.addEventListener("new_report", async (evt) => {
    try {
      const payload = JSON.parse(evt.data);
      prependAlert(payload);
      await Promise.all([refreshIntelFeed(), refreshStats(), refreshDashboardStats()]);
    } catch {
      // ignore malformed event payload
    }
  });

  stream.onerror = () => {
    streamStatus.textContent = "Stream: reconnecting...";
    streamStatus.style.borderColor = "#ffb703";
  };
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  scanBtn.disabled = true;
  scanBtn.textContent = "Analyzing...";

  try {
    const data = await fetchJson("/api/v1/scan-url", {
      method: "POST",
      body: JSON.stringify({
        url,
        source: "frontend",
      }),
    });

    state.lastScannedUrl = data.url;

    resultUrl.textContent = data.url;
    setGauge(Number(data.risk_score));
    setReasons(Array.isArray(data.reasons) ? data.reasons : []);
    explainSummary.textContent =
      data.explanation?.summary || "No explanation returned by model.";
    confidencePill.textContent = `Confidence: ${Math.round(
      Number(data.explanation?.confidence || 0) * 100
    )}%`;
    renderContributors(data.explanation?.contributors || []);

    openReport.disabled = false;
    openReport.textContent =
      data.verdict === "safe" ? "Report Anyway" : "Report This URL";
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
  const payload = {
    url: String(form.get("url") || "").trim(),
    reason: String(form.get("reason") || "").trim(),
    reporter_type: String(form.get("reporter_type") || "user"),
    reporter_name: String(form.get("reporter_name") || "").trim() || null,
    evidence: String(form.get("evidence") || "").trim() || null,
  };

  try {
    await fetchJson("/api/v1/reports", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    reportModal.close();
    reportForm.reset();
    await Promise.all([refreshIntelFeed(), refreshStats(), refreshDashboardStats()]);
  } catch (error) {
    alert(`Could not submit report: ${error.message}`);
  }
});

refreshIntel.addEventListener("click", refreshIntelFeed);
refreshDashboard.addEventListener("click", refreshDashboardStats);

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
  connectAlertStream();
  await Promise.all([
    checkHealth(),
    refreshStats(),
    refreshIntelFeed(),
    refreshDashboardStats(),
  ]);
})();
