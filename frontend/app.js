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
  lastVerdict: "Awaiting Scan",
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

function escapeHtml(value) {
  return value
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
  const pct = Math.round(score * 100);
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

  reasonList.innerHTML = reasons
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("");
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
    throw new Error(text || `Request failed: ${res.status}`);
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
    intelBody.innerHTML = "<tr><td colspan=\"4\">No reports yet.</td></tr>";
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
      </tr>
    `
    )
    .join("");
}

async function refreshIntelFeed() {
  try {
    const items = await fetchJson("/api/v1/intel-feed?limit=12");
    renderIntel(items);
  } catch {
    intelBody.innerHTML = "<tr><td colspan=\"4\">Could not load intel feed.</td></tr>";
  }
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
    state.lastVerdict = data.verdict;

    resultUrl.textContent = data.url;
    setGauge(Number(data.risk_score));
    setReasons(Array.isArray(data.reasons) ? data.reasons : []);

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
    evidence: String(form.get("evidence") || "").trim() || null,
  };

  try {
    await fetchJson("/api/v1/reports", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    reportModal.close();
    reportForm.reset();
    await Promise.all([refreshIntelFeed(), refreshStats()]);
  } catch (error) {
    alert(`Could not submit report: ${error.message}`);
  }
});

refreshIntel.addEventListener("click", refreshIntelFeed);

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
  await Promise.all([checkHealth(), refreshStats(), refreshIntelFeed()]);
})();
