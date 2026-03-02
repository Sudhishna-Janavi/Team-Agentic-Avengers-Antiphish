const API_BASE = window.__ANTIPHISH_CONFIG__?.API_BASE || "http://127.0.0.1:8000";
const AUTH_TOKEN_KEY = "antiphish_token";
const AUTH_ROLE_KEY = "antiphish_role";
const AUTH_EMAIL_KEY = "antiphish_email";

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
  reportedUrls: new Set(),
  authToken: localStorage.getItem(AUTH_TOKEN_KEY) || "",
  authRole: localStorage.getItem(AUTH_ROLE_KEY) || "",
  authEmail: localStorage.getItem(AUTH_EMAIL_KEY) || "",
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
const reportToast = document.getElementById("report-toast");
const authStatus = document.getElementById("auth-status");
const authGate = document.getElementById("auth-gate");
const appShell = document.getElementById("app-shell");
const authUsernameInput = document.getElementById("auth-username");
const authPasswordInput = document.getElementById("auth-password");
const authSignupBtn = document.getElementById("auth-signup");
const authLoginBtn = document.getElementById("auth-login");
const authLogoutBtn = document.getElementById("auth-logout");

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

function showToast(message) {
  if (!reportToast) return;
  reportToast.textContent = message;
  reportToast.classList.add("show");
  window.setTimeout(() => {
    reportToast.classList.remove("show");
  }, 2200);
}

async function refreshReportCount() {
  try {
    const data = await fetchJson("/api/reports?page=1&pageSize=1");
    const total = Number(data.total || 0);
    reportCount.textContent = `Reports: ${total}`;
    kpiTotal.textContent = String(total);
  } catch {
    reportCount.textContent = "Reports: unknown";
    kpiTotal.textContent = "-";
  }
}

function setLegacySectionsState() {
  streamStatus.textContent = "Stream: unavailable in minimal backend";
  streamStatus.style.borderColor = "#5f7f98";
  alertsList.innerHTML = "<li>Live stream is disabled in this minimal backend.</li>";

  refreshDashboard.disabled = true;
  refreshDashboard.textContent = "Local Only";

  kpiReporter.textContent = "n/a";
  kpiDomain.textContent = "n/a";
  reporterBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
  domainBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
  hourlyBars.innerHTML = '<p class="modal-help">Disabled in minimal backend.</p>';
}

async function fetchJson(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (options.auth === true && state.authToken) {
    headers.Authorization = `Bearer ${state.authToken}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers,
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

function setAuthState({ token = "", role = "", email = "" }) {
  state.authToken = token;
  state.authRole = role;
  state.authEmail = email;

  if (token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    localStorage.setItem(AUTH_ROLE_KEY, role);
    localStorage.setItem(AUTH_EMAIL_KEY, email);
  } else {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(AUTH_ROLE_KEY);
    localStorage.removeItem(AUTH_EMAIL_KEY);
  }

  if (state.authToken) {
    authStatus.textContent = `Logged in: ${state.authRole} (${state.authEmail})`;
    authStatus.style.borderColor = "#8f8f8f";
  } else {
    authStatus.textContent = "Not logged in";
    authStatus.style.borderColor = "#5e5e5e";
  }
}

function showApp() {
  authGate.classList.add("hidden");
  appShell.classList.remove("hidden");
}

function showAuthGate() {
  appShell.classList.add("hidden");
  authGate.classList.remove("hidden");
}

async function signup() {
  const username = authUsernameInput.value.trim();
  const password = authPasswordInput.value;
  if (!username || !password) {
    alert("Enter username and password.");
    return;
  }
  const data = await fetchJson("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setAuthState({ token: data.token, role: data.role, email: data.username });
  showApp();
  showToast(`Signed up as ${data.role}`);
}

async function login() {
  const username = authUsernameInput.value.trim();
  const password = authPasswordInput.value;
  if (!username || !password) {
    alert("Enter username and password.");
    return;
  }

  const data = await fetchJson("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setAuthState({ token: data.token, role: data.role, email: data.username });
  showApp();
  showToast(`Logged in as ${data.role}`);
}

async function hydrateSession() {
  if (!state.authToken) {
    setAuthState({});
    showAuthGate();
    return;
  }
  try {
    const me = await fetchJson("/api/auth/me", { auth: true });
    setAuthState({ token: state.authToken, role: me.role, email: me.username });
    showApp();
  } catch {
    setAuthState({});
    showAuthGate();
  }
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

    const normalized = state.lastScannedUrl;
    const canReport =
      String(data.riskLabel || "low") !== "low" && !state.reportedUrls.has(normalized);
    openReport.disabled = !canReport;
    if (String(data.riskLabel || "low") === "low") {
      openReport.textContent = "Reporting disabled for safe links";
    } else if (state.reportedUrls.has(normalized)) {
      openReport.textContent = "Already reported";
    } else {
      openReport.textContent = "Report This URL";
    }
  } catch (error) {
    riskLabel.textContent = "Scan failed";
    reasonList.innerHTML = `<li>${escapeHtml(error.message)}</li>`;
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Analyze";
  }
});

openReport.addEventListener("click", () => {
  if (!state.authToken) {
    alert("Please login first (user/admin).");
    return;
  }
  reportUrl.value = state.lastScannedUrl || urlInput.value.trim();
  reportModal.showModal();
});

cancelReport.addEventListener("click", () => {
  reportModal.close();
});

reportForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.authToken) {
    alert("Please login as user/admin before reporting.");
    return;
  }

  const form = new FormData(reportForm);
  const category = String(form.get("reason") || "phishing_or_scam").trim();
  const whySuspicious = String(form.get("whySuspicious") || "").trim();
  const evidence = String(form.get("evidence") || "").trim();

  const payload = {
    url: String(form.get("url") || "").trim(),
    reason: category || "phishing_or_scam",
    whySuspicious,
    evidence: evidence || null,
  };

  try {
    const report = await fetchJson("/api/report", {
      method: "POST",
      auth: true,
      body: JSON.stringify(payload),
    });
    const normalized = state.lastScannedUrl || payload.url;
    state.reportedUrls.add(normalized);

    if (report.status === "exists" || report.deduped) {
      showToast("Already reported — thanks!");
    } else {
      await refreshReportCount();
      showToast("Report submitted. Thank you.");
    }

    openReport.disabled = true;
    openReport.textContent = "Already reported";

    reportModal.close();
    reportForm.reset();
  } catch (error) {
    alert(`Could not submit report: ${error.message}`);
  }
});

authSignupBtn.addEventListener("click", async () => {
  try {
    await signup();
  } catch (error) {
    alert(`Sign up failed: ${error.message}`);
  }
});

authLoginBtn.addEventListener("click", async () => {
  try {
    await login();
  } catch (error) {
    alert(`Login failed: ${error.message}`);
  }
});

authLogoutBtn.addEventListener("click", async () => {
  if (!state.authToken) {
    setAuthState({});
    return;
  }
  try {
    await fetchJson("/api/auth/logout", { method: "POST", auth: true });
  } catch {
    // ignore and clear local session anyway
  }
  setAuthState({});
  showAuthGate();
  showToast("Logged out");
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
  await hydrateSession();
  if (!state.authToken) {
    return;
  }
  await refreshReportCount();
  setLegacySectionsState();
  await checkHealth();
})();
