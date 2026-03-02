const API_BASE = window.__ANTIPHISH_CONFIG__?.API_BASE || "http://127.0.0.1:8000";
const PAGE_SIZE = 25;
const AUTH_TOKEN_KEY = "antiphish_token";
const AUTH_ROLE_KEY = "antiphish_role";
const AUTH_EMAIL_KEY = "antiphish_email";

const state = {
  page: 1,
  total: 0,
  lastItems: [],
  debounceId: null,
  authToken: localStorage.getItem(AUTH_TOKEN_KEY) || "",
  authRole: localStorage.getItem(AUTH_ROLE_KEY) || "",
  authEmail: localStorage.getItem(AUTH_EMAIL_KEY) || "",
};

const feedBody = document.getElementById("feed-body");
const feedTotal = document.getElementById("feed-total");
const queryInput = document.getElementById("filter-query");
const reasonSelect = document.getElementById("filter-reason");
const sinceSelect = document.getElementById("filter-since");
const clearFiltersBtn = document.getElementById("clear-filters");
const prevPageBtn = document.getElementById("prev-page");
const nextPageBtn = document.getElementById("next-page");
const pageInfo = document.getElementById("page-info");

const detailModal = document.getElementById("report-detail-modal");
const closeDetailBtn = document.getElementById("close-detail");
const copyUrlBtn = document.getElementById("copy-url");
const feedAuthStatus = document.getElementById("feed-auth-status");
const feedAuthLogoutBtn = document.getElementById("feed-auth-logout");

function q(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatUtc(value) {
  return new Date(value).toISOString().slice(0, 19).replace("T", " ");
}

function truncate(value, maxLen = 100) {
  const text = String(value || "");
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen - 1)}…`;
}

async function fetchJson(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.auth === true && state.authToken) {
    headers.Authorization = `Bearer ${state.authToken}`;
  }
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
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
    feedAuthStatus.textContent = `Logged in: ${state.authRole} (${state.authEmail})`;
    feedAuthStatus.style.borderColor = "#8f8f8f";
  } else {
    feedAuthStatus.textContent = "Not logged in";
    feedAuthStatus.style.borderColor = "#5e5e5e";
  }
}

async function hydrateSession() {
  if (!state.authToken) {
    setAuthState({});
    return;
  }
  try {
    const me = await fetchJson("/api/auth/me", { auth: true });
    setAuthState({ token: state.authToken, role: me.role, email: me.username });
  } catch {
    setAuthState({});
  }
}

function buildListQuery() {
  const params = new URLSearchParams();
  params.set("page", String(state.page));
  params.set("pageSize", String(PAGE_SIZE));

  const query = queryInput.value.trim();
  const reason = reasonSelect.value;
  const since = sinceSelect.value;

  if (query) params.set("query", query);
  if (reason) params.set("reason", reason);
  if (since) params.set("since", since);

  return params.toString();
}

function updatePagination() {
  const maxPage = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  pageInfo.textContent = `Page ${state.page} of ${maxPage}`;
  prevPageBtn.disabled = state.page <= 1;
  nextPageBtn.disabled = state.page >= maxPage;
}

function renderRows(items) {
  if (!items.length) {
    feedBody.innerHTML = '<tr><td colspan="8">No reports match your filters.</td></tr>';
    return;
  }

  feedBody.innerHTML = items
    .map(
      (item) => `
      <tr class="feed-row" data-report-id="${escapeHtml(item.reportId)}">
        <td>${escapeHtml(formatUtc(item.timestamp))}</td>
        <td>${escapeHtml(item.url)}</td>
        <td>${escapeHtml(item.reason)}</td>
        <td>${escapeHtml(String(item.suspiciousPercent ?? "-"))}%</td>
        <td>${escapeHtml(String(item.frequency ?? 1))}</td>
        <td>${escapeHtml(item.reporter || "user")}</td>
        <td title="${escapeHtml(item.whySuspicious || "-")}">${escapeHtml(
          truncate(item.whySuspicious || "-", 96)
        )}</td>
        <td>${
          state.authRole === "admin"
            ? `<button class="danger-btn delete-report-btn" data-report-id="${escapeHtml(
                item.reportId
              )}" type="button">Delete</button>`
            : "-"
        }</td>
      </tr>
    `
    )
    .join("");
}

async function loadReports() {
  try {
    const data = await fetchJson(`/api/reports?${buildListQuery()}`);
    state.total = Number(data.total || 0);
    state.lastItems = Array.isArray(data.items) ? data.items : [];
    feedTotal.textContent = `Total: ${state.total}`;
    renderRows(state.lastItems);
    updatePagination();
  } catch {
    feedBody.innerHTML = '<tr><td colspan="8">Could not load reports.</td></tr>';
  }
}

function setText(id, value) {
  q(id).textContent = value || "-";
}

async function loadSignals(url) {
  const host = q("detail-signals");
  host.innerHTML = "<li>Loading...</li>";

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error("analyze failed");
    const data = await res.json();
    const signals = Array.isArray(data.signals) ? data.signals : [];
    if (!signals.length) {
      host.innerHTML = "<li>No signals available.</li>";
      return;
    }
    host.innerHTML = signals
      .map((signal) => `<li>${escapeHtml(signal.message || signal.id || "Signal")}</li>`)
      .join("");
  } catch {
    host.innerHTML = "<li>Could not load analysis signals.</li>";
  }
}

async function openDetail(reportId) {
  try {
    const detail = await fetchJson(`/api/reports/${encodeURIComponent(reportId)}`);

    setText("detail-id", detail.reportId);
    setText("detail-time", formatUtc(detail.timestamp));
    setText("detail-url", detail.url);
    setText("detail-normalized", detail.normalizedUrl);
    setText("detail-reason", detail.reason);
    setText("detail-suspicious", `${detail.suspiciousPercent ?? "-"}%`);
    setText("detail-frequency", String(detail.frequency ?? 1));
    setText("detail-reporter", detail.reporter || "user");
    setText("detail-why", detail.whySuspicious || "-");
    setText("detail-evidence", detail.evidence || "-");

    copyUrlBtn.dataset.url = detail.url;
    detailModal.showModal();
    await loadSignals(detail.url);
  } catch {
    // ignore
  }
}

feedBody.addEventListener("click", (event) => {
  const deleteBtn = event.target.closest(".delete-report-btn");
  if (deleteBtn) {
    const reportId = deleteBtn.dataset.reportId || "";
    if (!reportId) return;
    if (state.authRole !== "admin") {
      alert("Admin login required to delete reports.");
      return;
    }
    if (!confirm("Delete this report from community feed?")) return;
    (async () => {
      try {
        await fetchJson(`/api/reports/${encodeURIComponent(reportId)}`, {
          method: "DELETE",
          auth: true,
        });
        await loadReports();
      } catch (error) {
        alert(`Delete failed: ${error.message}`);
      }
    })();
    return;
  }

  const row = event.target.closest("tr[data-report-id]");
  if (!row) return;
  openDetail(row.dataset.reportId);
});

queryInput.addEventListener("input", () => {
  state.page = 1;
  if (state.debounceId) {
    window.clearTimeout(state.debounceId);
  }
  state.debounceId = window.setTimeout(loadReports, 220);
});

reasonSelect.addEventListener("change", () => {
  state.page = 1;
  loadReports();
});

sinceSelect.addEventListener("change", () => {
  state.page = 1;
  loadReports();
});

clearFiltersBtn.addEventListener("click", () => {
  queryInput.value = "";
  reasonSelect.value = "";
  sinceSelect.value = "24h";
  state.page = 1;
  loadReports();
});

prevPageBtn.addEventListener("click", () => {
  if (state.page <= 1) return;
  state.page -= 1;
  loadReports();
});

nextPageBtn.addEventListener("click", () => {
  const maxPage = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  if (state.page >= maxPage) return;
  state.page += 1;
  loadReports();
});

copyUrlBtn.addEventListener("click", async () => {
  const url = copyUrlBtn.dataset.url || "";
  if (!url) return;
  try {
    await navigator.clipboard.writeText(url);
    copyUrlBtn.textContent = "Copied";
    window.setTimeout(() => {
      copyUrlBtn.textContent = "Copy URL";
    }, 1200);
  } catch {
    // ignore
  }
});

closeDetailBtn.addEventListener("click", () => {
  detailModal.close();
});

feedAuthLogoutBtn.addEventListener("click", async () => {
  if (state.authToken) {
    try {
      await fetchJson("/api/auth/logout", { method: "POST", auth: true });
    } catch {
      // ignore
    }
  }
  setAuthState({});
  await loadReports();
});

(async function boot() {
  await hydrateSession();
  await loadReports();
})();
