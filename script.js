const auth = window.PhishGuardAuth;
auth?.requireAuth();

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const resultPanel = document.getElementById("result");
const riskTitle = document.getElementById("risk-title");
const riskBadge = document.getElementById("risk-badge");
const riskScore = document.getElementById("risk-score");
const riskFill = document.getElementById("risk-fill");
const riskWarning = document.getElementById("risk-warning");
const reasonList = document.getElementById("reason-list");
const reportBtn = document.getElementById("report-btn");
const reportFeedback = document.getElementById("report-feedback");
const scanDate = document.getElementById("scan-date");
const logoutBtn = document.getElementById("logout-btn");
const userGreeting = document.getElementById("user-greeting");

if (userGreeting && auth) {
  userGreeting.textContent = `Signed in as ${auth.getUsername()}`;
}

const resultPresets = {
  high: {
    title: "Potential Phishing",
    badge: "High Risk",
    score: 82,
    warning:
      "Warning: This link may be a phishing attempt. Do not enter passwords or payment details.",
    reasons: [
      "Domain closely resembles a known brand but uses uncommon spelling.",
      "The URL includes a login prompt path often seen in credential theft pages.",
      "Domain registration appears recent and reputation signals are limited.",
    ],
    colors: {
      badgeBg: "#fbe4e4",
      badgeText: "#6f1111",
      meter: "linear-gradient(90deg, #bf3227, #e26722)",
      warning: "#8b1d1d",
    },
  },
  medium: {
    title: "Suspicious Signals Found",
    badge: "Medium Risk",
    score: 56,
    warning:
      "Caution: This link shows suspicious signals. Proceed only if you trust the source.",
    reasons: [
      "The page requests sensitive details in an unusual context.",
      "The domain has mixed trust signals across public sources.",
      "Tracking parameters and redirects may hide the final destination.",
    ],
    colors: {
      badgeBg: "#fff2df",
      badgeText: "#8a4d06",
      meter: "linear-gradient(90deg, #c9781e, #e1b446)",
      warning: "#8a4d06",
    },
  },
  low: {
    title: "No Strong Phishing Signals",
    badge: "Low Risk",
    score: 18,
    warning:
      "No strong phishing signals detected, but always verify before sharing sensitive info.",
    reasons: [
      "Domain age and public trust indicators appear stable.",
      "No known deceptive keywords were detected in the URL structure.",
      "Page intent appears consistent with expected destination behavior.",
    ],
    colors: {
      badgeBg: "#e7f6eb",
      badgeText: "#16572d",
      meter: "linear-gradient(90deg, #3f9e60, #71b887)",
      warning: "#16572d",
    },
  },
};

function formatTimestamp() {
  const now = new Date();
  return `Analyzed on ${now.toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  })} at ${now.toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  })}`;
}

function choosePreset(url) {
  const normalized = url.toLowerCase();

  if (
    normalized.includes("login") ||
    normalized.includes("secure") ||
    normalized.includes("verify") ||
    normalized.includes("update")
  ) {
    return resultPresets.high;
  }

  if (normalized.includes("account") || normalized.includes("redirect")) {
    return resultPresets.medium;
  }

  return resultPresets.low;
}

function renderResult(result) {
  riskTitle.textContent = result.title;
  riskBadge.textContent = result.badge;
  riskBadge.style.background = result.colors.badgeBg;
  riskBadge.style.color = result.colors.badgeText;

  riskScore.textContent = `${result.score} / 100`;
  riskFill.style.width = `${result.score}%`;
  riskFill.style.background = result.colors.meter;

  riskWarning.textContent = result.warning;
  riskWarning.style.color = result.colors.warning;

  reasonList.innerHTML = "";
  for (const reason of result.reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonList.appendChild(item);
  }

  scanDate.textContent = formatTimestamp();
  reportFeedback.textContent = "";

  resultPanel.classList.remove("hidden");
  resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const candidate = urlInput.value.trim();
  if (!candidate) {
    urlInput.setCustomValidity("Enter a URL before running the check.");
    urlInput.reportValidity();
    return;
  }

  urlInput.setCustomValidity("");
  const result = choosePreset(candidate);
  renderResult(result);
});

reportBtn.addEventListener("click", () => {
  reportFeedback.textContent = "Thanks. Your report was submitted.";
});

logoutBtn?.addEventListener("click", () => {
  auth?.signOut();
});
