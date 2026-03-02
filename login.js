const auth = window.PhishGuardAuth;
const loginForm = document.getElementById("login-form");
const emailInput = document.getElementById("email-input");
const passwordInput = document.getElementById("password-input");
const loginFeedback = document.getElementById("login-feedback");

if (auth?.isAuthenticated()) {
  window.location.href = "./index.html";
}

function parseDisplayName(email) {
  const localPart = email.split("@")[0] || "Analyst";
  const formatted = localPart.replace(/[._-]/g, " ").trim();
  if (!formatted) {
    return "Analyst";
  }

  return formatted
    .split(" ")
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (!email || !password) {
    loginFeedback.textContent = "Enter both email and password.";
    return;
  }

  if (password.length < 8) {
    loginFeedback.textContent = "Password must be at least 8 characters.";
    return;
  }

  auth.signIn(parseDisplayName(email));
  window.location.href = "./index.html";
});
