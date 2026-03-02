const AUTH_TOKEN_KEY = "phishguard.authToken";
const AUTH_USER_KEY = "phishguard.authUser";

function isAuthenticated() {
  return localStorage.getItem(AUTH_TOKEN_KEY) === "active";
}

function requireAuth() {
  if (!isAuthenticated()) {
    window.location.href = "./login.html";
  }
}

function signIn(username) {
  localStorage.setItem(AUTH_TOKEN_KEY, "active");
  localStorage.setItem(AUTH_USER_KEY, username || "Analyst");
}

function signOut() {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(AUTH_USER_KEY);
  window.location.href = "./login.html";
}

function getUsername() {
  return localStorage.getItem(AUTH_USER_KEY) || "Analyst";
}

window.PhishGuardAuth = {
  isAuthenticated,
  requireAuth,
  signIn,
  signOut,
  getUsername,
};
