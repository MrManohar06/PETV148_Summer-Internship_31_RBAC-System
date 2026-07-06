// common.js — shared helpers for the RBAC demo UI.
// IMPORTANT: hiding elements here is a UX convenience only. Every
// action is re-checked server-side in auth.py / app.py. Never trust
// this file for actual security decisions.

function getToken() {
  return localStorage.getItem("rbac_token");
}

function setToken(token) {
  localStorage.setItem("rbac_token", token);
}

function clearToken() {
  localStorage.removeItem("rbac_token");
}

async function apiFetch(url, options = {}) {
  const token = getToken();
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  const resp = await fetch(url, Object.assign({}, options, { headers }));
  if (resp.status === 401) {
    clearToken();
    // Only redirect if we're not already on the login page — avoids a reload loop.
    if (!window.location.pathname.startsWith("/login-page")) {
      window.location.href = "/login-page";
    }
    return null;
  }
  return resp;
}

async function loadNavUserInfo() {
  const el = document.getElementById("nav-user-info");
  if (!el) return;
  if (!getToken()) return;   // don't even try if there's no token — avoids the loop
  const resp = await apiFetch("/api/me");
  if (!resp) return;
  if (resp.ok) {
    const data = await resp.json();
    el.textContent = `${data.username} — ${data.role}`;
  }
}

document.addEventListener("DOMContentLoaded", loadNavUserInfo);
