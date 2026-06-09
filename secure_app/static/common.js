"use strict";
/* secure_app — module commun à toutes les pages de l'IHM.
 * - Gestion des jetons (Bearer, pas de cookie -> pas de CSRF).
 * - Wrapper d'appel API avec refresh transparent sur 401.
 * - Barre de navigation adaptée à l'état d'authentification.
 * - Rendu DOM via textContent uniquement (jamais innerHTML).
 */

const TOKENS = {
  get access() { return localStorage.getItem("sa_access"); },
  get refresh() { return localStorage.getItem("sa_refresh"); },
  set(access, refresh) {
    localStorage.setItem("sa_access", access);
    localStorage.setItem("sa_refresh", refresh);
  },
  clear() {
    localStorage.removeItem("sa_access");
    localStorage.removeItem("sa_refresh");
  },
  get isAuthed() { return !!localStorage.getItem("sa_access"); },
};

const $ = (sel, root = document) => root.querySelector(sel);

let _toastTimer = null;
function toast(msg, kind) {
  let el = $("#toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.className = "toast" + (kind ? " " + kind : "");
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
}

/* ---- Appel API générique : ajoute le Bearer, gère le refresh sur 401 ---- */
async function api(path, { method = "GET", body = null, auth = true, _retry = false } = {}) {
  const headers = {};
  if (body !== null) headers["Content-Type"] = "application/json";
  if (auth && TOKENS.access) headers["Authorization"] = "Bearer " + TOKENS.access;

  const resp = await fetch(path, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 401 && auth && !_retry && TOKENS.refresh) {
    const ok = await tryRefresh();
    if (ok) return api(path, { method, body, auth, _retry: true });
  }

  let data = null;
  try { data = await resp.json(); } catch (_e) { /* corps vide */ }

  if (!resp.ok) {
    const detail = (data && data.detail) ? data.detail : "Erreur (" + resp.status + ")";
    const err = new Error(detail);
    err.status = resp.status;
    throw err;
  }
  return data;
}

async function tryRefresh() {
  try {
    const data = await api("/auth/refresh", {
      method: "POST",
      auth: false,
      body: { refresh_token: TOKENS.refresh },
    });
    TOKENS.set(data.access_token, data.refresh_token);
    return true;
  } catch (_e) {
    TOKENS.clear();
    return false;
  }
}

/* ----- Construit la barre de navigation selon l'état d'auth ----- */
function makeLink(href, text, cls) {
  const a = document.createElement("a");
  a.href = href;
  a.textContent = text;
  if (cls) a.className = cls;
  return a;
}

async function renderNav() {
  const host = $("#nav-links");
  if (!host) return;
  host.replaceChildren();
  host.appendChild(makeLink("/", "Accueil"));

  if (TOKENS.isAuthed) {
    // On confirme la session et affiche le nom d'utilisateur.
    let username = null;
    try { username = (await api("/users/me")).username; }
    catch (_e) { TOKENS.clear(); }

    if (username) {
      host.appendChild(makeLink("/dashboard", "Mon espace"));
      const who = document.createElement("span");
      who.className = "nav-user";
      who.textContent = "👤 " + username;
      host.appendChild(who);

      const out = document.createElement("button");
      out.className = "btn btn-ghost";
      out.textContent = "Déconnexion";
      out.addEventListener("click", logout);
      host.appendChild(out);
      return;
    }
  }
  host.appendChild(makeLink("/login", "Connexion"));
  host.appendChild(makeLink("/register", "Inscription", "btn btn-primary"));
}

async function logout() {
  try { await api("/auth/logout", { method: "POST" }); } catch (_e) { /* best effort */ }
  TOKENS.clear();
  window.location.href = "/";
}

/* Redirige vers /login si non authentifié (pages protégées). */
function requireAuth() {
  if (!TOKENS.isAuthed) {
    window.location.replace("/login");
    return false;
  }
  return true;
}

/* Sérialise un <form> en objet. */
function formData(form) {
  const o = {};
  for (const [k, v] of new FormData(form).entries()) {
    if (v !== "") o[k] = v;
  }
  return o;
}
