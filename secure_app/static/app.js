"use strict";
/* secure_app — client IHM.
 * - Auth par Bearer (pas de cookie -> pas de vecteur CSRF).
 * - Rendu via textContent uniquement (jamais innerHTML) -> pas d'injection DOM.
 * - Refresh transparent du token d'accès sur 401.
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
};

const $ = (sel) => document.querySelector(sel);

let _toastTimer = null;
function toast(msg, kind) {
  const el = $("#toast");
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
    // Tentative de rotation du token d'accès, puis on rejoue une fois.
    const ok = await tryRefresh();
    if (ok) return api(path, { method, body, auth, _retry: true });
  }

  let data = null;
  try { data = await resp.json(); } catch (_e) { /* corps vide */ }

  if (!resp.ok) {
    const detail = (data && data.detail) ? data.detail : "Erreur (" + resp.status + ")";
    throw new Error(detail);
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

/* ----------------------------- Vues ----------------------------- */
function showAuth() {
  $("#view-auth").classList.remove("hidden");
  $("#view-app").classList.add("hidden");
  $("#who").classList.add("hidden");
}

async function showApp() {
  $("#view-auth").classList.add("hidden");
  $("#view-app").classList.remove("hidden");
  $("#who").classList.remove("hidden");
  await loadProfile();
  await loadNotes();
}

/* --------------------------- Profil ----------------------------- */
async function loadProfile() {
  const me = await api("/users/me");
  $("#p-id").textContent = me.id;
  $("#p-user").textContent = me.username;
  $("#p-email").textContent = me.email;
  $("#p-mfa").textContent = me.mfa_enabled ? "✅ activé" : "❌ désactivé";
  $("#who-name").textContent = "👤 " + me.username;
}

/* ---------------------------- Notes ----------------------------- */
async function loadNotes() {
  const notes = await api("/notes");
  const list = $("#notes-list");
  list.replaceChildren();
  if (!notes.length) {
    const li = document.createElement("li");
    li.textContent = "Aucune note.";
    li.className = "muted";
    list.appendChild(li);
    return;
  }
  for (const n of notes) {
    const li = document.createElement("li");
    const wrap = document.createElement("div");
    const t = document.createElement("div");
    t.className = "n-title";
    t.textContent = n.title;
    const b = document.createElement("div");
    b.className = "n-body";
    b.textContent = n.body;
    wrap.appendChild(t);
    wrap.appendChild(b);

    const del = document.createElement("button");
    del.className = "btn btn-danger";
    del.textContent = "Supprimer";
    del.addEventListener("click", async () => {
      try {
        await api("/notes/" + encodeURIComponent(n.id), { method: "DELETE" });
        toast("Note supprimée.", "ok");
        loadNotes();
      } catch (e) { toast(e.message, "err"); }
    });

    li.appendChild(wrap);
    li.appendChild(del);
    list.appendChild(li);
  }
}

/* --------------------- Liaison des formulaires ------------------- */
function formData(form) {
  const o = {};
  for (const [k, v] of new FormData(form).entries()) o[k] = v;
  return o;
}

$("#form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const d = formData(e.target);
  const body = { username: d.username, password: d.password };
  if (d.otp) body.otp = d.otp;
  try {
    const tok = await api("/auth/login", { method: "POST", auth: false, body });
    TOKENS.set(tok.access_token, tok.refresh_token);
    e.target.reset();
    toast("Connecté.", "ok");
    showApp();
  } catch (err) { toast(err.message, "err"); }
});

$("#form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const d = formData(e.target);
  try {
    await api("/auth/register", { method: "POST", auth: false, body: d });
    e.target.reset();
    toast("Compte créé. Vous pouvez vous connecter.", "ok");
  } catch (err) { toast(err.message, "err"); }
});

$("#btn-logout").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch (_e) { /* best effort */ }
  TOKENS.clear();
  toast("Déconnecté.", "ok");
  showAuth();
});

$("#form-note").addEventListener("submit", async (e) => {
  e.preventDefault();
  const d = formData(e.target);
  try {
    await api("/notes", { method: "POST", body: { title: d.title, body: d.body } });
    e.target.reset();
    toast("Note ajoutée.", "ok");
    loadNotes();
  } catch (err) { toast(err.message, "err"); }
});

$("#form-ping").addEventListener("submit", async (e) => {
  e.preventDefault();
  const d = formData(e.target);
  const out = $("#ping-out");
  out.textContent = "…";
  try {
    const r = await api("/tools/ping", { method: "POST", body: { host: d.host } });
    out.textContent = "";
    const line = document.createElement("span");
    line.textContent = "host=" + r.host + "  rc=" + r.returncode + "  ";
    const verdict = document.createElement("span");
    verdict.className = r.reachable ? "badge-ok" : "badge-ko";
    verdict.textContent = r.reachable ? "JOIGNABLE" : "INJOIGNABLE";
    out.appendChild(line);
    out.appendChild(verdict);
  } catch (err) {
    out.textContent = "";
    const v = document.createElement("span");
    v.className = "badge-ko";
    v.textContent = "REJETÉ : " + err.message;
    out.appendChild(v);
  }
});

$("#btn-mfa-setup").addEventListener("click", async () => {
  try {
    const r = await api("/auth/mfa/setup", { method: "POST" });
    $("#mfa-secret").textContent = r.secret;
    $("#mfa-uri").textContent = r.otpauth_uri;
    $("#mfa-secret-box").classList.remove("hidden");
    toast("Secret généré. Entrez un code pour activer.", "ok");
  } catch (e) { toast(e.message, "err"); }
});

$("#form-mfa-enable").addEventListener("submit", async (e) => {
  e.preventDefault();
  const d = formData(e.target);
  try {
    await api("/auth/mfa/enable", { method: "POST", body: { otp: d.otp } });
    e.target.reset();
    $("#mfa-secret-box").classList.add("hidden");
    toast("MFA activé.", "ok");
    loadProfile();
  } catch (err) { toast(err.message, "err"); }
});

/* --------------------------- Démarrage --------------------------- */
(async function boot() {
  if (TOKENS.access) {
    try { await showApp(); return; }
    catch (_e) { TOKENS.clear(); }
  }
  showAuth();
})();
