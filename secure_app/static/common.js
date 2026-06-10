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
  initChrome();                       // burger + footer (idempotent)
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
      host.appendChild(makeLink("/coffre", "Coffre"));
      const who = document.createElement("span");
      who.className = "nav-user";
      who.textContent = "👤 " + username;
      host.appendChild(who);

      const out = document.createElement("button");
      out.className = "btn btn-ghost";
      out.textContent = "Déconnexion";
      out.addEventListener("click", logout);
      host.appendChild(out);
      closeBurger();
      return;
    }
  }
  host.appendChild(makeLink("/login", "Connexion"));
  host.appendChild(makeLink("/register", "Inscription", "btn btn-primary"));
  closeBurger();
}

/* ---- Chrome commun : bouton hamburger + pied de page (CSP-safe) ----
 * Tout est construit via createElement/textContent (aucun innerHTML),
 * injecté une seule fois. Source unique -> pas de markup dupliqué. */
function closeBurger() {
  const btn = $("#nav-toggle");
  const host = $("#nav-links");
  if (btn) btn.setAttribute("aria-expanded", "false");
  if (host) host.classList.remove("open");
}

function initChrome() {
  // 1) Bouton hamburger injecté dans la barre de navigation.
  const nav = $("header.nav");
  if (nav && !$("#nav-toggle")) {
    const btn = document.createElement("button");
    btn.id = "nav-toggle";
    btn.className = "nav-burger";
    btn.type = "button";
    btn.setAttribute("aria-label", "Ouvrir le menu");
    btn.setAttribute("aria-controls", "nav-links");
    btn.setAttribute("aria-expanded", "false");
    for (let i = 0; i < 3; i++) btn.appendChild(document.createElement("span"));
    btn.addEventListener("click", () => {
      const host = $("#nav-links");
      if (!host) return;
      const open = host.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.appendChild(btn);
  }

  // 2) Pied de page injecté en fin de <body> s'il n'existe pas déjà.
  if (!$("#site-footer")) buildFooter();
}

function buildFooter() {
  const footer = document.createElement("footer");
  footer.id = "site-footer";
  footer.className = "site-footer";

  const inner = document.createElement("div");
  inner.className = "footer-inner";

  const colA = document.createElement("div");
  colA.className = "footer-col";
  const hA = document.createElement("h4");
  hA.textContent = "🔐 secure_app";
  const pA = document.createElement("p");
  pA.textContent =
    "Vitrine défensive du programme « Sécurité en Programmation » (M1SPRO). "
    + "Jumeau durci de vuln_app : mêmes fonctions, surface d'attaque réduite.";
  colA.appendChild(hA);
  colA.appendChild(pA);

  const colB = document.createElement("div");
  colB.className = "footer-col";
  const hB = document.createElement("h4");
  hB.textContent = "Navigation";
  const ulB = document.createElement("ul");
  [["/", "Accueil"], ["/dashboard", "Mon espace"], ["/coffre", "Coffre à secrets"]]
    .forEach(([href, txt]) => {
      const li = document.createElement("li");
      li.appendChild(makeLink(href, txt));
      ulB.appendChild(li);
    });
  colB.appendChild(hB);
  colB.appendChild(ulB);

  const colC = document.createElement("div");
  colC.className = "footer-col";
  const hC = document.createElement("h4");
  hC.textContent = "Sécurité";
  const ulC = document.createElement("ul");
  ["Argon2id + JWT whitelisté", "AES-256-GCM au repos", "Anti-BOLA / rate limiting",
   "CSP stricte, conteneur non-root"].forEach((txt) => {
    const li = document.createElement("li");
    li.textContent = txt;
    li.style.color = "var(--muted)";
    li.style.fontSize = ".85rem";
    ulC.appendChild(li);
  });
  colC.appendChild(hC);
  colC.appendChild(ulC);

  inner.appendChild(colA);
  inner.appendChild(colB);
  inner.appendChild(colC);

  const bottom = document.createElement("div");
  bottom.className = "footer-bottom";
  bottom.textContent =
    "© 2026 secure_app — projet pédagogique M1SPRO. Ne pas utiliser de vrais secrets.";

  footer.appendChild(inner);
  footer.appendChild(bottom);
  document.body.appendChild(footer);
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
