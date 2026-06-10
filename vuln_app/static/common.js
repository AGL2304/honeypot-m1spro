"use strict";
/* vuln_app — module commun de l'IHM « jumeau rouge ».
 * Volontairement minimaliste : pas de durcissement, c'est le contraste.
 * (Aucune CSP serveur ici -> inline serait permis, mais on garde la même
 *  structure que secure_app pour un comparatif lisible.) */

const TOKENS = {
  get access() { return localStorage.getItem("va_access"); },
  get refresh() { return localStorage.getItem("va_refresh"); },
  set(access, refresh) {
    localStorage.setItem("va_access", access);
    localStorage.setItem("va_refresh", refresh);
  },
  clear() {
    localStorage.removeItem("va_access");
    localStorage.removeItem("va_refresh");
  },
  get isAuthed() { return !!localStorage.getItem("va_access"); },
};

const $ = (sel, root = document) => root.querySelector(sel);

let _toastTimer = null;
function toast(msg, kind) {
  let el = $("#toast");
  if (!el) { el = document.createElement("div"); el.id = "toast"; document.body.appendChild(el); }
  el.textContent = msg;
  el.className = "toast" + (kind ? " " + kind : "");
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
}

async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const headers = {};
  if (body !== null) headers["Content-Type"] = "application/json";
  if (auth && TOKENS.access) headers["Authorization"] = "Bearer " + TOKENS.access;
  const resp = await fetch(path, {
    method, headers, body: body !== null ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch (_e) { /* corps vide ou non-JSON */ }
  if (!resp.ok) {
    const detail = (data && data.detail) ? data.detail : "Erreur (" + resp.status + ")";
    const err = new Error(detail); err.status = resp.status; throw err;
  }
  return data;
}

function makeLink(href, text, cls) {
  const a = document.createElement("a");
  a.href = href; a.textContent = text;
  if (cls) a.className = cls;
  return a;
}

function closeBurger() {
  const btn = $("#nav-toggle"), host = $("#nav-links");
  if (btn) btn.setAttribute("aria-expanded", "false");
  if (host) host.classList.remove("open");
}

async function renderNav() {
  initChrome();
  const host = $("#nav-links");
  if (!host) return;
  host.replaceChildren();
  host.appendChild(makeLink("/", "Accueil"));

  if (TOKENS.isAuthed) {
    let username = null;
    try { username = (await api("/users/me")).username; } catch (_e) { /* on garde quand même */ }
    host.appendChild(makeLink("/dashboard", "Mon espace"));
    host.appendChild(makeLink("/coffre", "Coffre"));
    const who = document.createElement("span");
    who.className = "nav-user";
    who.textContent = "👤 " + (username || "?");
    host.appendChild(who);
    const out = document.createElement("button");
    out.className = "btn btn-ghost";
    out.textContent = "Déconnexion";
    out.addEventListener("click", logout);
    host.appendChild(out);
    closeBurger();
    return;
  }
  host.appendChild(makeLink("/login", "Connexion"));
  host.appendChild(makeLink("/register", "Inscription", "btn btn-primary"));
  closeBurger();
}

function logout() { TOKENS.clear(); window.location.href = "/"; }

function requireAuth() {
  if (!TOKENS.isAuthed) { window.location.replace("/login"); return false; }
  return true;
}

function formData(form) {
  const o = {};
  for (const [k, v] of new FormData(form).entries()) if (v !== "") o[k] = v;
  return o;
}

function initChrome() {
  const nav = $("header.nav");
  if (nav && !$("#nav-toggle")) {
    const btn = document.createElement("button");
    btn.id = "nav-toggle"; btn.className = "nav-burger"; btn.type = "button";
    btn.setAttribute("aria-label", "Ouvrir le menu");
    btn.setAttribute("aria-controls", "nav-links");
    btn.setAttribute("aria-expanded", "false");
    for (let i = 0; i < 3; i++) btn.appendChild(document.createElement("span"));
    btn.addEventListener("click", () => {
      const host = $("#nav-links"); if (!host) return;
      const open = host.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.appendChild(btn);
  }
  if (!$("#site-footer")) buildFooter();
}

function buildFooter() {
  const footer = document.createElement("footer");
  footer.id = "site-footer"; footer.className = "site-footer";
  const inner = document.createElement("div"); inner.className = "footer-inner";

  const a = document.createElement("div"); a.className = "footer-col";
  const ha = document.createElement("h4"); ha.textContent = "☠️ vuln_app";
  const pa = document.createElement("p");
  pa.textContent = "Jumeau VOLONTAIREMENT vulnérable de secure_app (M1SPRO). "
    + "Mêmes fonctions, toutes les protections retirées : à comparer côte à côte.";
  a.appendChild(ha); a.appendChild(pa);

  const b = document.createElement("div"); b.className = "footer-col";
  const hb = document.createElement("h4"); hb.textContent = "Navigation";
  const ulb = document.createElement("ul");
  [["/", "Accueil"], ["/dashboard", "Mon espace"], ["/coffre", "Coffre (en clair)"]]
    .forEach(([h, t]) => { const li = document.createElement("li"); li.appendChild(makeLink(h, t)); ulb.appendChild(li); });
  b.appendChild(hb); b.appendChild(ulb);

  const c = document.createElement("div"); c.className = "footer-col";
  const hc = document.createElement("h4"); hc.textContent = "Failles plantées";
  const ulc = document.createElement("ul");
  ["SQLi sur /auth/login", "Command injection /tools/ping", "JWT alg:none accepté",
   "BOLA + secrets en clair", "Aucun rate limit / en-tête"].forEach((t) => {
    const li = document.createElement("li"); li.textContent = t; ulc.appendChild(li);
  });
  c.appendChild(hc); c.appendChild(ulc);

  inner.appendChild(a); inner.appendChild(b); inner.appendChild(c);
  const bottom = document.createElement("div"); bottom.className = "footer-bottom";
  bottom.textContent = "⚠️ Démo pédagogique M1SPRO — ne JAMAIS déployer en production.";
  footer.appendChild(inner); footer.appendChild(bottom);
  document.body.appendChild(footer);
}
