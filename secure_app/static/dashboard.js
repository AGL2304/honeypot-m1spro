"use strict";
/* Espace authentifié : profil, MFA, notes, outil ping. */

async function loadProfile() {
  const me = await api("/users/me");
  $("#p-id").textContent = me.id;
  $("#p-user").textContent = me.username;
  $("#p-email").textContent = me.email;
  $("#p-mfa").textContent = me.mfa_enabled ? "✅ activé" : "❌ désactivé";
}

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

function bindForms() {
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
      out.textContent = "host=" + r.host + "  rc=" + r.returncode + "  ";
      const verdict = document.createElement("span");
      verdict.className = r.reachable ? "badge-ok" : "badge-ko";
      verdict.textContent = r.reachable ? "JOIGNABLE" : "INJOIGNABLE";
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
}

(async function () {
  if (!requireAuth()) return;       // redirige vers /login si pas de jeton
  await renderNav();
  bindForms();
  try {
    await loadProfile();
    await loadNotes();
  } catch (_e) {
    // Jeton invalide/expiré et refresh impossible -> retour au login.
    TOKENS.clear();
    window.location.replace("/login");
  }
})();
