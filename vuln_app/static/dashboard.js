"use strict";
/* Espace authentifié (vuln) : profil fuite-mdp, notes (BOLA), ping (RCE). */

async function loadProfile() {
  const me = await api("/users/me");
  $("#p-id").textContent = me.id || "—";
  $("#p-user").textContent = me.username || "—";
  $("#p-email").textContent = me.email || "—";
  // VULN : on affiche le mot de passe renvoyé en clair par l'API.
  $("#p-pass").textContent = me.password || "(non renvoyé)";
}

async function loadNotes() {
  const notes = await api("/notes");
  const list = $("#notes-list");
  list.replaceChildren();
  if (!notes.length) {
    const li = document.createElement("li");
    li.className = "muted"; li.textContent = "Aucune note.";
    list.appendChild(li); return;
  }
  for (const n of notes) {
    const li = document.createElement("li");
    const wrap = document.createElement("div");
    const t = document.createElement("div"); t.className = "n-title"; t.textContent = n.title;
    const b = document.createElement("div"); b.className = "n-body"; b.textContent = n.body;
    wrap.appendChild(t); wrap.appendChild(b);
    const del = document.createElement("button");
    del.className = "btn btn-danger"; del.textContent = "Supprimer";
    del.addEventListener("click", async () => {
      try { await api("/notes/" + encodeURIComponent(n.id), { method: "DELETE" });
        toast("Note supprimée.", "ok"); loadNotes();
      } catch (e) { toast(e.message, "err"); }
    });
    li.appendChild(wrap); li.appendChild(del); list.appendChild(li);
  }
}

function bindForms() {
  $("#form-note").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      await api("/notes", { method: "POST", body: { title: d.title, body: d.body || "" } });
      e.target.reset(); toast("Note ajoutée.", "ok"); loadNotes();
    } catch (err) { toast(err.message, "err"); }
  });

  $("#form-ping").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    const out = $("#ping-out");
    out.textContent = "…";
    try {
      const r = await api("/tools/ping", { method: "POST", body: { host: d.host } });
      // VULN : la sortie brute de la commande injectée est affichée telle quelle.
      out.textContent = "$ " + r.cmd + "\n\n" + (r.output || "");
    } catch (err) { out.textContent = "Erreur : " + err.message; }
  });
}

(async function () {
  if (!requireAuth()) return;
  await renderNav();
  bindForms();
  try { await loadProfile(); await loadNotes(); }
  catch (_e) { TOKENS.clear(); window.location.replace("/login"); }
})();
