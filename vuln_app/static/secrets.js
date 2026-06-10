"use strict";
/* Coffre vuln : valeurs EN CLAIR + panneau de fuite /secrets/export (tous comptes). */

async function loadSecrets() {
  const list = $("#secrets-list");
  const items = await api("/secrets");
  list.replaceChildren();
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted"; li.textContent = "Aucun secret.";
    list.appendChild(li);
  }
  for (const s of items) {
    const li = document.createElement("li");
    const main = document.createElement("div"); main.className = "secret-main";
    const label = document.createElement("div"); label.className = "secret-label"; label.textContent = s.label;
    // VULN : la valeur en clair est affichée directement (pas de masquage).
    const value = document.createElement("div"); value.className = "secret-value"; value.textContent = s.value;
    const meta = document.createElement("div"); meta.className = "secret-meta";
    meta.textContent = "id " + s.id;
    main.appendChild(label); main.appendChild(value); main.appendChild(meta);

    const actions = document.createElement("div"); actions.className = "secret-actions";
    const del = document.createElement("button");
    del.className = "btn btn-danger"; del.type = "button"; del.textContent = "Supprimer";
    del.addEventListener("click", async () => {
      try { await api("/secrets/" + encodeURIComponent(s.id), { method: "DELETE" });
        toast("Secret supprimé.", "ok"); refresh();
      } catch (e) { toast(e.message, "err"); }
    });
    actions.appendChild(del);
    li.appendChild(main); li.appendChild(actions); list.appendChild(li);
  }
}

async function loadLeak() {
  const body = $("#leak-body");
  body.replaceChildren();
  // Appel SANS authentification : démontre le dump complet.
  const all = await api("/secrets/export", { auth: false });
  for (const s of all) {
    const tr = document.createElement("tr");
    const u = document.createElement("td"); u.textContent = s.username || s.owner_id;
    const l = document.createElement("td"); l.textContent = s.label;
    const v = document.createElement("td"); v.className = "val"; v.textContent = s.value;
    tr.appendChild(u); tr.appendChild(l); tr.appendChild(v);
    body.appendChild(tr);
  }
}

async function refresh() {
  await loadSecrets();
  await loadLeak();
}

function bindForm() {
  $("#form-secret").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      await api("/secrets", { method: "POST", body: { label: d.label, value: d.value } });
      e.target.reset(); toast("Secret ajouté (en clair).", "ok"); refresh();
    } catch (err) { toast(err.message, "err"); }
  });
}

(async function () {
  if (!requireAuth()) return;
  await renderNav();
  bindForm();
  try { await refresh(); }
  catch (_e) { TOKENS.clear(); window.location.replace("/login"); }
})();
