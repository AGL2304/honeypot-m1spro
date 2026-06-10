"use strict";
/* Coffre à secrets : liste masquée + révélation à la demande (anti-disclosure).
 * - GET /secrets    -> aperçu masqué uniquement (preview).
 * - GET /secrets/id -> clair, réservé au propriétaire (ownership vérifié serveur).
 * Rendu DOM via textContent uniquement (jamais innerHTML) -> CSP-safe. */

function makeBtn(text, cls, onClick) {
  const b = document.createElement("button");
  b.className = cls;
  b.type = "button";
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

async function loadSecrets() {
  const list = $("#secrets-list");
  const items = await api("/secrets");
  list.replaceChildren();

  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "Aucun secret. Ajoutez-en un ci-dessus.";
    list.appendChild(li);
    return;
  }

  for (const s of items) {
    const li = document.createElement("li");

    const main = document.createElement("div");
    main.className = "secret-main";

    const label = document.createElement("div");
    label.className = "secret-label";
    const lock = document.createElement("span");
    lock.className = "lock";
    lock.textContent = "🔒";
    const lblText = document.createElement("span");
    lblText.textContent = s.label;
    label.appendChild(lock);
    label.appendChild(lblText);

    const value = document.createElement("div");
    value.className = "secret-value";
    value.textContent = s.preview;

    const meta = document.createElement("div");
    meta.className = "secret-meta";
    meta.textContent = "créé le " + (s.created_at || "—");

    main.appendChild(label);
    main.appendChild(value);
    main.appendChild(meta);

    // Actions : révéler (déchiffre côté serveur) / masquer / supprimer.
    const actions = document.createElement("div");
    actions.className = "secret-actions";

    let revealed = false;
    const reveal = makeBtn("Révéler", "btn", async () => {
      if (revealed) {
        value.textContent = s.preview;
        value.classList.remove("revealed");
        lock.textContent = "🔒";
        reveal.textContent = "Révéler";
        revealed = false;
        return;
      }
      try {
        const full = await api("/secrets/" + encodeURIComponent(s.id));
        value.textContent = full.value;
        value.classList.add("revealed");
        lock.textContent = "🔓";
        reveal.textContent = "Masquer";
        revealed = true;
      } catch (e) { toast(e.message, "err"); }
    });

    const del = makeBtn("Supprimer", "btn btn-danger", async () => {
      try {
        await api("/secrets/" + encodeURIComponent(s.id), { method: "DELETE" });
        toast("Secret supprimé.", "ok");
        loadSecrets();
      } catch (e) { toast(e.message, "err"); }
    });

    actions.appendChild(reveal);
    actions.appendChild(del);

    li.appendChild(main);
    li.appendChild(actions);
    list.appendChild(li);
  }
}

function bindForm() {
  $("#form-secret").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      await api("/secrets", { method: "POST", body: { label: d.label, value: d.value } });
      e.target.reset();
      toast("Secret ajouté (chiffré).", "ok");
      loadSecrets();
    } catch (err) { toast(err.message, "err"); }
  });
}

(async function () {
  if (!requireAuth()) return;
  await renderNav();
  bindForm();
  try {
    await loadSecrets();
  } catch (_e) {
    TOKENS.clear();
    window.location.replace("/login");
  }
})();
