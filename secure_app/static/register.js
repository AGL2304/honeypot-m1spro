"use strict";
/* Page d'inscription. */
(async function () {
  await renderNav();
  if (TOKENS.isAuthed) { window.location.replace("/dashboard"); return; }

  $("#form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      await api("/auth/register", {
        method: "POST",
        auth: false,
        body: { username: d.username, email: d.email, password: d.password },
      });
      toast("Compte créé. Redirection vers la connexion…", "ok");
      setTimeout(() => { window.location.href = "/login"; }, 1200);
    } catch (err) {
      toast(err.message, "err");
    }
  });
})();
