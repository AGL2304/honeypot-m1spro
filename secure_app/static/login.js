"use strict";
/* Page de connexion. */
(async function () {
  await renderNav();
  // Déjà connecté -> direction l'espace.
  if (TOKENS.isAuthed) { window.location.replace("/dashboard"); return; }

  $("#form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    const body = { username: d.username, password: d.password };
    if (d.otp) body.otp = d.otp;
    try {
      const tok = await api("/auth/login", { method: "POST", auth: false, body });
      TOKENS.set(tok.access_token, tok.refresh_token);
      window.location.href = "/dashboard";
    } catch (err) {
      toast(err.message, "err");
    }
  });
})();
