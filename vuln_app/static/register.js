"use strict";
(async function () {
  await renderNav();
  $("#form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      await api("/auth/register", {
        method: "POST", auth: false,
        body: { username: d.username, email: d.email || "", password: d.password },
      });
      toast("Compte créé. Connectez-vous.", "ok");
      window.location.href = "/login";
    } catch (err) { toast(err.message, "err"); }
  });
})();
