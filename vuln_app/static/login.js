"use strict";
(async function () {
  await renderNav();
  $("#form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    try {
      const r = await api("/auth/login", {
        method: "POST", auth: false,
        body: { username: d.username, password: d.password || "" },
      });
      TOKENS.set(r.access_token, r.refresh_token);
      toast("Connecté.", "ok");
      window.location.href = "/dashboard";
    } catch (err) { toast(err.message, "err"); }
  });
})();
