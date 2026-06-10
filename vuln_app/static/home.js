"use strict";
(async function () {
  await renderNav();
  if (TOKENS.isAuthed) {
    const s = document.querySelector("#cta-space");
    if (s) s.classList.remove("hidden");
    document.querySelectorAll('.hero .cta a[href="/login"], .hero .cta a[href="/register"]')
      .forEach((a) => a.classList.add("hidden"));
  }
})();
