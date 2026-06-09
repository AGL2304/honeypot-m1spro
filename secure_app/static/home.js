"use strict";
/* Page d'accueil : nav + adaptation des boutons d'appel à l'action. */
(async function () {
  await renderNav();
  if (TOKENS.isAuthed) {
    const space = document.querySelector("#cta-space");
    if (space) space.classList.remove("hidden");
    // On masque les CTA d'auth quand l'utilisateur est déjà connecté.
    document.querySelectorAll('.hero .cta a[href="/login"], .hero .cta a[href="/register"]')
      .forEach((a) => a.classList.add("hidden"));
  }
})();
