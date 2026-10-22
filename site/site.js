// Shared auth-state swap: when a session exists, the header's
// Sign in / Start free become a Dashboard link. Fails silently for
// anonymous visitors (the common case).
(function () {
  fetch('/v1/me').then(function (r) {
    if (!r.ok) throw new Error('anon');
    return r.json();
  }).then(function () {
    document.querySelectorAll('[data-auth="signin"], [data-auth="start"]').forEach(function (el) { el.hidden = true; });
    document.querySelectorAll('[data-auth="dash"]').forEach(function (el) { el.hidden = false; });
  }).catch(function () { /* anonymous */ });
})();
