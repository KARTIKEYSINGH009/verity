// Shared site behaviour: auth-state swap, mobile nav drawer (#06),
// password visibility toggles + copy buttons (#13/#14), and the
// OAuth slot reveal (#13 — hidden until providers resolve, no flash).
(function () {
  // Auth state: when a session exists, Sign in / Start free -> Dashboard.
  fetch('/v1/me').then(function (r) {
    if (!r.ok) throw new Error('anon');
    return r.json();
  }).then(function () {
    document.querySelectorAll('[data-auth="signin"], [data-auth="start"]').forEach(function (el) { el.hidden = true; });
    document.querySelectorAll('[data-auth="dash"]').forEach(function (el) { el.hidden = false; });
  }).catch(function () { /* anonymous */ });

  // #06 Mobile navigation drawer: clone the primary nav into a drawer
  // toggled by a hamburger button injected into the top bar.
  var topWrap = document.querySelector('.topbar .wrap');
  var primaryNav = document.querySelector('.topbar nav[aria-label="Primary"]');
  if (topWrap && primaryNav) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'mobile-menu-btn';
    btn.setAttribute('aria-label', 'Open menu');
    btn.setAttribute('aria-expanded', 'false');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>';
    var drawer = document.createElement('div');
    drawer.className = 'mobile-drawer';
    drawer.id = 'mobile-drawer';
    btn.setAttribute('aria-controls', 'mobile-drawer');
    var drawerNav = primaryNav.cloneNode(true);
    drawerNav.setAttribute('aria-label', 'Mobile');
    drawer.appendChild(drawerNav);
    topWrap.appendChild(btn);
    var header = document.querySelector('.topbar');
    if (header) header.appendChild(drawer);
    function setOpen(open) {
      drawer.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    }
    btn.addEventListener('click', function () { setOpen(!drawer.classList.contains('open')); });
    drawer.addEventListener('click', function (ev) { if (ev.target.closest('a')) setOpen(false); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') setOpen(false); });
  }

  // #13 OAuth slot: stays hidden until /v1/auth/providers answers, so a
  // cold start never flashes "Google sign-in is being configured".
  var slot = document.getElementById('oauth-slot');
  if (slot) {
    var gBtn = document.getElementById('google-btn');
    var gNote = document.getElementById('google-note');
    function reveal() { slot.hidden = false; }
    fetch('/v1/auth/providers').then(function (r) { return r.json(); }).then(function (p) {
      if (p && p.google && gBtn) {
        gBtn.href = '/v1/auth/google/start';
        gBtn.removeAttribute('aria-disabled');
        if (gNote) gNote.textContent = '';
      }
      reveal();
    }).catch(function () { reveal(); });
    if (gBtn) {
      gBtn.addEventListener('click', function (ev) {
        if (gBtn.getAttribute('aria-disabled') === 'true') ev.preventDefault();
      });
    }
  }

  // #13 Password Show/Hide toggles for every password field.
  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    var toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'pw-toggle';
    toggle.textContent = 'Show password';
    toggle.setAttribute('aria-label', 'Show password');
    toggle.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggle.textContent = show ? 'Hide password' : 'Show password';
      toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
    input.insertAdjacentElement('afterend', toggle);
  });

  // Copy buttons: <button data-copy-target="#id"> copies that element's text.
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest ? ev.target.closest('[data-copy-target]') : null;
    if (!btn) return;
    var target = document.querySelector(btn.getAttribute('data-copy-target'));
    if (!target || !navigator.clipboard) return;
    var label = btn.textContent;
    navigator.clipboard.writeText(target.textContent.trim()).then(function () {
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = label; }, 1600);
    }).catch(function () { /* clipboard unavailable */ });
  });
})();
