// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

//Copying the IBAN 
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy-iban]');
  if (!btn) return;
  const iban = btn.getAttribute('data-copy-iban');
  try {
    await navigator.clipboard.writeText(iban);
    btn.innerText = 'Copied!';
    setTimeout(() => (btn.innerText = 'Copy IBAN'), 1500);
  } catch {
    alert('Copy failed');
  }
});

(function () {
  const COOKIE = 'theme';
  const COOKIE_OPTS = 'path=/; max-age=' + (60 * 60 * 24 * 365) + '; samesite=lax';

  function getCookie(name) {
    return document.cookie.split('; ').find(x => x.startsWith(name + '='))?.split('=')[1];
  }
  function setCookie(name, value) {
    document.cookie = name + '=' + encodeURIComponent(value) + '; ' + COOKIE_OPTS;
  }
  const prefersDark = () => window.matchMedia('(prefers-color-scheme: dark)').matches;

  function applyTheme(mode) {
    let actual = mode;
    if (mode === 'system') actual = prefersDark() ? 'dark' : 'light';
    // Bootstrap 5.3
    document.documentElement.setAttribute('data-bs-theme', actual);
    // fallback клас за по-стари Bootstrap-и/собствени стилове
    document.documentElement.classList.toggle('dark', actual === 'dark');
  }

  function initTheme() {
    const saved = getCookie(COOKIE);
    const mode = saved ? decodeURIComponent(saved) : 'system';
    applyTheme(mode);

    // ако е системен режим – следи смяната на OS темата
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener?.('change', () => {
      const current = decodeURIComponent(getCookie(COOKIE) || 'system');
      if (current === 'system') applyTheme('system');
    });

    // свържи radio-тата, ако има на страницата (Appearance)
    document.querySelectorAll('[data-theme-option]').forEach(r => {
      r.addEventListener('change', () => {
        const selected = r.value;         // light | dark | system
        setCookie(COOKIE, selected);
        applyTheme(selected);
      });
    });
  }

  function setTheme(mode) {
    setCookie(COOKIE, mode);
    applyTheme(mode);
  }

  window.Theme = { initTheme, setTheme };
})();


