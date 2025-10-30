(() => {
  const KEY = 'sg:ui:mode';
  const btnId = 'theme-toggle';

  function getMode() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw === 'light' || raw === 'dark') return raw;
    } catch {}
    return 'dark';
  }

  function setMode(mode) {
    try { localStorage.setItem(KEY, mode); } catch {}
  }

  function apply(mode) {
    const isLight = mode === 'light';
    try {
      document.body.classList.toggle('light-theme', isLight);
      // Дублируем класс на <html>, чтобы стили могли применяться до построения <body>
      document.documentElement.classList.toggle('light-theme', isLight);
    } catch {}
    updateButton(mode);
    try { document.dispatchEvent(new CustomEvent('sg:theme-change', { detail: { mode } })); } catch {}
  }

  function updateButton(mode) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    if (mode === 'light') {
      btn.textContent = '🌙';
      btn.title = 'Тёмная тема';
      btn.setAttribute('aria-label', 'Тёмная тема');
    } else {
      btn.textContent = '☀';
      btn.title = 'Светлая тема';
      btn.setAttribute('aria-label', 'Светлая тема');
    }
  }

  function toggle() {
    const current = getMode();
    const next = current === 'light' ? 'dark' : 'light';
    setMode(next);
    apply(next);
  }

  function init() {
    const mode = getMode();
    apply(mode);
    const btn = document.getElementById(btnId);
    if (btn) btn.addEventListener('click', toggle);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
