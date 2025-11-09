(() => {
  const KEY = 'sg:ui:mode';
  const btnId = 'theme-toggle';
  const PROFILE_KEY = 'sg:ui:profile'; // 'color' | 'mono'

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
    // Если включён профиль Ч/Б — блокируем переключение темы
    try { if (localStorage.getItem(PROFILE_KEY) === 'mono') return; } catch {}
    const current = getMode();
    const next = current === 'light' ? 'dark' : 'light';
    setMode(next);
    apply(next);
  }

  function init() {
    // Если выбран профиль Ч/Б — принудительно светлая тема и заблокированная кнопка
    let mode = getMode();
    const isMono = (() => { try { return localStorage.getItem(PROFILE_KEY) === 'mono'; } catch { return false; } })();
    if (isMono) {
      mode = 'light';
      setMode('light');
    }
    apply(mode);
    const btn = document.getElementById(btnId);
    if (btn) {
      if (isMono) {
        btn.disabled = true;
        btn.title = 'Смена темы интерфейса не поддерживается для выбранного профиля';
      }
      btn.addEventListener('click', toggle);
    }
    // На случай изменения профиля в другой вкладке — отслеживаем storage
    window.addEventListener('storage', (e) => {
      if (e.key === PROFILE_KEY) {
        const mono = e.newValue === 'mono';
        const b = document.getElementById(btnId);
        if (mono) {
          setMode('light');
          apply('light');
          if (b) { b.disabled = true; b.title = 'Смена темы интерфейса не поддерживается для выбранного профиля'; }
        } else {
          if (b) { b.disabled = false; b.title = (getMode() === 'light') ? 'Тёмная тема' : 'Светлая тема'; }
        }
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
