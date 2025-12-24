(() => {
  const ENDPOINT = '/health';
  const POLL_MS = 15000;
  const TIMEOUT_MS = 5000;
  const TEXT = {
    db: 'Отсутствует соединение с базой данных',
    server: 'Соединение с сервером потеряно',
    ok: 'Соединение восстановлено',
  };

  let banner = null;
  let hideTimer = null;
  let pollTimer = null;
  let lastState = 'ok'; // 'ok' | 'db_down' | 'server_down'

  function ensureBanner() {
    if (banner) return banner;
    banner = document.createElement('div');
    banner.id = 'health-banner';
    banner.className = 'health-banner';
    banner.setAttribute('role', 'status');
    document.body.appendChild(banner);
    return banner;
  }

  function show(text, isOk = false) {
    const el = ensureBanner();
    clearTimeout(hideTimer);
    el.textContent = text;
    el.classList.toggle('is-ok', isOk);
    el.classList.add('visible');
    if (isOk) {
      hideTimer = window.setTimeout(() => {
        el.classList.remove('visible');
      }, 2600);
    }
  }

  function hide() {
    const el = ensureBanner();
    el.classList.remove('visible');
  }

  function setState(state) {
    if (state === 'ok') {
      if (lastState !== 'ok') {
        show(TEXT.ok, true);
      } else {
        hide();
      }
      lastState = 'ok';
      return;
    }

    const isServer = state === 'server_down';
    const msg = isServer ? TEXT.server : TEXT.db;
    // Если меняется тип сбоя то обновляется текст
    if (lastState !== state || !ensureBanner().classList.contains('visible')) {
      show(msg, false);
    }
    lastState = state;
  }

  async function ping() {
    const controller = new AbortController();
    const t = window.setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const resp = await fetch(ENDPOINT, { method: 'GET', signal: controller.signal });
      if (!resp.ok) {
        setState('db_down');
        return;
      }
      const data = await resp.json().catch(() => ({}));
      if (data && data.status === 'ok') {
        setState('ok');
      } else {
        setState('db_down');
      }
    } catch (e) {
      setState('server_down');
    } finally {
      window.clearTimeout(t);
    }
  }

  function stop() {
    if (pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function start() {
    // Первый запрос сразу, дальше по интервалу
    ping();
    pollTimer = window.setInterval(ping, POLL_MS);
  }

  function ensureRunning() {
    // Если страница вернулась из bfcache или вкладка была скрыта, дёргаем опрос заново
    if (!pollTimer) {
      start();
      return;
    }
    ping();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }

  window.addEventListener('pageshow', ensureRunning);
  window.addEventListener('pagehide', () => {
    // На возврате из bfcache пересоздадим таймер
    stop();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') ensureRunning();
    else stop();
  });
})();
