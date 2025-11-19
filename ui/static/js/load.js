(() => {
  const form = document.getElementById('run-form');
  const runBtn = document.getElementById('run-btn');
  const stopBtn = document.getElementById('stop-btn');
  const gnnRunBtn = document.getElementById('gnn-run-btn');
  const gnnStopBtn = document.getElementById('gnn-stop-btn');
  const gnnClearBtn = document.getElementById('gnn-clear-btn');
  const output = document.getElementById('output');
  const clearBtn = document.getElementById('clear-btn');
  const LS_KEY = 'sg:data:filters';

  let abortController = null;
  let currentRunId = null;
  let currentJobKind = null; // 'load' | 'gnn' | null
  // Запоминаем ключ последней зафиксированной строки прогресса, чтобы не дублировать финал
  let lastFinalKey = null;
  let inBar = false;

  function appendRaw(text) {
    output.textContent += text;
    output.scrollTop = output.scrollHeight;
  }

  function append(text) {
    const parts = String(text).split('\r');
    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];
      const isBarLike = /\|/.test(seg) && /\]/.test(seg) && /\d+%/.test(seg);

      // Нормализованный ключ бара (без хвоста в квадратных скобках)
      let key = null;
      let isFinal = false;
      if (isBarLike) {
        key = seg.replace(/\s\[[^\]]*\]\s*$/, '').trimEnd();
        isFinal = /100%\|/.test(seg) || (/\b100%\b/.test(seg) && /\]/.test(seg));
        if (lastFinalKey && key === lastFinalKey) {
          continue;
        }
      }

      if (i === 0) {
        appendRaw(seg);
      } else {
        if (isBarLike) {
          // Начало/продолжение полосы: не затираем предыдущие строки
          if (!inBar && !output.textContent.endsWith('\n')) appendRaw('\n');
          inBar = true;
          const content = output.textContent;
          const lastNL = content.lastIndexOf('\n');
          const head = lastNL === -1 ? '' : content.slice(0, lastNL + 1);
          output.textContent = head + seg;
          output.scrollTop = output.scrollHeight;
        } else {
          inBar = false;
          appendRaw(seg);
        }
      }

      // Завершаем бар, если это финал
      if (isBarLike && isFinal) {
        if (lastFinalKey !== key) {
          lastFinalKey = key;
          if (!output.textContent.endsWith('\n')) appendRaw('\n');
        }
        inBar = false;
      }
    }
    // Сжимаем лишние пустые строки: максимум одна пустая строка подряд
    output.textContent = output.textContent.replace(/\n{3,}/g, '\n\n');
  }

  function gatherValues() {
    const only = Array.from(form.querySelectorAll('input[name="only"]:checked')).map(i => i.value);
    const skip = Array.from(form.querySelectorAll('input[name="skip"]:checked')).map(i => i.value);
    const yearRaw = (form.querySelector('#cve_from_year').value || '').trim();
    const cve_from_year = yearRaw ? parseInt(yearRaw, 10) : null;
    // Флажок принудительной перезаписи: при включении игнорируем проверку хеша
    const forceCveEl = form.querySelector('#force_cve');
    const force_cve = !!(forceCveEl && forceCveEl.checked);
    const check_hash = !force_cve; // фронт шлёт check_hash=true/false, как ждёт бэкенд
    return { only, skip, cve_from_year, check_hash, force_cve };
  }

  function updateDisable() {
    const onlyBoxes = Array.from(form.querySelectorAll('input[name="only"]'));
    const skipBoxes = Array.from(form.querySelectorAll('input[name="skip"]'));
    const onlyMap = Object.fromEntries(onlyBoxes.map(cb => [cb.value, cb]));
    const skipMap = Object.fromEntries(skipBoxes.map(cb => [cb.value, cb]));

    // Если отмечен ONLY[X], запретить SKIP[X] и снять отметку
    for (const val in onlyMap) {
      const o = onlyMap[val];
      const s = skipMap[val];
      if (!s) continue;
      if (o.checked) {
        s.checked = false;
        s.disabled = true;
      } else {
        if (!s.checked) s.disabled = false;
      }
    }

    // Если отмечен SKIP[X], запретить ONLY[X] и снять отметку
    for (const val in skipMap) {
      const s = skipMap[val];
      const o = onlyMap[val];
      if (!o) continue;
      if (s.checked) {
        o.checked = false;
        o.disabled = true;
      } else {
        if (!o.checked) o.disabled = false;
      }
    }
  }

  async function runLoad() {
    const payload = gatherValues();
    // Генерируем run_id на клиенте, сервер может вернуть свой через заголовок
    currentRunId = `${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
    currentJobKind = 'load';
    payload.run_id = currentRunId;
    // Оценим ширину в символах по ширине окна/блока вывода
    try {
      const rect = output.getBoundingClientRect();
      const px = rect.width || window.innerWidth || 800;
      const cols = Math.max(60, Math.floor(px / 8)); // ~8px на символ моноширинного шрифта
      payload.columns = cols;
    } catch {}
    output.textContent = '';
    runBtn.disabled = true;
    stopBtn.disabled = false;
    if (gnnRunBtn) gnnRunBtn.disabled = true;
    if (gnnStopBtn) gnnStopBtn.disabled = true;
    if (gnnClearBtn) gnnClearBtn.disabled = true;
    abortController = new AbortController();

    try {
      const resp = await fetch('/run/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: abortController.signal,
      });

      if (!resp.ok) {
        let msg = `${resp.status} ${resp.statusText}`;
        try {
          const data = await resp.json();
          if (data && data.error) msg = `${msg} — ${data.error}`;
        } catch {}
        append(`Ошибка запуска: ${msg}\n`);
        return;
      }
      if (!resp.body) {
        append(`Ошибка запуска: пустой ответ сервера\n`);
        return;
      }

      const hdrId = resp.headers.get('x-run-id');
      if (hdrId) currentRunId = hdrId;

      const reader = resp.body.getReader();
      const decoder = new TextDecoder('utf-8');
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        append(decoder.decode(value, { stream: true }));
      }
    } catch (err) {
      append(`\n[client error] ${err}\n`);
    } finally {
      runBtn.disabled = false;
      stopBtn.disabled = true;
      if (gnnRunBtn) gnnRunBtn.disabled = false;
      if (gnnStopBtn) gnnStopBtn.disabled = true;
      if (gnnClearBtn) gnnClearBtn.disabled = false;
      abortController = null;
      currentRunId = null;
      currentJobKind = null;
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (currentRunId) return;
    runLoad();
  });

  // Взаимоисключающие чекбоксы ONLY/SKIP
  form.querySelectorAll('input[name="only"], input[name="skip"]').forEach(cb => {
    cb.addEventListener('change', updateDisable);
    cb.addEventListener('change', () => {
      try {
        localStorage.setItem(LS_KEY, JSON.stringify(gatherValues()));
      } catch (e) { console.warn('ls save filters', e); }
    });
  });
  updateDisable();
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const data = JSON.parse(raw);
      const setChecks = (name, vals=[]) => {
        const set = new Set(vals);
        form.querySelectorAll(`input[name="${name}"]`).forEach(cb => { cb.checked = set.has(cb.value); });
      };
      setChecks('only', Array.isArray(data.only) ? data.only : []);
      setChecks('skip', Array.isArray(data.skip) ? data.skip : []);
      if (typeof data.cve_from_year === 'number') {
        const y = form.querySelector('#cve_from_year'); if (y) y.value = String(data.cve_from_year);
      } else {
        const y = form.querySelector('#cve_from_year'); if (y) y.value = '';
      }
      // восстановление чекбокса принудительной перезаписи
      const fc = form.querySelector('#force_cve');
      if (fc) fc.checked = !!data.force_cve;
      updateDisable();
    }
  } catch (e) { console.warn('ls load filters', e); }
  const yearInput = form.querySelector('#cve_from_year');
  if (yearInput) {
    yearInput.addEventListener('input', () => {
      try { localStorage.setItem(LS_KEY, JSON.stringify(gatherValues())); } catch (e) { console.warn('ls save year', e); }
    });
  }
  const forceInput = form.querySelector('#force_cve');
  if (forceInput) {
    forceInput.addEventListener('change', () => {
      try { localStorage.setItem(LS_KEY, JSON.stringify(gatherValues())); } catch (e) { console.warn('ls save force', e); }
    });
  }

  stopBtn.addEventListener('click', async () => {
    if (!currentRunId) {
      if (abortController) abortController.abort();
      runBtn.disabled = false;
      stopBtn.disabled = true;
      abortController = null;
      return;
    }
    if (currentJobKind !== 'load') {
      return;
    }
    try {
      const resp = await fetch('/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: currentRunId }),
      });
      const data = await resp.json().catch(() => ({}));
      append(`\n[server stop] ${data.status || resp.status}\n`);
    } catch (e) {
      append(`\n[server stop error] ${e}\n`);
    } finally {
      if (abortController) abortController.abort();
      runBtn.disabled = false;
      stopBtn.disabled = true;
      if (gnnRunBtn) gnnRunBtn.disabled = false;
      if (gnnStopBtn) gnnStopBtn.disabled = true;
      if (gnnClearBtn) gnnClearBtn.disabled = false;
      abortController = null;
      currentRunId = null;
      currentJobKind = null;
    }
  });

  clearBtn.addEventListener('click', () => {
    output.textContent = '';
    form.querySelectorAll('input[name="only"], input[name="skip"]').forEach(cb => { cb.checked = false; cb.disabled = false; });
    const y = form.querySelector('#cve_from_year'); if (y) y.value = '';
    const fc = form.querySelector('#force_cve'); if (fc) fc.checked = false;
    updateDisable();
    try { localStorage.removeItem(LS_KEY); } catch (e) { console.warn('ls clear filters', e); }
  });

  async function runGnn() {
    if (currentRunId) return;

    const payload = {};
    currentRunId = `${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
    currentJobKind = 'gnn';
    payload.run_id = currentRunId;
    try {
      const rect = output.getBoundingClientRect();
      const px = rect.width || window.innerWidth || 800;
      const cols = Math.max(60, Math.floor(px / 8));
      payload.columns = cols;
    } catch {}

    output.textContent = '';
    if (gnnRunBtn) gnnRunBtn.disabled = true;
    if (gnnStopBtn) gnnStopBtn.disabled = false;
    if (gnnClearBtn) gnnClearBtn.disabled = true;
    runBtn.disabled = true;
    stopBtn.disabled = true;
    abortController = new AbortController();

    try {
      const resp = await fetch('/run/gnn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: abortController.signal,
      });

      if (!resp.ok) {
        let msg = `${resp.status} ${resp.statusText}`;
        try {
          const data = await resp.json();
          if (data && data.error) msg = `${msg} — ${data.error}`;
        } catch {}
        append(`Ошибка запуска GNN: ${msg}\n`);
        return;
      }
      if (!resp.body) {
        append(`Ошибка запуска GNN: пустой ответ сервера\n`);
        return;
      }

      const hdrId = resp.headers.get('x-run-id');
      if (hdrId) currentRunId = hdrId;

      const reader = resp.body.getReader();
      const decoder = new TextDecoder('utf-8');
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        append(decoder.decode(value, { stream: true }));
      }
    } catch (err) {
      append(`\n[client error gnn] ${err}\n`);
    } finally {
      if (gnnRunBtn) gnnRunBtn.disabled = false;
      if (gnnStopBtn) gnnStopBtn.disabled = true;
      if (gnnClearBtn) gnnClearBtn.disabled = false;
      runBtn.disabled = false;
      stopBtn.disabled = true;
      abortController = null;
      currentRunId = null;
      currentJobKind = null;
    }
  }

  if (gnnRunBtn) {
    gnnRunBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (currentRunId) return;
      runGnn();
    });
  }

  if (gnnStopBtn) {
    gnnStopBtn.addEventListener('click', async () => {
      if (!currentRunId || currentJobKind !== 'gnn') {
        return;
      }
      try {
        const resp = await fetch('/stop', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ run_id: currentRunId }),
        });
        const data = await resp.json().catch(() => ({}));
        append(`\n[server stop gnn] ${data.status || resp.status}\n`);
      } catch (e) {
        append(`\n[server stop gnn error] ${e}\n`);
      } finally {
        if (abortController) abortController.abort();
        if (gnnRunBtn) gnnRunBtn.disabled = false;
        if (gnnStopBtn) gnnStopBtn.disabled = true;
        if (gnnClearBtn) gnnClearBtn.disabled = false;
        runBtn.disabled = false;
        stopBtn.disabled = true;
        abortController = null;
        currentRunId = null;
        currentJobKind = null;
      }
    });
  }

  async function performGnnClear() {
    if (currentRunId) {
      const msg = 'Ошибка очистки: найден запущенный процесс (загрузчик или GNN).';
      openGnnClearResultModal(msg);
      return;
    }
    try {
      const resp = await fetch('/gnn/clear', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && (data.status === 'ok' || !data.status)) {
        const msg = 'Добавленные GNN связи успешно удалены из базы.';
        openGnnClearResultModal(msg);
      } else {
        const msg = `Ошибка сервера (${resp.status}) при очистке связей, добавленных GNN: ${data.error || 'Неизвестная ошибка'}`;
        openGnnClearResultModal(msg);
      }
    } catch (e) {
      const msg = `Ошибка сети при очистке связей, добавленных GNN: ${e}`;
      openGnnClearResultModal(msg);
    }
  }

  if (gnnClearBtn) {
    gnnClearBtn.addEventListener('click', () => {
      if (currentRunId) {
        const msg = 'Ошибка очистки: найден запущенный процесс (загрузчик или GNN).';
        openGnnClearResultModal(msg);
        return;
      }
      openGnnClearConfirmModal();
    });
  }

  // защита от ухода со страницы во время загрузки
  const leaveBackdrop = document.getElementById('leave-confirm-backdrop');
  const leaveCancel = document.getElementById('leave-cancel');
  const leaveConfirm = document.getElementById('leave-confirm');
  let leavePendingHref = null;
  let allowLeave = false; // когда true, beforeunload не блокирует

  // наличие запущенного процесса (загрузчик или GNN) определяется по currentRunId
  const isBusy = () => !!currentRunId;

  // Модалки управления очисткой GNN
  const gnnClearConfirmBackdrop = document.getElementById('gnn-clear-confirm-backdrop');
  const gnnClearConfirmBtn = document.getElementById('gnn-clear-confirm');
  const gnnClearCancelBtn = document.getElementById('gnn-clear-cancel');
  const gnnClearResultBackdrop = document.getElementById('gnn-clear-result-backdrop');
  const gnnClearResultMessage = document.getElementById('gnn-clear-result-message');
  const gnnClearResultOk = document.getElementById('gnn-clear-result-ok');

  function openGnnClearConfirmModal() {
    if (!gnnClearConfirmBackdrop) return;
    gnnClearConfirmBackdrop.hidden = false;
    gnnClearConfirmBackdrop.classList.add('open');
  }
  function closeGnnClearConfirmModal() {
    if (!gnnClearConfirmBackdrop) return;
    gnnClearConfirmBackdrop.classList.remove('open');
    gnnClearConfirmBackdrop.hidden = true;
  }
  function openGnnClearResultModal(message) {
    if (!gnnClearResultBackdrop) return;
    if (gnnClearResultMessage) gnnClearResultMessage.textContent = message;
    gnnClearResultBackdrop.hidden = false;
    gnnClearResultBackdrop.classList.add('open');
  }
  function closeGnnClearResultModal() {
    if (!gnnClearResultBackdrop) return;
    gnnClearResultBackdrop.classList.remove('open');
    gnnClearResultBackdrop.hidden = true;
  }

  if (gnnClearCancelBtn) gnnClearCancelBtn.addEventListener('click', () => closeGnnClearConfirmModal());
  if (gnnClearConfirmBackdrop) {
    gnnClearConfirmBackdrop.addEventListener('click', (e) => {
      if (e.target === gnnClearConfirmBackdrop) closeGnnClearConfirmModal();
    });
  }
  if (gnnClearResultBackdrop) {
    gnnClearResultBackdrop.addEventListener('click', (e) => {
      if (e.target === gnnClearResultBackdrop) closeGnnClearResultModal();
    });
  }
  if (gnnClearConfirmBtn) {
    gnnClearConfirmBtn.addEventListener('click', async () => {
      closeGnnClearConfirmModal();
      await performGnnClear();
    });
  }
  if (gnnClearResultOk) {
    gnnClearResultOk.addEventListener('click', () => closeGnnClearResultModal());
  }

  function openLeaveModal(href=null) {
    leavePendingHref = href;
    if (leaveBackdrop) { leaveBackdrop.hidden = false; leaveBackdrop.classList.add('open'); }
  }
  function closeLeaveModal() {
    leavePendingHref = null;
    if (leaveBackdrop) { leaveBackdrop.classList.remove('open'); leaveBackdrop.hidden = true; }
  }
  if (leaveCancel) leaveCancel.addEventListener('click', closeLeaveModal);
  if (leaveBackdrop) leaveBackdrop.addEventListener('click', (e) => { if (e.target === leaveBackdrop) closeLeaveModal(); });
  if (leaveConfirm) leaveConfirm.addEventListener('click', async () => {
    allowLeave = true;
    const href = leavePendingHref;
    // остановка серверного процесса перед уходом
    try {
      if (currentRunId) {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 3000);
        try {
          await fetch('/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ run_id: currentRunId }),
            keepalive: true,
            signal: controller.signal,
          }).catch(() => {});
        } finally {
          clearTimeout(t);
        }
      }
    } catch {}
    try { if (abortController) abortController.abort(); } catch {}
    closeLeaveModal();
    if (href) window.location.href = href;
  });

  // Перехватываем клики по внутренним ссылкам
  document.addEventListener('click', (e) => {
    if (!isBusy() || allowLeave) return;
    const a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (!a) return;
    // модификаторы/новая вкладка/якоря/скрипты пропускаем
    const hrefAttr = a.getAttribute('href');
    if (!hrefAttr || hrefAttr.startsWith('#') || hrefAttr.startsWith('javascript:')) return;
    if (a.target === '_blank' || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
    let url;
    try { url = new URL(a.href, window.location.href); } catch { return; }
    if (url.origin !== window.location.origin) return; // внешние ссылки не блокируем модалкой
    e.preventDefault();
    openLeaveModal(a.href);
  }, true);

  // Блокируем перезагрузку/закрытие/переход назад системным диалогом браузера
  window.addEventListener('beforeunload', (e) => {
    if (!isBusy() || allowLeave) return;
    e.preventDefault();
    e.returnValue = '';
    return '';
  });

  // Авто-флип тултипа: если справа мало места, показывать слева
  const TIP_REQ_WIDTH = 420;
  function updateTipSide(el) {
    try {
      const rect = el.getBoundingClientRect();
      const spaceRight = Math.max(0, window.innerWidth - rect.right);
      if (spaceRight < TIP_REQ_WIDTH) el.classList.add('tip-left');
      else el.classList.remove('tip-left');
    } catch {}
  }
  function bindTipAutoFlip(root=document) {
    const tips = root.querySelectorAll('.help-icon[data-tip]');
    tips.forEach(el => {
      el.addEventListener('mouseenter', () => updateTipSide(el));
      el.addEventListener('focus', () => updateTipSide(el));
      // Обновление при ресайзе окна
      window.addEventListener('resize', () => updateTipSide(el));
    });
  }
  bindTipAutoFlip(document);
})();
