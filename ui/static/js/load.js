(() => {
  const form = document.getElementById('run-form');
  const runBtn = document.getElementById('run-btn');
  const stopBtn = document.getElementById('stop-btn');
  const refreshBtn = document.getElementById('refresh-epss-kev-btn');
  const gnnRunBtn = document.getElementById('gnn-run-btn');
  const gnnStopBtn = document.getElementById('gnn-stop-btn');
  const gnnClearBtn = document.getElementById('gnn-clear-btn');
  const gnnRocBtn = document.getElementById('gnn-roc-btn');
  const output = document.getElementById('output');
  const clearBtn = document.getElementById('clear-btn');
  const LS_KEY = 'sg:data:filters';

  let abortController = null;
  let currentRunId = null;
  let currentJobKind = null; // 'load' | 'refresh' | 'gnn' | null
  let gnnRecovered = false;
  let gnnPollInFlight = false;
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
    if (refreshBtn) refreshBtn.disabled = true;
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
      if (refreshBtn) refreshBtn.disabled = false;
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

  if (refreshBtn) {
    refreshBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (currentRunId) return;
      runRefresh();
    });
  }

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
      if (refreshBtn) refreshBtn.disabled = false;
      stopBtn.disabled = true;
      abortController = null;
      return;
    }
    if (currentJobKind !== 'load' && currentJobKind !== 'refresh') {
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
      if (refreshBtn) refreshBtn.disabled = false;
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

  async function runRefresh() {
    if (currentRunId) return;

    const payload = {};
    currentRunId = `${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
    currentJobKind = 'refresh';
    payload.run_id = currentRunId;
    try {
      const rect = output.getBoundingClientRect();
      const px = rect.width || window.innerWidth || 800;
      const cols = Math.max(60, Math.floor(px / 8));
      payload.columns = cols;
    } catch {}

    output.textContent = '';
    runBtn.disabled = true;
    if (refreshBtn) refreshBtn.disabled = true;
    stopBtn.disabled = false;
    if (gnnRunBtn) gnnRunBtn.disabled = true;
    if (gnnStopBtn) gnnStopBtn.disabled = true;
    if (gnnClearBtn) gnnClearBtn.disabled = true;
    abortController = new AbortController();

    try {
      const resp = await fetch('/run/refresh_epss_kev', {
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
        append(`Ошибка запуска обновления: ${msg}\n`);
        return;
      }
      if (!resp.body) {
        append(`Ошибка запуска обновления: пустой ответ сервера\n`);
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
      append(`\n[client error refresh] ${err}\n`);
    } finally {
      runBtn.disabled = false;
      if (refreshBtn) refreshBtn.disabled = false;
      stopBtn.disabled = true;
      if (gnnRunBtn) gnnRunBtn.disabled = false;
      if (gnnStopBtn) gnnStopBtn.disabled = true;
      if (gnnClearBtn) gnnClearBtn.disabled = false;
      abortController = null;
      currentRunId = null;
      currentJobKind = null;
    }
  }

  async function runGnn() {
    if (currentRunId) return;

    const payload = {};
    currentRunId = `${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
    currentJobKind = 'gnn';
    gnnRecovered = false;
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
    if (refreshBtn) refreshBtn.disabled = true;
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
      if (refreshBtn) refreshBtn.disabled = false;
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
        if (refreshBtn) refreshBtn.disabled = false;
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
  const gnnResumeBackdrop = document.getElementById('gnn-resume-backdrop');
  const gnnResumeMessage = document.getElementById('gnn-resume-message');
  const gnnResumeOk = document.getElementById('gnn-resume-ok');
  const gnnRocBackdrop = document.getElementById('gnn-roc-backdrop');
  const gnnRocMessage = document.getElementById('gnn-roc-message');
  const gnnRocStats = document.getElementById('gnn-roc-stats');
  const gnnRocCanvas = document.getElementById('gnn-roc-canvas');
  const gnnRocClose = document.getElementById('gnn-roc-close');

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

  function openGnnResumeModal(message) {
    if (!gnnResumeBackdrop) return;
    if (gnnResumeMessage && message) gnnResumeMessage.textContent = message;
    gnnResumeBackdrop.hidden = false;
    gnnResumeBackdrop.classList.add('open');
  }
  function closeGnnResumeModal() {
    if (!gnnResumeBackdrop) return;
    gnnResumeBackdrop.classList.remove('open');
    gnnResumeBackdrop.hidden = true;
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
  if (gnnResumeBackdrop) {
    gnnResumeBackdrop.addEventListener('click', (e) => {
      if (e.target === gnnResumeBackdrop) closeGnnResumeModal();
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
  if (gnnResumeOk) {
    gnnResumeOk.addEventListener('click', () => closeGnnResumeModal());
  }

  async function restoreGnnState() {
    if (currentRunId || currentJobKind) return;
    try {
      const resp = await fetch('/gnn/status', { method: 'GET' });
      if (!resp.ok) return;
      const data = await resp.json();
      if (!data || data.status !== 'running' || !data.run_id) return;

      currentRunId = data.run_id;
      currentJobKind = 'gnn';
      gnnRecovered = true;
      if (gnnRunBtn) gnnRunBtn.disabled = true;
      if (gnnStopBtn) gnnStopBtn.disabled = false;
      if (gnnClearBtn) gnnClearBtn.disabled = true;
      runBtn.disabled = true;
      if (refreshBtn) refreshBtn.disabled = true;
      stopBtn.disabled = true;

      let note = 'Обнаружен запущенный процесс GNN. Поток логов был потерян (страница или сервис были перезагружены).';
      if (data.started_at) {
        try {
          const when = new Date(data.started_at).toLocaleString();
          note += ` Время старта: ${when}.`;
        } catch {}
      }
      note += ' Управление восстановлено — вы можете остановить процесс.';
      openGnnResumeModal(note);
      append(`\n[info] GNN уже запущен (run_id=${data.run_id})\n`);
    } catch {}
  }

  async function pollRecoveredGnn() {
    if (!gnnRecovered || currentJobKind !== 'gnn' || !currentRunId) return;
    if (gnnPollInFlight) return;
    gnnPollInFlight = true;
    try {
      const resp = await fetch('/gnn/status', { method: 'GET' });
      if (!resp.ok) return;
      const data = await resp.json();
      if (!data || data.status !== 'running') {
        append(`\n[info] GNN завершен (run_id=${currentRunId})\n`);
        currentRunId = null;
        currentJobKind = null;
        gnnRecovered = false;
        if (gnnRunBtn) gnnRunBtn.disabled = false;
        if (gnnStopBtn) gnnStopBtn.disabled = true;
        if (gnnClearBtn) gnnClearBtn.disabled = false;
        runBtn.disabled = false;
        if (refreshBtn) refreshBtn.disabled = false;
        stopBtn.disabled = true;
        return;
      }
      if (data.run_id && data.run_id !== currentRunId) {
        currentRunId = data.run_id;
        let note = 'Обнаружен другой запущенный процесс GNN. Поток логов недоступен.';
        note += ` Текущий run_id: ${data.run_id}.`;
        openGnnResumeModal(note);
        append(`\n[info] GNN процесс изменился (run_id=${data.run_id})\n`);
      }
    } catch {} finally {
      gnnPollInFlight = false;
    }
  }

  function openGnnRocModal() {
    if (!gnnRocBackdrop) return;
    gnnRocBackdrop.hidden = false;
    gnnRocBackdrop.classList.add('open');
  }
  function closeGnnRocModal() {
    if (!gnnRocBackdrop) return;
    gnnRocBackdrop.classList.remove('open');
    gnnRocBackdrop.hidden = true;
  }
  function setRocMessage(message) {
    if (!gnnRocMessage) return;
    gnnRocMessage.textContent = message || '';
    gnnRocMessage.hidden = !message;
  }
  function setRocStats(text) {
    if (!gnnRocStats) return;
    gnnRocStats.textContent = '';
    if (!text) {
      gnnRocStats.hidden = true;
      return;
    }
    gnnRocStats.hidden = false;
    const parts = Array.isArray(text) ? text : [text];
    parts.forEach((part) => {
      const span = document.createElement('span');
      span.className = 'roc-pill';
      span.textContent = part;
      gnnRocStats.appendChild(span);
    });
  }

  function getCssVar(name, fallback) {
    const val = getComputedStyle(document.body).getPropertyValue(name).trim();
    return val || fallback;
  }

  function drawRocCurve(canvas, data) {
    if (!canvas || !data) return;
    const fpr = Array.isArray(data.fpr) ? data.fpr : [];
    const tpr = Array.isArray(data.tpr) ? data.tpr : [];
    if (!fpr.length || !tpr.length) throw new Error('Нет данных для графика.');

    const rect = canvas.getBoundingClientRect();
    const width = Math.max(320, Math.floor(rect.width || 640));
    const height = Math.max(220, Math.floor(width * 0.62));
    const dpr = window.devicePixelRatio || 1;

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const colors = {
      bg: getCssVar('--surface-soft', '#0f1326'),
      axis: getCssVar('--line-soft', '#1d2342'),
      diag: getCssVar('--muted', '#9aa0b4'),
      curve: getCssVar('--accent', '#4f8cff'),
      text: getCssVar('--text', '#e5e7ef'),
      muted: getCssVar('--muted', '#9aa0b4'),
    };

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = colors.bg;
    ctx.fillRect(0, 0, width, height);

    const margin = { left: 50, right: 18, top: 16, bottom: 38 };
    const plotW = Math.max(10, width - margin.left - margin.right);
    const plotH = Math.max(10, height - margin.top - margin.bottom);

    ctx.strokeStyle = colors.axis;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, margin.top + plotH);
    ctx.lineTo(margin.left + plotW, margin.top + plotH);
    ctx.stroke();

    ctx.save();
    ctx.setLineDash([6, 6]);
    ctx.strokeStyle = colors.diag;
    ctx.lineWidth = 2;
    ctx.globalAlpha = 0.55;
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top + plotH);
    ctx.lineTo(margin.left + plotW, margin.top);
    ctx.stroke();
    ctx.restore();

    ctx.strokeStyle = colors.curve;
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < Math.min(fpr.length, tpr.length); i++) {
      const x = margin.left + Number(fpr[i]) * plotW;
      const y = margin.top + (1 - Number(tpr[i])) * plotH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();

    ctx.fillStyle = colors.text;
    ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif';
    ctx.fillText('FPR', margin.left + plotW / 2 - 10, margin.top + plotH + 26);
    ctx.save();
    ctx.translate(16, margin.top + plotH / 2 + 10);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('TPR', 0, 0);
    ctx.restore();

    ctx.fillStyle = colors.muted;
    ctx.fillText('0', margin.left - 10, margin.top + plotH + 14);
    ctx.fillText('1', margin.left + plotW - 6, margin.top + plotH + 14);
    ctx.fillText('1', margin.left - 14, margin.top + 8);
  }

  async function loadRocData() {
    setRocMessage('Загрузка ROC-AUC...');
    setRocStats(null);
    if (gnnRocCanvas) gnnRocCanvas.hidden = true;

    let resp;
    try {
      resp = await fetch('/gnn/roc-auc', { method: 'GET' });
    } catch (err) {
      setRocMessage(`Не удалось загрузить ROC-AUC: ${err}`);
      return;
    }

    let data = null;
    try {
      data = await resp.json();
    } catch (err) {
      setRocMessage(`Не удалось разобрать ответ сервера: ${err}`);
      return;
    }

    if (!resp.ok) {
      setRocMessage(data && data.error ? data.error : `Ошибка загрузки (${resp.status})`);
      return;
    }

    if (!data || data.status !== 'ok') {
      const msg = (data && data.error) ? data.error : 'ROC-AUC данные пока недоступны.';
      setRocMessage(msg);
      return;
    }

    const meta = data.meta || {};
    const auc = typeof data.auc === 'number' ? data.auc.toFixed(4) : 'n/a';
    const parts = [`AUC: ${auc}`];
    if (meta.mode) parts.push(`Режим: ${meta.mode}`);
    if (typeof meta.pos_test === 'number' && typeof meta.neg_test === 'number') {
      parts.push(`test: +${meta.pos_test} / -${meta.neg_test}`);
    }
    if (meta.created_at) {
      const dt = new Date(meta.created_at);
      if (!Number.isNaN(dt.getTime())) {
        parts.push(`Обновлено: ${dt.toLocaleString()}`);
      }
    }
    setRocStats(parts);
    setRocMessage(null);
    if (gnnRocCanvas) {
      gnnRocCanvas.hidden = false;
      requestAnimationFrame(() => {
        try {
          drawRocCurve(gnnRocCanvas, data);
        } catch (err) {
          gnnRocCanvas.hidden = true;
          setRocMessage(`Не удалось построить график: ${err}`);
        }
      });
    }
  }

  if (gnnRocBtn) {
    gnnRocBtn.addEventListener('click', async () => {
      openGnnRocModal();
      await loadRocData();
    });
  }
  if (gnnRocClose) gnnRocClose.addEventListener('click', () => closeGnnRocModal());
  if (gnnRocBackdrop) {
    gnnRocBackdrop.addEventListener('click', (e) => {
      if (e.target === gnnRocBackdrop) closeGnnRocModal();
    });
  }

  restoreGnnState();
  setInterval(pollRecoveredGnn, 5000);

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
