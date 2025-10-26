(() => {
  const form = document.getElementById('run-form');
  const runBtn = document.getElementById('run-btn');
  const stopBtn = document.getElementById('stop-btn');
  const output = document.getElementById('output');
  const clearBtn = document.getElementById('clear-btn');

  let abortController = null;
  let currentRunId = null;
  // Запоминаем ключ последней зафиксированной строки прогресса, чтобы не дублировать финал
  let lastFinalKey = null;
  // Флаг: сейчас обрабатываем перерисовку прогресс-бара
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
    return { only, skip, cve_from_year };
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

  async function run() {
    const payload = gatherValues();
    // Генерируем run_id на клиенте, сервер может вернуть свой через заголовок
    currentRunId = `${Date.now()}-${Math.random().toString(16).slice(2,8)}`;
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
    abortController = new AbortController();

    try {
      const resp = await fetch('/run', {
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
      abortController = null;
      currentRunId = null;
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    run();
  });

  // Взаимоисключающие чекбоксы ONLY/SKIP
  form.querySelectorAll('input[name="only"], input[name="skip"]').forEach(cb => {
    cb.addEventListener('change', updateDisable);
  });
  updateDisable();

  stopBtn.addEventListener('click', async () => {
    if (!currentRunId) {
      if (abortController) abortController.abort();
      runBtn.disabled = false;
      stopBtn.disabled = true;
      abortController = null;
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
      abortController = null;
      currentRunId = null;
    }
  });

  clearBtn.addEventListener('click', () => {
    output.textContent = '';
  });
})();
