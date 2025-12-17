(() => {
  const $ = (sel) => document.querySelector(sel);
  const nameInput = $('#target-name');
  const cveText = $('#cve-text');
  const fileInput = $('#cve-file');
  const dropzone = $('#file-drop');
  const fileStatus = $('#file-status');
  const checkBtn = $('#check-btn');
  const goBtn = $('#go-btn');
  const clearBtn = $('#clear-btn');
  const checkResult = $('#check-result');

  const uploadBackdrop = $('#upload-backdrop');
  const uploadStatus = $('#upload-status');
  const uploadBar = $('#upload-bar');
  const uploadCancel = $('#upload-cancel');
  const uploadClose = $('#upload-close');

  const confirmBackdrop = $('#target-confirm-backdrop');
  const confirmBody = $('#target-confirm-body');
  const confirmCancel = $('#target-confirm-cancel');
  const confirmOk = $('#target-confirm-ok');

  const cleanupConfirmBackdrop = $('#cleanup-confirm-backdrop');
  const cleanupConfirmBody = $('#cleanup-confirm-body');
  const cleanupCancel = $('#cleanup-cancel');
  const cleanupConfirm = $('#cleanup-confirm');
  const cleanupResultBackdrop = $('#cleanup-result-backdrop');
  const cleanupResultBody = $('#cleanup-result-body');
  const cleanupResultClose = $('#cleanup-result-close');
  const cleanupOldBtn = $('#cleanup-old-btn');
  const cleanupAllBtn = $('#cleanup-all-btn');

  const searchInput = $('#target-search');
  const searchSuggest = $('#target-suggest');

  const NAME_RE = /^[A-Za-z0-9._-]{3,64}$/;
  const PAGE = 50;

  let uploadXhr = null;
  let uploadInProgress = false;
  let uploadedCves = [];
  let confirmAction = null;
  let searchOffset = 0;
  let cleanupMode = null;

  function debounce(fn, ms=200) {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  function setCheckResult(lines, kind) {
    if (!checkResult) return;
    checkResult.innerHTML = '';
    checkResult.classList.remove('ok', 'warn', 'err');
    if (kind) checkResult.classList.add(kind);
    (lines || []).forEach((text) => {
      const div = document.createElement('div');
      div.textContent = text;
      checkResult.appendChild(div);
    });
  }

  function setError(text) {
    setCheckResult([text], 'err');
  }

  function buildPayload() {
    return {
      name: (nameInput.value || '').trim(),
      cves_text: (cveText.value || ''),
      file_cves: uploadedCves || [],
    };
  }

  function validateName() {
    const name = (nameInput.value || '').trim();
    if (name && !NAME_RE.test(name)) {
      return 'Имя должно иметь длину 3 до 64 символов. Допустимы латиница, цифры, точки, дефисы и подчёркивания.';
    }
    return null;
  }

  const fetchJSON = async (url, opts) => {
    const r = await fetch(url, opts);
    if (!r.ok) {
      let msg = `${r.status} ${r.statusText}`;
      try {
        const data = await r.json();
        if (data && data.error) msg = data.error;
      } catch {}
      throw new Error(msg);
    }
    return await r.json();
  };

  function openBackdrop(el) {
    if (!el) return;
    el.removeAttribute('hidden');
    el.classList.add('open');
  }

  function closeBackdrop(el) {
    if (!el) return;
    el.classList.remove('open');
    el.setAttribute('hidden', '');
  }

  function setUploadState({ text, progress, canCancel, canClose }) {
    if (uploadStatus) uploadStatus.textContent = text || '';
    if (uploadBar) uploadBar.style.width = `${Math.max(0, Math.min(100, progress || 0))}%`;
    if (uploadCancel) uploadCancel.disabled = !canCancel;
    if (uploadClose) uploadClose.disabled = !canClose;
  }

  function clearUploadState(message) {
    uploadedCves = [];
    if (fileInput) fileInput.value = '';
    if (fileStatus) fileStatus.textContent = message || '';
  }

  function startUpload(file) {
    if (!file) return;
    const ext = String(file.name || '').toLowerCase();
    if (!ext.endsWith('.xml')) {
      clearUploadState('Поддерживается только XML файл');
      return;
    }
    if (uploadXhr) {
      try { uploadXhr.abort(); } catch {}
    }
    setCheckResult([], null);
    if (fileStatus) fileStatus.textContent = `Файл: ${file.name}, загрузка…`;
    uploadInProgress = true;
    setUploadState({ text: 'Загрузка файла…', progress: 0, canCancel: true, canClose: false });
    openBackdrop(uploadBackdrop);

    uploadXhr = new XMLHttpRequest();
    uploadXhr.open('POST', '/api/targets/parse', true);
    uploadXhr.responseType = 'json';
    uploadXhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      const pct = Math.round((e.loaded / e.total) * 100);
      setUploadState({ text: `Загрузка файла… ${pct}%`, progress: pct, canCancel: true, canClose: false });
    };
    uploadXhr.onload = () => {
      uploadInProgress = false;
      if (uploadXhr.status >= 200 && uploadXhr.status < 300) {
        const data = uploadXhr.response || {};
        const items = Array.isArray(data.items) ? data.items : [];
        if (!items.length) {
          clearUploadState('Файл загружен, но CVE не найдены');
          setUploadState({ text: 'CVE не найдены в файле', progress: 100, canCancel: false, canClose: true });
        } else {
          uploadedCves = items;
          if (fileStatus) fileStatus.textContent = `Файл: ${file.name}, CVE: ${items.length}`;
          setUploadState({ text: 'Файл успешно загружен', progress: 100, canCancel: false, canClose: true });
        }
      } else {
        clearUploadState('Ошибка загрузки файла');
        setUploadState({ text: 'Ошибка загрузки файла', progress: 0, canCancel: false, canClose: true });
      }
      uploadXhr = null;
    };
    uploadXhr.onerror = () => {
      uploadInProgress = false;
      clearUploadState('Ошибка загрузки файла');
      setUploadState({ text: 'Ошибка загрузки файла', progress: 0, canCancel: false, canClose: true });
      uploadXhr = null;
    };
    uploadXhr.onabort = () => {
      uploadInProgress = false;
      clearUploadState('Загрузка отменена');
      setUploadState({ text: 'Загрузка отменена', progress: 0, canCancel: false, canClose: true });
      uploadXhr = null;
    };

    const form = new FormData();
    form.append('file', file);
    uploadXhr.send(form);
  }

  async function runCheck(renderToModal) {
    if (uploadInProgress) {
      if (renderToModal) {
        confirmBody.textContent = 'Дождитесь завершения загрузки файла';
        confirmOk.disabled = true;
        openBackdrop(confirmBackdrop);
      } else {
        setError('Дождитесь завершения загрузки файла');
      }
      return null;
    }
    const nameErr = validateName();
    if (nameErr) {
      if (renderToModal) {
        confirmBody.textContent = nameErr;
        confirmOk.disabled = true;
        openBackdrop(confirmBackdrop);
      } else {
        setError(nameErr);
      }
      return null;
    }
    const payload = buildPayload();
    let data;
    try {
      data = await fetchJSON('/api/targets/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      if (renderToModal) {
        confirmBody.textContent = `Ошибка проверки: ${e.message}`;
        confirmOk.disabled = true;
        openBackdrop(confirmBackdrop);
      } else {
        setError(`Ошибка проверки: ${e.message}`);
      }
      return null;
    }

    if (data.generated_name && data.name) {
      nameInput.value = data.name;
    }

    const lines = [];
    lines.push(`Имя объекта: ${data.name || '-'}`);
    lines.push(`Найдено CVE: ${data.found} из ${data.total}`);
    lines.push(`Отсутствует CVE: ${data.missing}`);
    lines.push(data.exists ? 'Статус: объект будет обновлён' : 'Статус: объект будет создан');
    if (data.missing > 0) {
      lines.push('Рекомендуется обновить базу');
    }

    if (renderToModal) {
      confirmBody.innerHTML = '';
      lines.forEach((text) => {
        const div = document.createElement('div');
        div.textContent = text;
        confirmBody.appendChild(div);
      });
      confirmOk.disabled = !(data.found > 0);
      openBackdrop(confirmBackdrop);
    } else {
      setCheckResult(lines, data.missing > 0 ? 'warn' : 'ok');
    }
    return { payload, data };
  }

  async function createTarget(payload) {
    try {
      const data = await fetchJSON('/api/targets/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (data && data.target_uri) {
        window.location.href = `/generation?cpe=${encodeURIComponent(data.target_uri)}`;
      }
    } catch (e) {
      confirmBody.textContent = `Ошибка создания объекта: ${e.message}`;
      confirmOk.disabled = true;
      openBackdrop(confirmBackdrop);
    }
  }

  function openConfirmForExisting(item) {
    confirmBody.innerHTML = '';
    if (searchSuggest) searchSuggest.innerHTML = '';
    const lines = [
      `Имя объекта: ${item.name || '-'}`,
      `Найдено CVE: ${item.found_count} из ${item.input_total}`,
      `Отсутствует CVE: ${item.missing_count}`,
    ];
    if (item.missing_count > 0) {
      lines.push('Рекомендуется обновить базу');
    }
    lines.forEach((text) => {
      const div = document.createElement('div');
      div.textContent = text;
      confirmBody.appendChild(div);
    });
    confirmOk.disabled = !(item.found_count > 0);
    confirmAction = () => {
      window.location.href = `/generation?cpe=${encodeURIComponent(item.target_uri)}`;
    };
    openBackdrop(confirmBackdrop);
  }

  function renderSuggestList(container, items, onPick, hasMore, onMore, append=false) {
    let ul = container.querySelector('ul');
    if (!ul) { ul = document.createElement('ul'); container.innerHTML = ''; container.appendChild(ul); }
    const prevMore = ul.querySelector('li.more');
    if (prevMore) prevMore.remove();
    if (!append) ul.innerHTML = '';
    (items || []).forEach(it => {
      const li = document.createElement('li');
      const title = document.createElement('div');
      title.className = 'target-suggest-title';
      title.textContent = it.name || '';
      const meta = document.createElement('div');
      meta.className = 'target-suggest-meta';
      meta.textContent = `CVE: ${it.found_count}/${it.input_total}, отсутствует: ${it.missing_count}`;
      li.appendChild(title);
      li.appendChild(meta);
      li.addEventListener('click', () => onPick(it));
      ul.appendChild(li);
    });
    if (hasMore) {
      const more = document.createElement('li');
      more.className = 'more';
      more.textContent = 'Показать ещё';
      more.addEventListener('click', onMore);
      ul.appendChild(more);
    }
  }

  async function loadTargets(reset=true) {
    if (!searchSuggest || !searchInput) return;
    if (reset) searchOffset = 0;
    const q = encodeURIComponent(searchInput.value.trim());
    try {
      const data = await fetchJSON(`/api/targets/search?q=${q}&limit=${PAGE}&offset=${searchOffset}`);
      renderSuggestList(
        searchSuggest,
        data.items || [],
        (it) => openConfirmForExisting(it),
        (data.items && data.items.length === PAGE),
        () => { searchOffset += PAGE; loadTargets(false); },
        !reset ? true : false
      );
    } catch (e) {
      searchSuggest.innerHTML = `<div class="warn">Ошибка поиска: ${e.message}</div>`;
    }
  }

  function bindDropzone() {
    if (!dropzone || !fileInput) return;
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag');
      const file = (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) || null;
      if (file) startUpload(file);
    });
    fileInput.addEventListener('change', () => {
      const file = fileInput.files && fileInput.files[0];
      if (file) startUpload(file);
    });
  }

  function clearForm() {
    if (uploadXhr) {
      try { uploadXhr.abort(); } catch {}
    }
    nameInput.value = '';
    cveText.value = '';
    clearUploadState('');
    setCheckResult([], null);
  }

  checkBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    await runCheck(false);
  });

  goBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    const result = await runCheck(true);
    if (!result) {
      confirmAction = null;
      return;
    }
    confirmAction = () => createTarget(result.payload);
  });

  confirmOk.addEventListener('click', (e) => {
    e.preventDefault();
    if (confirmAction) confirmAction();
  });
  confirmCancel.addEventListener('click', () => {
    confirmAction = null;
    closeBackdrop(confirmBackdrop);
  });

  clearBtn.addEventListener('click', (e) => {
    e.preventDefault();
    clearForm();
  });

  uploadCancel.addEventListener('click', (e) => {
    e.preventDefault();
    if (uploadXhr) {
      try { uploadXhr.abort(); } catch {}
    }
  });
  uploadClose.addEventListener('click', (e) => {
    e.preventDefault();
    closeBackdrop(uploadBackdrop);
  });

  cleanupOldBtn.addEventListener('click', () => {
    cleanupMode = 'older_than';
    cleanupConfirmBody.textContent = 'Удалить все созданные объекты из базы данных старше 10 дней?';
    openBackdrop(cleanupConfirmBackdrop);
  });
  cleanupAllBtn.addEventListener('click', () => {
    cleanupMode = 'all';
    cleanupConfirmBody.textContent = 'Удалить все созданные объекты из базы данных?';
    openBackdrop(cleanupConfirmBackdrop);
  });
  cleanupCancel.addEventListener('click', () => closeBackdrop(cleanupConfirmBackdrop));
  cleanupConfirm.addEventListener('click', async () => {
    closeBackdrop(cleanupConfirmBackdrop);
    if (!cleanupMode) return;
    try {
      const payload = cleanupMode === 'older_than' ? { mode: cleanupMode, days: 10 } : { mode: cleanupMode };
      const data = await fetchJSON('/api/targets/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      cleanupResultBody.textContent = `Удалено объектов: ${data.deleted || 0}`;
      openBackdrop(cleanupResultBackdrop);
      loadTargets(true);
    } catch (e) {
      cleanupResultBody.textContent = `Ошибка очистки: ${e.message}`;
      openBackdrop(cleanupResultBackdrop);
    }
  });
  cleanupResultClose.addEventListener('click', () => closeBackdrop(cleanupResultBackdrop));

  if (searchInput) {
    searchInput.addEventListener('input', debounce(() => loadTargets(true), 200));
    searchInput.addEventListener('focus', () => loadTargets(true));
  }
  if (nameInput) nameInput.addEventListener('input', () => setCheckResult([], null));
  if (cveText) cveText.addEventListener('input', () => setCheckResult([], null));
  document.addEventListener('click', (e) => {
    const targets = [searchInput, searchSuggest];
    if (!targets.some(t => t && (t === e.target || (t.contains && t.contains(e.target))))) {
      if (searchSuggest) searchSuggest.innerHTML = '';
    }
  }, true);

  bindDropzone();
})();
