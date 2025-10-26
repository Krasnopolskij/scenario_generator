(() => {
  const $ = (sel) => document.querySelector(sel);
  const partEl = $('#part');
  const vendorEl = $('#vendor');
  const productEl = $('#product');
  const versionEl = $('#version');
  const partStatus = document.getElementById('part-status');
  const vendorStatus = document.getElementById('vendor-status');
  const productStatus = document.getElementById('product-status');
  const versionStatus = document.getElementById('version-status');
  const vendorSug = $('#vendor-suggest');
  const productSug = $('#product-suggest');
  const versionSug = $('#version-suggest');
  const results = $('#results');
  const picked = $('#picked');
  const form = $('#cpe-form');
  const resetBtn = document.getElementById('reset-btn');
  const resetFiltersBtn = document.getElementById('reset-filters-btn');
  const LS_FILTERS = 'sg:cpe:filters';
  const LS_PICKED = 'sg:cpe:picked';
  const LS_LAST_QUERY = 'sg:cpe:lastQuery';

  function debounce(fn, ms=200) {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  function renderSuggest(container, items, onPick) {
    if (!items || items.length === 0) { container.innerHTML = ''; return; }
    const ul = document.createElement('ul');
    items.forEach(v => {
      const li = document.createElement('li');
      li.textContent = v;
      li.addEventListener('click', () => { onPick(v); container.innerHTML = ''; });
      ul.appendChild(li);
    });
    container.innerHTML = '';
    container.appendChild(ul);
  }

  function setStatus(el, ok) {
    if (!el) return;
    if (ok) { el.classList.add('ok'); el.title = 'Выбрано'; }
    else { el.classList.remove('ok'); el.title = 'Не выбрано'; }
  }

  const fetchJSON = async (url) => {
    const r = await fetch(url);
    if (!r.ok) throw new Error(r.statusText);
    return await r.json();
  };

  // Пагинация подсказок
  const PAGE = 50;
  let vendorOffset = 0, productOffset = 0, versionOffset = 0;

  function renderSuggestList(container, items, onPick, hasMore, onMore, append=false) {
    let ul = container.querySelector('ul');
    if (!ul) { ul = document.createElement('ul'); container.innerHTML = ''; container.appendChild(ul); }
    // Удаляем предыдущую кнопку More, чтобы не дублировать
    const prevMore = ul.querySelector('li.more');
    if (prevMore) prevMore.remove();
    // Если это не дозагрузка — очищаем список
    if (!append) ul.innerHTML = '';
    (items || []).forEach(v => {
      const li = document.createElement('li');
      li.textContent = v;
      li.addEventListener('click', () => { onPick(v); container.innerHTML = ''; });
      ul.appendChild(li);
    });
    if (hasMore) {
      const more = document.createElement('li'); more.className = 'more'; more.textContent = 'Показать ещё';
      more.addEventListener('click', onMore);
      ul.appendChild(more);
    }
  }

  async function loadVendors(reset=true) {
    const part = partEl.value; if (!part) return;
    if (reset) vendorOffset = 0;
    const q = encodeURIComponent(vendorEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/vendors?part=${part}&q=${q}&limit=${PAGE}&offset=${vendorOffset}`);
      renderSuggestList(
        vendorSug,
        data.items,
        (v) => { vendorEl.value = v; setStatus(vendorStatus, true); productEl.value=''; versionEl.value=''; setStatus(productStatus,false); setStatus(versionStatus,false); productSug.innerHTML=''; versionSug.innerHTML=''; productEl.focus(); },
        data.items && data.items.length === PAGE,
        () => { vendorOffset += PAGE; loadVendors(false); },
        !reset ? true : false
      );
    } catch (e) {
      vendorSug.innerHTML = `<div class=\"warn\">Ошибка загрузки: ${e}</div>`;
    }
  }

  async function loadProducts(reset=true) {
    const part = partEl.value; const vendor = vendorEl.value.trim(); if (!part || !vendor) return;
    if (reset) productOffset = 0;
    const q = encodeURIComponent(productEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/products?part=${part}&vendor=${encodeURIComponent(vendor)}&q=${q}&limit=${PAGE}&offset=${productOffset}`);
      renderSuggestList(
        productSug,
        data.items,
        (v) => { productEl.value = v; setStatus(productStatus, true); versionEl.value=''; setStatus(versionStatus,false); versionSug.innerHTML=''; versionEl.focus(); },
        data.items && data.items.length === PAGE,
        () => { productOffset += PAGE; loadProducts(false); },
        !reset ? true : false
      );
    } catch (e) {
      productSug.innerHTML = `<div class=\"warn\">Ошибка загрузки: ${e}</div>`;
    }
  }

  async function loadVersions(reset=true) {
    const part = partEl.value; const vendor = vendorEl.value.trim(); const product = productEl.value.trim(); if (!part || !vendor || !product) return;
    if (reset) versionOffset = 0;
    const q = encodeURIComponent(versionEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/versions?part=${part}&vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}&q=${q}&limit=${PAGE}&offset=${versionOffset}`);
      renderSuggestList(
        versionSug,
        data.items,
        (v) => { versionEl.value = v; setStatus(versionStatus, true); versionSug.innerHTML=''; },
        data.items && data.items.length === PAGE,
        () => { versionOffset += PAGE; loadVersions(false); },
        !reset ? true : false
      );
    } catch (e) {
      versionSug.innerHTML = `<div class=\"warn\">Ошибка загрузки: ${e}</div>`;
    }
  }

  async function suggestVendors() {
    const part = partEl.value; if (!part) return;
    const q = encodeURIComponent(vendorEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/vendors?part=${part}&q=${q}`);
      renderSuggest(vendorSug, data.items, (v) => {
        vendorEl.value = v; setStatus(vendorStatus, true);
        productEl.value=''; versionEl.value=''; setStatus(productStatus, false); setStatus(versionStatus, false);
        productSug.innerHTML=''; versionSug.innerHTML=''; productEl.focus();
      });
    } catch (e) {
      vendorSug.innerHTML = `<div class="warn">Ошибка загрузки: ${e}</div>`;
    }
  }

  async function suggestProducts() {
    const part = partEl.value; const vendor = vendorEl.value.trim(); if (!part || !vendor) return;
    const q = encodeURIComponent(productEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/products?part=${part}&vendor=${encodeURIComponent(vendor)}&q=${q}`);
      renderSuggest(productSug, data.items, (v) => {
        productEl.value = v; setStatus(productStatus, true);
        versionEl.value=''; setStatus(versionStatus, false);
        versionSug.innerHTML=''; versionEl.focus();
      });
    } catch (e) {
      productSug.innerHTML = `<div class="warn">Ошибка загрузки: ${e}</div>`;
    }
  }

  async function suggestVersions() {
    const part = partEl.value; const vendor = vendorEl.value.trim(); const product = productEl.value.trim(); if (!part || !vendor || !product) return;
    const q = encodeURIComponent(versionEl.value.trim());
    try {
      const data = await fetchJSON(`/api/cpe/versions?part=${part}&vendor=${encodeURIComponent(vendor)}&product=${encodeURIComponent(product)}&q=${q}`);
      renderSuggest(versionSug, data.items, (v) => { versionEl.value = v; setStatus(versionStatus, true); versionSug.innerHTML=''; });
    } catch (e) {
      versionSug.innerHTML = `<div class="warn">Ошибка загрузки: ${e}</div>`;
    }
  }

  vendorEl.addEventListener('input', debounce(() => { setStatus(vendorStatus, false); loadVendors(true); }, 200));
  productEl.addEventListener('input', debounce(() => { setStatus(productStatus, false); loadProducts(true); }, 200));
  versionEl.addEventListener('input', debounce(() => { setStatus(versionStatus, false); loadVersions(true); }, 200));
  // Показ вариантов при фокусе
  vendorEl.addEventListener('focus', () => loadVendors(true));
  productEl.addEventListener('focus', () => loadProducts(true));
  versionEl.addEventListener('focus', () => loadVersions(true));
  partEl.addEventListener('change', () => {
    setStatus(partStatus, !!partEl.value);
    vendorEl.value=''; productEl.value=''; versionEl.value='';
    setStatus(vendorStatus, false); setStatus(productStatus, false); setStatus(versionStatus, false);
    vendorSug.innerHTML=''; productSug.innerHTML=''; versionSug.innerHTML=''; vendorEl.focus();
  });

  // Скрыть подсказки при клике вне
  document.addEventListener('click', (e) => {
    const targets = [vendorEl, productEl, versionEl, vendorSug, productSug, versionSug];
    if (!targets.some(t => t && (t === e.target || (t.contains && t.contains(e.target))))) {
      vendorSug.innerHTML=''; productSug.innerHTML=''; versionSug.innerHTML='';
    }
  }, true);

  // Храним ссылки на кнопки в результатах, чтобы менять их цвет при выборе/удалении
  const btnByCpe = new Map();

  function setBtnSelected(btn, on) {
    if (!btn) return;
    btn.classList.toggle('selected', !!on);
    btn.textContent = on ? 'Выбрано' : 'Выбрать';
  }

  function renderResults(items) {
    btnByCpe.clear();
    if (!items || items.length === 0) { results.innerHTML = '<div class="muted">Ничего не найдено</div>'; return; }

    const seen = new Set();
    const frag = document.createDocumentFragment();
    items.forEach(row => {
      if (!row || !row.cpe23Uri || seen.has(row.cpe23Uri)) return;
      seen.add(row.cpe23Uri);
      const div = document.createElement('div');
      div.className = 'row';
      const left = document.createElement('div');
      left.textContent = row.cpe23Uri;
      const right = document.createElement('div');
      const btn = document.createElement('button');
      btn.textContent = 'Выбрать';
      btn.dataset.cpe = row.cpe23Uri;

      if (pickedSet.has(row.cpe23Uri)) setBtnSelected(btn, true);
      right.appendChild(btn);
      div.appendChild(left); div.appendChild(right);
      frag.appendChild(div);
      btnByCpe.set(row.cpe23Uri, btn);
    });
    results.innerHTML = '';
    results.appendChild(frag);
  }

  const pickedSet = new Set();
  const pickedMap = new Map();
  const modal = document.getElementById('graph-confirm-backdrop');
  const modalCancel = document.getElementById('modal-cancel');
  const modalConfirm = document.getElementById('modal-confirm');
  let pendingCpeToVisualize = null;

  function saveFilters() {
    try {
      const data = {
        part: partEl.value || '',
        vendor: vendorEl.value || '',
        product: productEl.value || '',
        version: versionEl.value || ''
      };
      localStorage.setItem(LS_FILTERS, JSON.stringify(data));
    } catch (e) { console.warn('ls save cpe filters', e); }
  }

  function loadFilters() {
    try {
      const raw = localStorage.getItem(LS_FILTERS);
      if (!raw) return;
      const d = JSON.parse(raw);
      if (d && typeof d === 'object') {
        if (d.part) { partEl.value = d.part; setStatus(partStatus, !!d.part); }
        if (typeof d.vendor === 'string') { vendorEl.value = d.vendor; setStatus(vendorStatus, !!d.vendor); }
        if (typeof d.product === 'string') { productEl.value = d.product; setStatus(productStatus, !!d.product); }
        if (typeof d.version === 'string') { versionEl.value = d.version; setStatus(versionStatus, !!d.version); }
      }
    } catch (e) { console.warn('ls load cpe filters', e); }
  }

  function openModal(cpe) {
    pendingCpeToVisualize = cpe;
    if (modal) { modal.hidden = false; modal.classList.add('open'); }
  }

  function closeModal() {
    pendingCpeToVisualize = null;
    if (modal) { modal.classList.remove('open'); modal.hidden = true; }
  }

  if (modalCancel) modalCancel.addEventListener('click', closeModal);
  if (modal) modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });
  if (modalConfirm) modalConfirm.addEventListener('click', () => {
    if (!pendingCpeToVisualize) { closeModal(); return; }
    const uri = encodeURIComponent(pendingCpeToVisualize);
    closeModal();
    // Переходим на страницу графа, передаём cpe через query
    window.location.href = `/graph?cpe=${uri}`;
  });

  function removePicked(cpe) {
    if (!pickedSet.has(cpe)) return;
    pickedSet.delete(cpe);
    const li = pickedMap.get(cpe);
    if (li && li.remove) li.remove();
    pickedMap.delete(cpe);
    const btn = btnByCpe.get(cpe);
    if (btn) setBtnSelected(btn, false);
    try { localStorage.setItem(LS_PICKED, JSON.stringify(Array.from(pickedSet))); } catch (e) { console.warn('ls save picked', e); }
  }

  function addPicked(cpe) {
    if (pickedSet.has(cpe)) return;
    pickedSet.add(cpe);
    const li = document.createElement('li');
    li.dataset.cpe = cpe;

    const txt = document.createElement('span');
    txt.textContent = cpe;
    txt.style.wordBreak = 'break-all';
    const actions = document.createElement('span');
    actions.className = 'picked-actions';
    const show = document.createElement('button');
    show.textContent = 'Отобразить связи';
    show.className = 'btn-link';
    show.addEventListener('click', (e) => { e.preventDefault(); openModal(cpe); });
    const rm = document.createElement('button');
    rm.textContent = '×';
    rm.addEventListener('click', () => removePicked(cpe));
    actions.appendChild(show);
    actions.appendChild(rm);
    li.appendChild(txt);
    li.appendChild(actions);
    picked.appendChild(li);
    pickedMap.set(cpe, li);
    try { localStorage.setItem(LS_PICKED, JSON.stringify(Array.from(pickedSet))); } catch (e) { console.warn('ls save picked', e); }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const part = partEl.value; if (!part) return;
    const vendor = vendorEl.value.trim();
    const product = productEl.value.trim();
    const version = versionEl.value.trim();
    const params = new URLSearchParams({ part });
    if (vendor) params.append('vendor', vendor);
    if (product) params.append('product', product);
    if (version) params.append('version', version);
    try { localStorage.setItem(LS_LAST_QUERY, JSON.stringify({ part, vendor, product, version })); } catch (e2) { console.warn('ls save lastQuery', e2); }
    saveFilters();
    try {
      const data = await fetchJSON(`/api/cpe/search?${params.toString()}`);
      renderResults(data.items);
    } catch (err) {
      results.textContent = `Ошибка: ${err}`;
    }
  });

  // Делегирование клика по кнопкам в списке результатов
  results.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest('button');
    if (!btn || !btn.dataset || !btn.dataset.cpe) return;
    const cpe = btn.dataset.cpe;
    if (pickedSet.has(cpe)) {
      // Повторный клик — удалить из выбранных
      removePicked(cpe);
    } else {
      addPicked(cpe);
      setBtnSelected(btn, true);
    }
  });

  // Сбросы
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      partEl.value = '';
      setStatus(partStatus, false);
      vendorEl.value=''; productEl.value=''; versionEl.value='';
      setStatus(vendorStatus, false); setStatus(productStatus, false); setStatus(versionStatus, false);
      vendorSug.innerHTML=''; productSug.innerHTML=''; versionSug.innerHTML='';
      results.innerHTML=''; picked.innerHTML='';
      pickedSet.clear();
      pickedMap.clear();
      if (btnByCpe) btnByCpe.clear();
      partEl.focus();
      try { localStorage.removeItem(LS_FILTERS); } catch (e) { console.warn('ls clear filters', e); }
      try { localStorage.removeItem(LS_PICKED); } catch (e) { console.warn('ls clear picked', e); }
      try { localStorage.removeItem(LS_LAST_QUERY); } catch (e) { console.warn('ls clear lastQuery', e); }
    });
  }

  if (resetFiltersBtn) {
    resetFiltersBtn.addEventListener('click', () => {
      partEl.value = '';
      setStatus(partStatus, false);
      vendorEl.value=''; productEl.value=''; versionEl.value='';
      setStatus(vendorStatus, false); setStatus(productStatus, false); setStatus(versionStatus, false);
      vendorSug.innerHTML=''; productSug.innerHTML=''; versionSug.innerHTML='';
      try { localStorage.removeItem(LS_FILTERS); } catch (e) { console.warn('ls clear filters', e); }
      partEl.focus();
    });
  }

  // Автовосстановление
  loadFilters();
  try {
    const raw = localStorage.getItem(LS_PICKED);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) arr.forEach(cpe => addPicked(cpe));
    }
  } catch (e) { console.warn('ls load picked', e); }

  try {
    const qraw = localStorage.getItem(LS_LAST_QUERY);
    const q = qraw ? JSON.parse(qraw) : null;
    if (q && q.part) {
      const p = new URLSearchParams({ part: q.part });
      if (q.vendor) p.append('vendor', q.vendor);
      if (q.product) p.append('product', q.product);
      if (q.version) p.append('version', q.version);
      fetchJSON(`/api/cpe/search?${p.toString()}`).then(d => renderResults(d.items)).catch(() => {});
    }
  } catch (e) { console.warn('ls load lastQuery', e); }

  // Сохранение фильтров по вводу
  partEl.addEventListener('change', saveFilters);
  vendorEl.addEventListener('input', debounce(saveFilters, 150));
  productEl.addEventListener('input', debounce(saveFilters, 150));
  versionEl.addEventListener('input', debounce(saveFilters, 150));
})();
