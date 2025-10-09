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

  function renderResults(items) {
    if (!items || items.length === 0) { results.innerHTML = '<div class="muted">Ничего не найдено</div>'; return; }
    // Убираем дубли по cpe23Uri на всякий случай
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
      btn.textContent = 'Добавить';
      btn.addEventListener('click', () => addPicked(row.cpe23Uri));
      right.appendChild(btn);
      div.appendChild(left); div.appendChild(right);
      frag.appendChild(div);
    });
    results.innerHTML = '';
    results.appendChild(frag);
  }

  const pickedSet = new Set();
  function addPicked(cpe) {
    if (pickedSet.has(cpe)) return; // уже добавлено
    pickedSet.add(cpe);
    const li = document.createElement('li');
    li.textContent = cpe;
    const rm = document.createElement('button');
    rm.textContent = '×';
    rm.style.marginLeft = '8px';
    rm.addEventListener('click', () => { pickedSet.delete(cpe); li.remove(); });
    li.appendChild(rm);
    picked.appendChild(li);
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
    try {
      const data = await fetchJSON(`/api/cpe/search?${params.toString()}`);
      renderResults(data.items);
    } catch (err) {
      results.textContent = `Ошибка: ${err}`;
    }
  });

  // Сброс формы
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      partEl.value = '';
      setStatus(partStatus, false);
      vendorEl.value=''; productEl.value=''; versionEl.value='';
      setStatus(vendorStatus, false); setStatus(productStatus, false); setStatus(versionStatus, false);
      vendorSug.innerHTML=''; productSug.innerHTML=''; versionSug.innerHTML='';
      results.innerHTML=''; picked.innerHTML='';
      partEl.focus();
    });
  }
})();
