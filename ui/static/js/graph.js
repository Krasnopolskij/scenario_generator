(() => {
  const form = document.getElementById('graph-form');
  const cpeInput = document.getElementById('cpe');
  const modeSel = document.getElementById('mode');
  const container = document.getElementById('graph');
  const inspector = document.getElementById('inspector-content');
  const clearBtn = document.getElementById('clear-graph');
  const scModeSel = document.getElementById('sc-mode');
  const scMaxPerTacticInput = document.getElementById('sc-max-per-tactic');
  const genScenariosBtn = document.getElementById('gen-scenarios');
  const clearScenariosBtn = document.getElementById('clear-scenarios');
  const scenariosList = document.getElementById('scenarios-list');
  const LS_FORM = 'sg:graph:form';
  const LS_SNAP = 'sg:graph:snapshot';
  const LS_SCEN = 'sg:graph:scenarios';
  const LS_SC_FORM = 'sg:graph:scform';
  const SNAP_LIMIT = 2 * 1024 * 1024; // 2MB

  let cy = null;
  let isScenarioView = false;
  let currentScenarioId = null;
  const scenarioShowBtns = new Map();

  const debounce = (fn, ms=250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  function saveForm() {
    try { localStorage.setItem(LS_FORM, JSON.stringify({ cpe: cpeInput.value || '', mode: modeSel.value || 'full' })); } catch (e) { console.warn('ls save graph form', e); }
  }

  function restoreForm() {
    try {
      const raw = localStorage.getItem(LS_FORM);
      if (!raw) return;
      const d = JSON.parse(raw);
      if (d && typeof d === 'object') {
        if (typeof d.cpe === 'string' && d.cpe && !new URLSearchParams(window.location.search).get('cpe')) cpeInput.value = d.cpe;
        if (typeof d.mode === 'string') modeSel.value = d.mode === 'simple' ? 'simple' : 'full';
      }
    } catch (e) { console.warn('ls load graph form', e); }
  }

  function trySaveSnapshot() {
    if (!cy) return;
    const snap = { cy: cy.json(), zoom: cy.zoom(), pan: cy.pan(), ts: Date.now() };
    let s = '';
    try { s = JSON.stringify(snap); } catch (e) { console.warn('snap stringify', e); return; }
    try {
      const size = new Blob([s]).size;
      if (size > SNAP_LIMIT) return;
      localStorage.setItem(LS_SNAP, s);
    } catch (e) { console.warn('ls save graph snapshot', e); }
  }
  const saveSnapshotDebounced = debounce(trySaveSnapshot, 400);
  
  // Сохранение настроек панели сценариев
  function saveScForm() {
    try {
      const mode = (scModeSel && scModeSel.value) || 'strict';
      let maxPer = 2;
      try { maxPer = Math.max(1, Math.min(10, parseInt(scMaxPerTacticInput.value || '2'))); } catch {}
      localStorage.setItem(LS_SC_FORM, JSON.stringify({ mode, max_per_tactic: maxPer }));
    } catch (e) { console.warn('ls save sc form', e); }
  }

  function restoreScForm() {
    try {
      const raw = localStorage.getItem(LS_SC_FORM);
      if (!raw) return;
      const d = JSON.parse(raw);
      if (d && typeof d === 'object') {
        if (scModeSel && typeof d.mode === 'string') scModeSel.value = d.mode === 'relaxed' ? 'relaxed' : 'strict';
        if (scMaxPerTacticInput) {
          let v = parseInt(d.max_per_tactic);
          if (!Number.isFinite(v)) v = 2;
          v = Math.max(1, Math.min(10, v));
          scMaxPerTacticInput.value = String(v);
        }
      }
    } catch (e) { console.warn('ls load sc form', e); }
  }

  function restoreSnapshotIfAny() {
    if (new URLSearchParams(window.location.search).get('cpe')) return;
    try {
      const raw = localStorage.getItem(LS_SNAP);
      if (!raw) return false;
      const snap = JSON.parse(raw);
      if (!window.cytoscape) return false;
      if (cy) { cy.destroy(); cy = null; }
      const elements = (snap.cy && snap.cy.elements) ? snap.cy.elements : [];
      cy = cytoscape({
        container,
        elements,
        style: [
          { selector: 'node', style: {
            'label': 'data(label)',
            'color': '#e5e7ef',
            'font-size': 12,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'none',
            'background-color': ele => colorByGroup(ele.data('group')),
            'shape': 'ellipse',
            'border-width': 1,
            'border-color': '#2a3052',
            'width': 46,
            'height': 46,
            'padding': 0
          }},
          { selector: 'node.sel', style: {
            'border-width': 3,
            'border-color': '#4f8cff',
            'z-index': 999
          }},
          { selector: 'node.neigh', style: {
            'border-width': 2,
            'border-color': '#3b4775'
          }},
          { selector: 'edge', style: {
            'curve-style': 'bezier',
            'target-arrow-shape': 'none',
            'line-color': ele => edgeColor(ele.data('type')),
            'width': 1.2,
            'opacity': 0.85
          }},
        ],
        layout: { name: 'preset' }
      });
      if (snap.pan) cy.pan(snap.pan);
      if (typeof snap.zoom === 'number') cy.zoom(snap.zoom);
      cy.on('tap', 'node', (evt) => {
        cy.elements().removeClass('sel neigh');
        const ele = evt.target;
        ele.addClass('sel');
        ele.closedNeighborhood().difference(ele).addClass('neigh');
        renderInspector(ele);
      });
      cy.on('tap', (evt) => { if (evt.target === cy) { cy.elements().removeClass('sel neigh'); renderInspector(null); } });
      cy.on('free zoom pan', saveSnapshotDebounced);
      return true;
    } catch (e) { console.warn('ls load graph snapshot', e); return false; }
  }

  // Восстановление из локального снапшота принудительно (для выхода из режима сценария)
  function restoreSnapshotFromLS() {
    try {
      const raw = localStorage.getItem(LS_SNAP);
      if (!raw) return false;
      const snap = JSON.parse(raw);
      if (!window.cytoscape) return false;
      if (cy) { cy.destroy(); cy = null; }
      const elements = (snap.cy && snap.cy.elements) ? snap.cy.elements : [];
      cy = cytoscape({
        container,
        elements,
        style: [
          { selector: 'node', style: {
            'label': 'data(label)',
            'color': '#e5e7ef',
            'font-size': 12,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'none',
            'background-color': ele => colorByGroup(ele.data('group')),
            'shape': 'ellipse',
            'border-width': 1,
            'border-color': '#2a3052',
            'width': 46,
            'height': 46,
            'padding': 0
          }},
          { selector: 'node.sel', style: {
            'border-width': 3,
            'border-color': '#4f8cff',
            'z-index': 999
          }},
          { selector: 'node.neigh', style: {
            'border-width': 2,
            'border-color': '#3b4775'
          }},
          { selector: 'edge', style: {
            'curve-style': 'bezier',
            'target-arrow-shape': 'none',
            'line-color': ele => edgeColor(ele.data('type')),
            'width': 1.2,
            'opacity': 0.85
          }},
        ],
        layout: { name: 'preset' }
      });
      if (snap.pan) cy.pan(snap.pan);
      if (typeof snap.zoom === 'number') cy.zoom(snap.zoom);
      cy.on('tap', 'node', (evt) => {
        cy.elements().removeClass('sel neigh');
        const ele = evt.target;
        ele.addClass('sel');
        ele.closedNeighborhood().difference(ele).addClass('neigh');
        renderInspector(ele);
      });
      cy.on('tap', (evt) => { if (evt.target === cy) { cy.elements().removeClass('sel neigh'); renderInspector(null); } });
      // Повторно включаем автоснапшот только для обычного графа
      cy.on('free zoom pan', saveSnapshotDebounced);
      isScenarioView = false;
      return true;
    } catch (e) { console.warn('restoreSnapshotFromLS', e); return false; }
  }

  function colorByGroup(group) {
    switch (group) {
      case 'CPE': return '#8e44ad';
      case 'CVE': return '#e74c3c';
      case 'CWE': return '#e49659';
      case 'CAPEC': return '#3498db';
      case 'Technique': return '#4fca21';
      default: return '#95a5a6';
    }
  }

  function edgeColor(type) {
    switch (type) {
      case 'AFFECTS': return '#c0392b';
      case 'CWE_TO_CVE': return '#d35400';
      case 'CAPEC_TO_CWE': return '#2980b9';
      case 'CAPEC_PARENT_TO_CAPEC_CHILD': return '#7f8c8d';
      case 'CAPEC_TO_TECHNIQUE': return '#27ae60';
      case 'SC_STEP': return '#7f8c8d';
      case 'SC_TECH_TO_CVE': return '#8e44ad';
      default: return '#7f8c8d';
    }
  }

  function renderInspector(nodeData) {
    if (!inspector) return;
    if (!nodeData) {
      inspector.innerHTML = '<div class="row"><div class="k">Подсказка</div><div class="v">Кликните по узлу на графе</div></div>';
      return;
    }
    const raw = nodeData.data('raw') || {};
    const group = raw.group || nodeData.data('group') || 'Node';
    const label = raw.label || nodeData.data('label') || '';
    const props = (raw.props) || {};
    const rows = [];
    rows.push(`<div class="row"><div class="k">Тип</div><div class="v">${group}</div></div>`);

    // Специальный порядок для узлов Technique
    if (group === 'Technique') {
      const order = ['name', 'identifier', 'tactic_order', 'primary_tactic', 'tactics', 'description'];
      for (const k of order) {
        if (!(k in props)) continue;
        let v = props[k];
        if (v == null) v = '';
        if (Array.isArray(v)) v = v.join(', ');
        const vs = String(v).slice(0, 800);
        rows.push(`<div class="row"><div class="k">${k}</div><div class="v">${vs}</div></div>`);
      }
      // Остальные поля (если есть)
      for (const k of Object.keys(props)) {
        if (order.includes(k)) continue;
        let v = props[k];
        if (v == null) v = '';
        if (Array.isArray(v)) v = v.join(', ');
        const vs = String(v).slice(0, 800);
        rows.push(`<div class="row"><div class="k">${k}</div><div class="v">${vs}</div></div>`);
        if (rows.length > 30) break;
      }
      rows.push(`<div class="row"><div class="k">label</div><div class="v">${label}</div></div>`);
      inspector.innerHTML = rows.join('');
      return;
    }

    // Поведение по умолчанию для других групп: свойства как есть и label в конце
    for (const k of Object.keys(props)) {
      let v = props[k];
      if (v == null) v = '';
      if (Array.isArray(v)) v = v.join(', ');
      const vs = String(v).slice(0, 800);
      rows.push(`<div class="row"><div class="k">${k}</div><div class="v">${vs}</div></div>`);
      if (rows.length > 30) break;
    }
    rows.push(`<div class="row"><div class="k">label</div><div class="v">${label}</div></div>`);
    inspector.innerHTML = rows.join('');
  }

  function highlightNodesByIds(ids) {
    if (!cy || !Array.isArray(ids) || ids.length === 0) return;
    // Снимаем прошлую подсветку
    cy.elements().removeClass('sel neigh');
    // Собираем единую коллекцию из всех найденных элементов
    let col = cy.collection();
    for (const rawId of ids) {
      const id = String(rawId);
      const ele = cy.getElementById(id);
      if (ele && ele.length) {
        col = col.union(ele);
      }
    }
    if (!col || col.length === 0) return;
    col.addClass('sel');
    col.closedNeighborhood().difference(col).addClass('neigh');
    // Не сохраняем подсветку в снимок; и тем более не перетираем снимок, когда отображается сценарий
    if (!isScenarioView) trySaveSnapshot();
  }

  async function generateScenarios() {
    const cpe = (cpeInput.value || '').trim();
    if (!cpe) { alert('Сначала укажите cpe23Uri и постройте граф'); return; }
    const mode = (scModeSel && scModeSel.value) || 'strict';
    let maxPer = 3;
    try { maxPer = Math.max(1, Math.min(10, parseInt(scMaxPerTacticInput.value || '3'))); } catch {}
    const qs = new URLSearchParams({ cpe, mode, max_per_tactic: String(maxPer) });
    scenariosList.innerHTML = '<div class="muted">Загрузка…</div>';
    let data;
    try {
      const resp = await fetch(`/api/scenarios?${qs.toString()}`);
      if (!resp.ok) { throw new Error(`HTTP ${resp.status}`); }
      data = await resp.json();
    } catch (e) {
      scenariosList.innerHTML = `<div class="warn">Ошибка загрузки сценариев: ${e}</div>`;
      return;
    }
    renderScenarios(data);
  }

  function renderScenarios(data) {
    if (!data || !Array.isArray(data.scenarios)) { scenariosList.innerHTML = '<div class="muted">Нет данных</div>'; return; }
    const frag = document.createDocumentFragment();
    const meta = document.createElement('div');
    meta.className = 'sc-meta';
    modeName = data.mode === 'relaxed' ? 'нестрогий' : 'строгий';
    meta.textContent = `Сценариев: ${data.scenarios.length} (режим: ${modeName}, техник на тактику: ${data.max_per_tactic})`;
    frag.appendChild(meta);

    scenarioShowBtns.clear();

    data.scenarios.forEach((sc) => {
      const box = document.createElement('div');
      box.className = 'scenario';
      const head = document.createElement('div');
      head.className = 'scenario-head';
      const title = document.createElement('div');
      title.className = 'scenario-title';
      title.textContent = `${sc.id} • score ${Number(sc.score || 0).toFixed(1)}`;
      const act = document.createElement('div');
      act.className = 'scenario-actions';
      const btn = document.createElement('button');
      btn.textContent = 'Подсветить на графе';
      btn.addEventListener('click', () => {
        const ids = [];
        for (const step of sc.steps || []) {
          const t = step.technique; if (t && t.id) ids.push(String(t.id));
          for (const c of (step.cves || [])) { if (c && c.id) ids.push(String(c.id)); }
          for (const w of (step.cwes || [])) { if (w && w.id) ids.push(String(w.id)); }
          for (const cp of (step.capecs || [])) { if (cp && cp.id) ids.push(String(cp.id)); }
        }
        highlightNodesByIds(ids);
      });
      act.appendChild(btn);
      const btnShow = document.createElement('button');
      btnShow.textContent = 'Отобразить';

      // helpers to unify button state
      const setShowBtn = (btn, sel) => {
        if (!btn) return;
        btn.textContent = sel ? 'Назад к графу' : 'Отобразить';
        btn.classList.toggle('selected', !!sel);
      };
      const resetAllShowBtns = () => {
        scenarioShowBtns.forEach((b) => setShowBtn(b, false));
      };

      btnShow.addEventListener('click', () => {
        // Клик по кнопке отображения
        if (!isScenarioView) {
          // Входим в режим сценария из графа
          trySaveSnapshot();
          renderScenario(sc);
          resetAllShowBtns();
          setShowBtn(btnShow, true);
          isScenarioView = true;
          currentScenarioId = sc.id;
        } else {
          if (currentScenarioId === sc.id) {
            // Выходим из сценария
            const ok = restoreSnapshotFromLS();
            if (ok) {
              resetAllShowBtns();
              isScenarioView = false;
              currentScenarioId = null;
            }
          } else {
            // Переключаемся на другой сценарий без возврата к графу
            renderScenario(sc);
            resetAllShowBtns();
            setShowBtn(btnShow, true);
            currentScenarioId = sc.id;
          }
        }
      });
      scenarioShowBtns.set(sc.id, btnShow);
      act.appendChild(btnShow);
      head.appendChild(title); head.appendChild(act);
      box.appendChild(head);

      const steps = document.createElement('div');
      steps.className = 'scenario-steps';
      (sc.steps || []).forEach((st, idx) => {
        const row = document.createElement('div');
        row.className = 'scenario-step';
        const left = document.createElement('div');
        const tprops = st.technique && st.technique.props || {};
        left.textContent = `${idx+1}. [${st.tactic || '?'}] ${tprops.identifier || ''} ${tprops.name ? '— ' + tprops.name : ''}`;
        const right = document.createElement('div');
        right.className = 'step-cves';
        (st.cves || []).forEach(cv => {
          const chip = document.createElement('span');
          chip.className = 'chip';
          chip.textContent = (cv.props && cv.props.identifier) || '';
          chip.title = (cv.props && cv.props.description) || '';
          chip.addEventListener('click', (e) => { e.stopPropagation(); if (cv.id) highlightNodesByIds([String(cv.id)]); });
          right.appendChild(chip);
        });
        row.appendChild(left); row.appendChild(right);
        row.addEventListener('click', () => {
          const ids = [];
          const t = st.technique; if (t && t.id) ids.push(String(t.id));
          for (const c of (st.cves || [])) { if (c && c.id) ids.push(String(c.id)); }
          for (const w of (st.cwes || [])) { if (w && w.id) ids.push(String(w.id)); }
          for (const cp of (st.capecs || [])) { if (cp && cp.id) ids.push(String(cp.id)); }
          highlightNodesByIds(ids);
        });
        steps.appendChild(row);
      });
      box.appendChild(steps);
      frag.appendChild(box);
    });
    scenariosList.innerHTML = '';
    scenariosList.appendChild(frag);
  }

  function renderScenario(sc) {
    if (!window.cytoscape) return;
    const elements = buildScenarioElements(sc);
    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({
      container,
      elements,
      style: [
        { selector: 'node', style: {
          'label': 'data(label)',
          'color': '#e5e7ef',
          'font-size': 12,
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'none',
          'background-color': ele => colorByGroup(ele.data('group')),
          'shape': 'ellipse',
          'border-width': 1,
          'border-color': '#2a3052',
          'width': 46,
          'height': 46,
          'padding': 0
        }},
        { selector: 'node.sel', style: {
          'border-width': 3,
          'border-color': '#4f8cff',
          'z-index': 999
        }},
        { selector: 'node.neigh', style: {
          'border-width': 2,
          'border-color': '#3b4775'
        }},
        { selector: 'edge', style: {
          'curve-style': 'bezier',
          'target-arrow-shape': 'none',
          'line-color': ele => edgeColor(ele.data('type')),
          'width': 1.2,
          'opacity': 0.85
        }},
      ],
      layout: { name: 'preset', fit: true, padding: 20 }
    });
    cy.on('tap', 'node', (evt) => {
      cy.elements().removeClass('sel neigh');
      const ele = evt.target;
      ele.addClass('sel');
      ele.closedNeighborhood().difference(ele).addClass('neigh');
      renderInspector(ele);
    });
    cy.on('tap', (evt) => { if (evt.target === cy) { cy.elements().removeClass('sel neigh'); renderInspector(null); } });
    // В режиме сценария снимок не сохраняем, чтобы не перетирать исходный граф в LS
  }

  function buildScenarioElements(sc) {
    const GAP_X = 140;
    const TECH_Y = 80;
    const CVE_START_Y = 220;
    const CVE_GAP_Y = 38;
    const CVE_SPREAD_X = 26; // горизонтальный разнос CVE вокруг техники
    const elements = [];
    const steps = sc.steps || [];

    // Позиции техник
    const techPos = new Map(); // tid -> {x,y}
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i];
      const t = st.technique;
      if (!t || !t.id) continue;
      const x = i * GAP_X;
      const tid = String(t.id);
      techPos.set(tid, { x, y: TECH_Y });
      elements.push({ data: { id: tid, label: 'Tech', group: 'Technique', raw: t }, position: { x, y: TECH_Y } });
      if (i > 0) {
        const prev = steps[i - 1].technique;
        if (prev && prev.id) {
          const eid = `sc_step_${prev.id}_${t.id}`;
          elements.push({ data: { id: eid, source: String(prev.id), target: String(t.id), type: 'SC_STEP' } });
        }
      }
    }

    // Собираем CVE -> индексы техник
    const cveMap = new Map(); // cveId -> { raw, indices: Set<number> }
    for (let i = 0; i < steps.length; i++) {
      const cves = Array.isArray(steps[i].cves) ? steps[i].cves : [];
      for (const cv of cves) {
        if (!cv || !cv.id) continue;
        const cid = String(cv.id);
        let entry = cveMap.get(cid);
        if (!entry) { entry = { raw: cv, indices: new Set() }; cveMap.set(cid, entry); }
        entry.indices.add(i);
      }
    }

    // Считаем центры многошаговых CVE и подготовим разнос уникальных CVE по технике
    const cveEntries = [];
    const uniqueByTech = new Map(); // techIndex -> array of {id, raw}
    cveMap.forEach((v, cid) => {
      const idxs = Array.from(v.indices.values());
      if (idxs.length === 0) return;
      if (idxs.length === 1) {
        const i = idxs[0];
        const arr = uniqueByTech.get(i) || [];
        arr.push({ id: cid, raw: v.raw });
        uniqueByTech.set(i, arr);
      } else {
      const minI = Math.min(...idxs);
      const maxI = Math.max(...idxs);
      const centerI = (minI + maxI) / 2;
      const x = centerI * GAP_X;
      cveEntries.push({ id: cid, raw: v.raw, x });
      }
    });

    // Для уникальных CVE каждого шага делаем веер по X относительно техники
    uniqueByTech.forEach((list, i) => {
      const baseX = i * GAP_X;
      const n = list.length;
      // Расставляем симметрично вокруг центра: -..0..+
      for (let k = 0; k < n; k++) {
        const offset = (k - (n - 1) / 2) * CVE_SPREAD_X;
        cveEntries.push({ id: String(list[k].id), raw: list[k].raw, x: baseX + offset });
      }
    });
    cveEntries.sort((a, b) => (a.x - b.x) || String(a.id).localeCompare(String(b.id)));

    let row = 0;
    const addedCve = new Set();
    for (const ce of cveEntries) {
      const y = CVE_START_Y + row * CVE_GAP_Y;
      const cid = String(ce.id);
      if (!addedCve.has(cid)) {
        elements.push({ data: { id: cid, label: 'CVE', group: 'CVE', raw: ce.raw }, position: { x: ce.x, y } });
        addedCve.add(cid);
      row += 1;
    }
    }

    // Рёбра техника -> CVE (без дублей)
    const edgeIds = new Set();
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i];
      const t = st.technique; if (!t || !t.id) continue;
      const tid = String(t.id);
      const cves = Array.isArray(st.cves) ? st.cves : [];
      for (const cv of cves) {
        if (!cv || !cv.id) continue;
        const cid = String(cv.id);
        const eid = `sc_tc_${tid}_${cid}`;
        if (edgeIds.has(eid)) continue;
        edgeIds.add(eid);
        elements.push({ data: { id: eid, source: tid, target: cid, type: 'SC_TECH_TO_CVE' } });
      }
    }

    return elements;
  }

  // === Сохранение/восстановление кэша сценариев в localStorage ===
  function trySaveScenariosCache(params, data) { /* no-op: сценарии больше не кэшируем */ }

  function restoreScenariosIfAny() { return false; }

  async function draw() {
    const cpe = (cpeInput.value || '').trim();
    const mode = modeSel.value || 'full';
    if (!cpe) {
      alert('Укажите cpe23Uri');
      return;
    }
    saveForm();
    const params = new URLSearchParams({ cpe, mode, limit: '2000' });
    const resp = await fetch(`/api/graph/subgraph?${params.toString()}`);
    if (!resp.ok) {
      alert(`Ошибка API: ${resp.status}`);
      return;
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      alert('Ошибка разбора ответа API');
      return;
    }
    const ncount = (data.nodes || []).length;
    const ecount = (data.edges || []).length;
    console.log('subgraph:', { nodes: ncount, edges: ecount });

    if (!window.cytoscape) {
      container.innerHTML = '<div style="padding:8px;color:#bbb">Cytoscape не найден. Убедитесь, что подключён локальный файл /static/js/vendor/cytoscape.js-3.33.1/dist/cytoscape.min.js</div>';
      return;
    }
    const elements = [];
    for (const n of data.nodes || []) {
      elements.push({ data: { id: n.id, label: n.label, group: n.group, raw: n } });
    }
    for (const e of data.edges || []) {
      elements.push({ data: { id: e.id, source: e.source, target: e.target, type: e.type } });
    }

    if (ncount === 0 && ecount === 0) {
      container.innerHTML = '<div style="padding:8px;color:#666">Подграф пуст — проверьте cpe23Uri.</div>';
      return;
    }

    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({
      container,
      elements,
      style: [
        { selector: 'node', style: {
          'label': 'data(label)',
          'color': '#e5e7ef',
          'font-size': 12,
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'none',
          'background-color': ele => colorByGroup(ele.data('group')),
          'shape': 'ellipse',
          'border-width': 1,
          'border-color': '#2a3052',
          'width': 46,
          'height': 46,
          'padding': 0
        }},
        { selector: 'node.sel', style: {
          'border-width': 3,
          'border-color': '#4f8cff',
          'z-index': 999
        }},
        { selector: 'node.neigh', style: {
          'border-width': 2,
          'border-color': '#3b4775'
        }},
        { selector: 'edge', style: {
          'curve-style': 'bezier',
          'target-arrow-shape': 'none',
          'line-color': ele => edgeColor(ele.data('type')),
          'width': 1.2,
          'opacity': 0.85
        }},
      ],
      layout: { name: 'cose', animate: false, fit: true, padding: 20 }
    });

    cy.on('tap', 'node', (evt) => {
      cy.elements().removeClass('sel neigh');
      const ele = evt.target;
      ele.addClass('sel');
      ele.closedNeighborhood().difference(ele).addClass('neigh');
      renderInspector(ele);
    });

    // Сбор выделения по клику на холсте
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass('sel neigh');
        renderInspector(null);
      }
    });
    cy.on('free zoom pan', saveSnapshotDebounced);
    trySaveSnapshot();
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    draw();
  });
  cpeInput.addEventListener('input', debounce(saveForm, 200));
  modeSel.addEventListener('change', saveForm);

  // Предзаполнение поля из query-параметра ?cpe=...
  try {
    const sp = new URLSearchParams(window.location.search);
    const qCpe = sp.get('cpe');
    if (qCpe && cpeInput) cpeInput.value = qCpe;
  } catch {}

  restoreForm();
  restoreSnapshotIfAny();
  restoreScForm();

  if (genScenariosBtn) {
    genScenariosBtn.addEventListener('click', generateScenarios);
  }
  if (clearScenariosBtn) {
    clearScenariosBtn.addEventListener('click', () => {
      scenariosList.innerHTML = '';
      if (cy) { cy.elements().removeClass('sel neigh'); }
      // Если сейчас отображается сценарий — вернёмся к исходному графу
      if (isScenarioView) {
        restoreSnapshotFromLS();
        isScenarioView = false;
        currentScenarioId = null;
      }
      // Чистим кэш сценариев в LS, чтобы не переполнять
      try { localStorage.removeItem(LS_SCEN); } catch {}
    });
  }
  if (scModeSel) scModeSel.addEventListener('change', saveScForm);
  if (scMaxPerTacticInput) scMaxPerTacticInput.addEventListener('input', debounce(saveScForm, 200));

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (cy) { cy.destroy(); cy = null; }
      container.innerHTML = '';
      cpeInput.value = '';
      modeSel.value = 'full';
      try { localStorage.removeItem(LS_FORM); } catch (e) { console.warn('ls clear graph form', e); }
      try { localStorage.removeItem(LS_SNAP); } catch (e) { console.warn('ls clear graph snap', e); }
    });
  }
})();
