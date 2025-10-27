(() => {
  const form = document.getElementById('graph-form');
  const cpeInput = document.getElementById('cpe');
  const modeSel = document.getElementById('mode');
  const container = document.getElementById('graph');
  const inspector = document.getElementById('inspector-content');
  const clearBtn = document.getElementById('clear-graph');
  const scModeSel = document.getElementById('sc-mode');
  const scMaxPerTacticInput = document.getElementById('sc-max-per-tactic');
  const viewModeSel = document.getElementById('view-mode');
  const showAllCves = document.getElementById('show-all-cves');
  const genScenariosBtn = document.getElementById('gen-scenarios');
  const clearScenariosBtn = document.getElementById('clear-scenarios');
  const scenariosList = document.getElementById('scenarios-list');
  // Inspector collapse controls
  const insp = document.querySelector('.page-graph .inspector');
  const inspToggle = document.getElementById('insp-toggle');
  const mainGrid = document.querySelector('.page-graph main');
  // Theme controls
  const themeBtn = document.getElementById('open-theme');
  const themeBackdrop = document.getElementById('theme-backdrop');
  const themeCanvasInput = document.getElementById('theme-canvas');
  const themeLabelInput = document.getElementById('theme-label');
  const themeNodeInputs = {
    CPE: document.getElementById('theme-node-cpe'),
    CVE: document.getElementById('theme-node-cve'),
    CWE: document.getElementById('theme-node-cwe'),
    CAPEC: document.getElementById('theme-node-capec'),
    Technique: document.getElementById('theme-node-tech'),
  };
  const themeEdgeInputs = {
    AFFECTS: document.getElementById('theme-edge-AFFECTS'),
    CWE_TO_CVE: document.getElementById('theme-edge-CWE_TO_CVE'),
    CAPEC_TO_CWE: document.getElementById('theme-edge-CAPEC_TO_CWE'),
    CAPEC_PARENT_TO_CAPEC_CHILD: document.getElementById('theme-edge-CAPEC_PARENT_TO_CAPEC_CHILD'),
    CAPEC_TO_TECHNIQUE: document.getElementById('theme-edge-CAPEC_TO_TECHNIQUE'),
    SC_STEP: document.getElementById('theme-edge-SC_STEP'),
    SC_TECH_TO_CVE: document.getElementById('theme-edge-SC_TECH_TO_CVE'),
    SC_GROUP: document.getElementById('theme-edge-SC_GROUP'),
  };
  const themeResetBtn = document.getElementById('theme-reset');
  const themeCancelBtn = document.getElementById('theme-cancel');
  const themeApplyBtn = document.getElementById('theme-apply');
  const LS_FORM = 'sg:graph:form';
  const LS_SNAP = 'sg:graph:snapshot';
  const LS_SCEN = 'sg:graph:scenarios';
  const LS_SC_FORM = 'sg:graph:scform';
  const LS_THEME = 'sg:graph:theme';
  const LS_INSP = 'sg:graph:inspCollapsed';
  const SNAP_LIMIT = 2 * 1024 * 1024; // 2MB

  let cy = null;
  let isScenarioView = false;
  let currentScenarioId = null;
  const scenarioShowBtns = new Map();

  // ===== Inspector collapse handling =====
  function setInspectorCollapsed(flag, save=true) {
    try {
      if (mainGrid) mainGrid.classList.toggle('insp-collapsed', !!flag);
      if (insp) insp.classList.toggle('collapsed', !!flag);
      if (save) { try { localStorage.setItem(LS_INSP, JSON.stringify(!!flag)); } catch {} }
      // Let Cytoscape know container resized
      if (cy && typeof cy.resize === 'function') setTimeout(() => { try { cy.resize(); } catch {} }, 0);
    } catch {}
  }
  function initInspectorCollapse() {
    try {
      const raw = localStorage.getItem(LS_INSP);
      const v = raw ? JSON.parse(raw) : false;
      setInspectorCollapsed(!!v, false);
    } catch {}
    if (inspToggle) inspToggle.addEventListener('click', () => setInspectorCollapsed(!(insp && insp.classList.contains('collapsed'))));
  }

  // ===== Theme handling =====
  function loadTheme() {
    try { const raw = localStorage.getItem(LS_THEME); if (!raw) return null; const t = JSON.parse(raw); if (t && typeof t === 'object') return t; } catch {}
    return null;
  }
  function saveTheme(theme) {
    try {
      if (theme && (theme.nodeColors || theme.canvas || theme.labels || theme.edgeColors)) localStorage.setItem(LS_THEME, JSON.stringify(theme));
      else localStorage.removeItem(LS_THEME);
    } catch {}
  }
  function applyTheme(theme, opts={ save:false }) {
    // Canvas background
    if (container) {
      if (theme && theme.canvas) container.style.background = theme.canvas; else container.style.background = '';
    }
    if (cy) {
      const nodes = cy.nodes();
      // Label color
      const labelColor = theme && theme.labels ? String(theme.labels) : null;
      if (labelColor) {
        nodes.forEach(n => { n.style('color', labelColor); });
      } else {
        nodes.forEach(n => { n.removeStyle('color'); });
      }
      // Per-group node colors
      const colors = (theme && theme.nodeColors) || {};
      nodes.forEach(n => {
        const g = n.data('group');
        if (g === 'TechLabel') return;
        const val = colors[g];
        if (val) n.style('background-color', val);
        else n.removeStyle('background-color');
      });

      // Edge colors by type
      const ecolors = (theme && theme.edgeColors) || {};
      const edges = cy.edges();
      edges.forEach(e => {
        const t = e.data('type');
        const c = ecolors[t];
        if (c) {
          e.style('line-color', c);
          e.style('target-arrow-color', c);
          e.style('source-arrow-color', c);
        } else {
          e.removeStyle('line-color');
          e.removeStyle('target-arrow-color');
          e.removeStyle('source-arrow-color');
        }
      });
    }
    if (opts.save) saveTheme(theme);
  }
  function openThemeModal() {
    const saved = loadTheme() || {};
    try { if (themeCanvasInput) themeCanvasInput.value = (saved.canvas || '#0f1326'); } catch {}
    try { if (themeLabelInput) themeLabelInput.value = (saved.labels || '#e5e7ef'); } catch {}
    const cols = (saved.nodeColors || {});
    try { if (themeNodeInputs.CPE) themeNodeInputs.CPE.value = cols.CPE || colorByGroup('CPE'); } catch {}
    try { if (themeNodeInputs.CVE) themeNodeInputs.CVE.value = cols.CVE || colorByGroup('CVE'); } catch {}
    try { if (themeNodeInputs.CWE) themeNodeInputs.CWE.value = cols.CWE || colorByGroup('CWE'); } catch {}
    try { if (themeNodeInputs.CAPEC) themeNodeInputs.CAPEC.value = cols.CAPEC || colorByGroup('CAPEC'); } catch {}
    try { if (themeNodeInputs.Technique) themeNodeInputs.Technique.value = cols.Technique || colorByGroup('Technique'); } catch {}
    const ecols = (saved.edgeColors || {});
    try { if (themeEdgeInputs.AFFECTS) themeEdgeInputs.AFFECTS.value = ecols.AFFECTS || edgeColor('AFFECTS'); } catch {}
    try { if (themeEdgeInputs.CWE_TO_CVE) themeEdgeInputs.CWE_TO_CVE.value = ecols.CWE_TO_CVE || edgeColor('CWE_TO_CVE'); } catch {}
    try { if (themeEdgeInputs.CAPEC_TO_CWE) themeEdgeInputs.CAPEC_TO_CWE.value = ecols.CAPEC_TO_CWE || edgeColor('CAPEC_TO_CWE'); } catch {}
    try { if (themeEdgeInputs.CAPEC_PARENT_TO_CAPEC_CHILD) themeEdgeInputs.CAPEC_PARENT_TO_CAPEC_CHILD.value = ecols.CAPEC_PARENT_TO_CAPEC_CHILD || edgeColor('CAPEC_PARENT_TO_CAPEC_CHILD'); } catch {}
    try { if (themeEdgeInputs.CAPEC_TO_TECHNIQUE) themeEdgeInputs.CAPEC_TO_TECHNIQUE.value = ecols.CAPEC_TO_TECHNIQUE || edgeColor('CAPEC_TO_TECHNIQUE'); } catch {}
    try { if (themeEdgeInputs.SC_STEP) themeEdgeInputs.SC_STEP.value = ecols.SC_STEP || edgeColor('SC_STEP'); } catch {}
    try { if (themeEdgeInputs.SC_TECH_TO_CVE) themeEdgeInputs.SC_TECH_TO_CVE.value = ecols.SC_TECH_TO_CVE || edgeColor('SC_TECH_TO_CVE'); } catch {}
    try { if (themeEdgeInputs.SC_GROUP) themeEdgeInputs.SC_GROUP.value = ecols.SC_GROUP || edgeColor('SC_GROUP'); } catch {}
    try { themeBackdrop.removeAttribute('hidden'); themeBackdrop.classList.add('open'); } catch {}
  }
  function closeThemeModal() {
    try { themeBackdrop.classList.remove('open'); themeBackdrop.setAttribute('hidden',''); } catch {}
    const t = loadTheme();
    applyTheme(t || {}, { save:false });
  }
  function bindThemeUI() {
    if (themeBtn && themeBackdrop) themeBtn.addEventListener('click', openThemeModal);
    if (themeCancelBtn) themeCancelBtn.addEventListener('click', closeThemeModal);
    if (themeResetBtn) themeResetBtn.addEventListener('click', () => { saveTheme(null); applyTheme({}, { save:false }); closeThemeModal(); });
    if (themeApplyBtn) themeApplyBtn.addEventListener('click', () => {
      const nodeColors = {
        CPE: themeNodeInputs.CPE?.value,
        CVE: themeNodeInputs.CVE?.value,
        CWE: themeNodeInputs.CWE?.value,
        CAPEC: themeNodeInputs.CAPEC?.value,
        Technique: themeNodeInputs.Technique?.value,
      };
      const edgeColors = {
        AFFECTS: themeEdgeInputs.AFFECTS?.value,
        CWE_TO_CVE: themeEdgeInputs.CWE_TO_CVE?.value,
        CAPEC_TO_CWE: themeEdgeInputs.CAPEC_TO_CWE?.value,
        CAPEC_PARENT_TO_CAPEC_CHILD: themeEdgeInputs.CAPEC_PARENT_TO_CAPEC_CHILD?.value,
        CAPEC_TO_TECHNIQUE: themeEdgeInputs.CAPEC_TO_TECHNIQUE?.value,
        SC_STEP: themeEdgeInputs.SC_STEP?.value,
        SC_TECH_TO_CVE: themeEdgeInputs.SC_TECH_TO_CVE?.value,
        SC_GROUP: themeEdgeInputs.SC_GROUP?.value,
      };
      const theme = { canvas: themeCanvasInput?.value, labels: themeLabelInput?.value, nodeColors, edgeColors };
      applyTheme(theme, { save:true }); closeThemeModal();
    });
    const preview = () => {
      const nodeColors = {
        CPE: themeNodeInputs.CPE?.value,
        CVE: themeNodeInputs.CVE?.value,
        CWE: themeNodeInputs.CWE?.value,
        CAPEC: themeNodeInputs.CAPEC?.value,
        Technique: themeNodeInputs.Technique?.value,
      };
      const edgeColors = {
        AFFECTS: themeEdgeInputs.AFFECTS?.value,
        CWE_TO_CVE: themeEdgeInputs.CWE_TO_CVE?.value,
        CAPEC_TO_CWE: themeEdgeInputs.CAPEC_TO_CWE?.value,
        CAPEC_PARENT_TO_CAPEC_CHILD: themeEdgeInputs.CAPEC_PARENT_TO_CAPEC_CHILD?.value,
        CAPEC_TO_TECHNIQUE: themeEdgeInputs.CAPEC_TO_TECHNIQUE?.value,
        SC_STEP: themeEdgeInputs.SC_STEP?.value,
        SC_TECH_TO_CVE: themeEdgeInputs.SC_TECH_TO_CVE?.value,
        SC_GROUP: themeEdgeInputs.SC_GROUP?.value,
      };
      const theme = { canvas: themeCanvasInput?.value, labels: themeLabelInput?.value, nodeColors, edgeColors };
      applyTheme(theme, { save:false });
    };
    if (themeCanvasInput) themeCanvasInput.addEventListener('input', preview);
    if (themeLabelInput) themeLabelInput.addEventListener('input', preview);
    Object.values(themeNodeInputs).forEach(inp => { if (inp) inp.addEventListener('input', preview); });
    Object.values(themeEdgeInputs).forEach(inp => { if (inp) inp.addEventListener('input', preview); });
  }

  // === Tooltip for node hover ===
  let tooltipEl = null;
  let lastMouse = { x: 0, y: 0 };
  function ensureTooltip() {
    if (tooltipEl) return tooltipEl;
    tooltipEl = document.createElement('div');
    tooltipEl.id = 'graph-tooltip';
    tooltipEl.style.position = 'fixed';
    tooltipEl.style.zIndex = '10000';
    tooltipEl.style.pointerEvents = 'none';
    tooltipEl.style.visibility = 'hidden';
    tooltipEl.style.transform = 'translate(-9999px, -9999px)';
    document.body.appendChild(tooltipEl);
    if (container) {
      container.addEventListener('mousemove', (e) => { lastMouse.x = e.clientX; lastMouse.y = e.clientY; }, { passive: true });
      container.addEventListener('mouseleave', () => hideTooltip());
    }
    return tooltipEl;
  }
  function showTooltip(text, xOverride, yOverride) {
    const el = ensureTooltip();
    if (!text) { hideTooltip(); return; }
    el.textContent = String(text);
    el.style.visibility = 'visible';
    const x = (typeof xOverride === 'number') ? xOverride : (lastMouse.x + 12);
    const y = (typeof yOverride === 'number') ? yOverride : (lastMouse.y + 12);
    el.style.transform = `translate(${x}px, ${y}px)`;
  }
  function hideTooltip() {
    if (!tooltipEl) return;
    tooltipEl.style.visibility = 'hidden';
    tooltipEl.style.transform = 'translate(-9999px, -9999px)';
  }
  function hoverTextForEle(ele) {
    try {
      const group = ele.data('group') || '';
      const raw = ele.data('raw') || {};
      const props = raw.props || {};
      if (group === 'CVE') return props.identifier || ele.data('label') || '';
      if (group === 'CPE') return props.product || props.title || props.cpe23Uri || ele.data('label') || '';
      if (group === 'TacticGroup') return ele.data('label') || '';
      return props.name || ele.data('label') || '';
    } catch { return ''; }
  }
  function bindTooltipEvents() {
    if (!cy) return;
    cy.off('mouseover');
    cy.off('mouseout');
    cy.off('mousemove');
    cy.on('mouseover', 'node', (evt) => {
      const txt = hoverTextForEle(evt.target);
      const rp = (evt.target && evt.target.renderedPosition) ? evt.target.renderedPosition() : null;
      let x, y; try { const rect = container.getBoundingClientRect(); if (rp) { x = rect.left + rp.x + 12; y = rect.top + rp.y + 12; } } catch {}
      if (txt) showTooltip(txt, x, y); else hideTooltip();
    });
    cy.on('mousemove', 'node', (evt) => {
      try {
        const oe = evt.originalEvent;
        if (oe && typeof oe.clientX === 'number' && typeof oe.clientY === 'number') {
          lastMouse.x = oe.clientX; lastMouse.y = oe.clientY;
        }
      } catch {}
      const txt = hoverTextForEle(evt.target);
      const rp = (evt.target && evt.target.renderedPosition) ? evt.target.renderedPosition() : null;
      let x, y; try { const rect = container.getBoundingClientRect(); if (rp) { x = rect.left + rp.x + 12; y = rect.top + rp.y + 12; } } catch {}
      if (txt) showTooltip(txt, x, y); else hideTooltip();
    });
    cy.on('mouseout', 'node', () => hideTooltip());
  }

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
      const view_mode = (viewModeSel && viewModeSel.value) || 'linear';
      localStorage.setItem(LS_SC_FORM, JSON.stringify({ mode, max_per_tactic: maxPer, view_mode }));
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
        if (viewModeSel && typeof d.view_mode === 'string') viewModeSel.value = (d.view_mode === 'primary') ? 'primary' : 'linear';
      }
    } catch (e) { console.warn('ls load sc form', e); }
  }

  function applyViewModeAvailability() {
    const vm = (viewModeSel && viewModeSel.value) || 'linear';
    const disable = vm === 'primary';
    if (scMaxPerTacticInput) scMaxPerTacticInput.disabled = disable;
    if (showAllCves) showAllCves.disabled = (vm !== 'primary');
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
      bindTooltipEvents();
      const th1 = loadTheme(); if (th1) applyTheme(th1);
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
      bindTooltipEvents();
      const th2 = loadTheme(); if (th2) applyTheme(th2);
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
      case 'SC_GROUP': return '#7f8c8d';
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
    const viewMode = (viewModeSel && viewModeSel.value) || 'linear';
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
    if (viewMode === 'primary') {
      renderPrimaryCard(data);
    } else {
      renderScenarios(data);
    }
  }

  function renderScenarios(data) {
    if (!data || !Array.isArray(data.scenarios)) { scenariosList.innerHTML = '<div class="muted">Нет данных</div>'; return; }
    const frag = document.createDocumentFragment();
    const meta = document.createElement('div');
    meta.className = 'sc-meta';
    const modeName = data.mode === 'relaxed' ? 'нестрогий' : 'строгий';
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
        { selector: 'node[group="TechLabel"]', style: {
          'background-opacity': 0,
          'border-width': 0,
          'label': 'data(label)',
          'font-size': 11,
          'color': '#9aa0b4',
          'text-halign': 'center',
          'text-valign': 'center',
          'events': 'no'
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
    bindTooltipEvents();
    // В режиме сценария снимок не сохраняем, чтобы не перетирать исходный граф в LS
    const th3 = loadTheme(); if (th3) applyTheme(th3);
  }

  function buildScenarioElements(sc) {
    const GAP_X = 100;
    const TECH_Y = 80;
    const TECH_LABEL_Y = TECH_Y - 30;
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
      // Label above technique with its identifier
      const tIdLabel = (t.props && t.props.identifier) ? String(t.props.identifier) : '';
      if (tIdLabel) {
        const lid = `tl_${tid}`;
        elements.push({ data: { id: lid, label: tIdLabel, group: 'TechLabel' }, position: { x, y: TECH_LABEL_Y } });
      }
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
    bindTooltipEvents();
    cy.on('free zoom pan', saveSnapshotDebounced);
    trySaveSnapshot();
    const th4 = loadTheme(); if (th4) applyTheme(th4);
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
  applyViewModeAvailability();
  initInspectorCollapse();
  // Theme UI and initial apply
  bindThemeUI();
  const initTheme = loadTheme(); if (initTheme) applyTheme(initTheme);

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
  if (viewModeSel) viewModeSel.addEventListener('change', () => { applyViewModeAvailability(); saveScForm(); });
  if (showAllCves) showAllCves.addEventListener('change', () => {
    if (isScenarioView && currentScenarioId === 'PRIMARY') {
      if (showAllCves.checked) showPrimaryAllCVEs();
      else { cy.elements("edge[type='SC_TECH_TO_CVE']").remove(); cy.elements("node[group='CVE']").remove(); }
      const th = loadTheme(); if (th) applyTheme(th);
    }
  });

  // ===== Первичный сценарий (primary) — визуализация групп тактик =====
  function renderPrimaryCard(data) {
    const frag = document.createDocumentFragment();
    const box = document.createElement('div'); box.className = 'scenario primary';
    const head = document.createElement('div'); head.className = 'scenario-head';
    const title = document.createElement('div'); title.className = 'scenario-title'; title.textContent = 'Первичный сценарий';
    const act = document.createElement('div'); act.className = 'scenario-actions';
    const btnShow = document.createElement('button'); btnShow.textContent = 'Отобразить';
    // фиксированная ширина, чтобы текст не менял размер
    try { btnShow.style.width = '220px'; } catch {}
    const mega = Array.isArray(data.mega) ? data.mega : [];
    buildPrimaryStepIndex(mega);
    const setBtn = (sel) => { btnShow.textContent = sel ? 'Назад к графу' : 'Отобразить'; btnShow.classList.toggle('selected', !!sel); };
    btnShow.addEventListener('click', () => {
      if (!isScenarioView) {
        trySaveSnapshot();
        renderPrimaryOnCanvas(mega);
        setBtn(true);
        isScenarioView = true;
        currentScenarioId = 'PRIMARY';
      } else {
        const ok = restoreSnapshotFromLS();
        if (ok) { setBtn(false); isScenarioView = false; currentScenarioId = null; }
      }
    });
    act.appendChild(btnShow);
    head.appendChild(title); head.appendChild(act);
    box.appendChild(head);
    frag.appendChild(box);
    scenariosList.innerHTML = ''; scenariosList.appendChild(frag);

    // Если уже открыт первичный сценарий и пользователь заново сгенерировал — не возвращаемся к графу, а перерисовываем
    if (isScenarioView && currentScenarioId === 'PRIMARY') {
      setBtn(true);
      renderPrimaryOnCanvas(mega);
    } else {
      setBtn(false);
    }
  }

  let primaryStepByTechId = new Map();
  function buildPrimaryStepIndex(mega) {
    primaryStepByTechId = new Map();
    for (const col of mega || []) {
      for (const st of (col.techniques || [])) { const t = st.technique; if (t && t.id) primaryStepByTechId.set(String(t.id), st); }
    }
  }

  function renderPrimaryOnCanvas(mega) {
    if (!window.cytoscape) return;
    const elements = buildPrimaryElements(mega);
    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({
      container,
      elements,
      style: [
        { selector: 'node', style: {
          'label': 'data(label)','color':'#e5e7ef','font-size':12,'text-valign':'center','text-halign':'center','text-wrap':'none',
          'background-color': ele => colorByGroup(ele.data('group')),'shape':'ellipse','border-width':1,'border-color':'#2a3052','width':46,'height':46,'padding':0 }},
        { selector: 'node[group="TacticGroup"]', style: {
          'shape':'round-rectangle','background-color':'#141939','background-opacity':0.22,'label':'data(label)',
          'text-valign':'top','text-halign':'center','border-color':'#3b4775','border-width':1,'padding':14 }},
        { selector: 'node.sel', style: { 'border-width':3,'border-color':'#4f8cff','z-index':999 }},
        { selector: 'node.neigh', style: { 'border-width':2,'border-color':'#3b4775' }},
        { selector: 'edge', style: { 'curve-style':'bezier','target-arrow-shape':'none','line-color': ele => edgeColor(ele.data('type')),'width':1.2,'opacity':0.85 }},
        { selector: 'edge[type="SC_GROUP"]', style: { 'target-arrow-shape': 'triangle', 'target-arrow-color': '#7f8c8d' }},
      ],
      layout: { name: 'preset', fit: true, padding: 20 }
    });
    cy.on('tap', 'node', (evt) => {
      const ele = evt.target;
      const grp = ele.data('group');
      if (grp === 'TacticGroup') {
        if (showAllCves && showAllCves.checked) {
          showPrimaryAllCVEs();
        } else {
          showPrimaryGroupDetails(ele);
        }
      }
      cy.elements().removeClass('sel neigh'); ele.addClass('sel'); ele.closedNeighborhood().difference(ele).addClass('neigh'); renderInspector(ele);
    });
    cy.on('tap', (evt) => { if (evt.target === cy) { cy.elements().removeClass('sel neigh'); renderInspector(null); } });
    bindTooltipEvents();

    // При включённом флаге — сразу показать все CVE
    if (showAllCves && showAllCves.checked) {
      showPrimaryAllCVEs();
    }
    const th5 = loadTheme(); if (th5) applyTheme(th5);
  }

  function buildPrimaryElements(mega) {
    const COL_GAP=110, ROW_GAP=70, TOP_Y=80; const elements=[]; const cols=(mega||[]).slice().sort((a,b)=>(a.tactic_order||0)-(b.tactic_order||0));
    const groupIds=[];
    for (let ci=0; ci<cols.length; ci++) {
      const col = cols[ci]; const gid = `tg_${ci}`; groupIds.push(gid);
      elements.push({ data: { id: gid, label: String(col.tactic||''), group:'TacticGroup' }, position: { x: ci*COL_GAP, y: TOP_Y } });
      const items = col.techniques || [];
      for (let ri=0; ri<items.length; ri++) { const st=items[ri]; const t=st.technique; if (!t||!t.id) continue; const x=ci*COL_GAP; const y=TOP_Y+ri*ROW_GAP; elements.push({ data: { id:String(t.id), label:'Tech', group:'Technique', raw:t, parent: gid }, position:{x,y} }); }
    }
    // Простые связи между соседними группами
    for (let i=0; i<groupIds.length-1; i++) { const s=groupIds[i], t=groupIds[i+1]; const eid=`sc_group_${i}_${i+1}`; elements.push({ data: { id:eid, source:s, target:t, type:'SC_GROUP' } }); }
    return elements;
  }

  function showPrimaryGroupDetails(groupEle) {
    // Удаляем прежние CVE узлы и связи к ним
    cy.elements("edge[type='SC_TECH_TO_CVE']").remove();
    cy.nodes("[group = 'CVE']").remove();
    addCVEsForGroup(groupEle, false);
    const th = loadTheme(); if (th) applyTheme(th);
  }

  function addCVEsForGroup(groupEle, dontClear) {
    const kids = groupEle.children();
    const bb = groupEle.boundingBox(); const centerX = (bb.x1+bb.x2)/2; const baseY = bb.y2 + 80; const CVE_GAP_Y=38, SPREAD_X=28;
    // Собираем CVE с привязкой к минимальному ряду техники, чтобы сверху шли CVE от верхних техник
    const items = [];
    kids.forEach(k => {
      const tid = String(k.id());
      const st = primaryStepByTechId.get(tid); if (!st) return; const cves = Array.isArray(st.cves)?st.cves:[];
      const row = Math.round((k.position('y') - bb.y1) / 70); // приблизительный ряд
      for (const cv of cves) { if (!cv || !cv.id) continue; items.push({ cv, tid, row }); }
    });
    // Сортировка CVE по верхним связанным техникам
    items.sort((a,b)=> a.row - b.row);
    const placed = new Set(); let idx=0;
    for (const it of items) {
      const cid = String(it.cv.id); const tid = it.tid;
      if (!placed.has(cid)) {
        const x = centerX + (idx - Math.floor(items.length/2))*SPREAD_X; const y = baseY + idx*CVE_GAP_Y;
        // Узел CVE может уже существовать (если он встречался в другой группе).
        // В этом случае не добавляем его повторно, чтобы не получить ошибку дубликата id.
        if (cy.getElementById(cid).length === 0) {
          try {
            cy.add({ group:'nodes', data:{ id: cid, label:'CVE', group:'CVE', raw: it.cv }, position:{ x, y } });
          } catch (e) {
            // На всякий случай игнорируем возможные гонки/дубликаты
          }
        }
        placed.add(cid); idx++;
      }
      const eid = `pg_tc_${tid}_${cid}`;
      if (cy.getElementById(eid).length === 0) {
        try {
          cy.add({ group:'edges', data:{ id: eid, source: tid, target: cid, type: 'SC_TECH_TO_CVE' } });
        } catch (e) {
          // безопасно игнорируем повторные добавления
        }
      }
    }
    // Применяем тему к только что добавленным элементам
    const th = loadTheme(); if (th) applyTheme(th);
  }

  function showPrimaryAllCVEs() {
    // Полностью перестраиваем CVE-слой
    cy.elements("edge[type='SC_TECH_TO_CVE']").remove();
    cy.elements("node[group='CVE']").remove();
    const groups = cy.nodes("[group = 'TacticGroup']");
    groups.forEach(g => addCVEsForGroup(g, true));
    const th = loadTheme(); if (th) applyTheme(th);
  }

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
