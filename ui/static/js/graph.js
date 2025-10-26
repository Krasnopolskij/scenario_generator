(() => {
  const form = document.getElementById('graph-form');
  const cpeInput = document.getElementById('cpe');
  const modeSel = document.getElementById('mode');
  const container = document.getElementById('graph');
  const inspector = document.getElementById('inspector-content');

  let cy = null;

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
    rows.push(`<div class="row"><div class="k">label</div><div class="v">${label}</div></div>`);
    const keys = Object.keys(props);
    for (const k of keys) {
      let v = props[k];
      if (v == null) v = '';
      if (Array.isArray(v)) v = v.join(', ');
      const vs = String(v).slice(0, 800);
      rows.push(`<div class="row"><div class="k">${k}</div><div class="v">${vs}</div></div>`);
      if (rows.length > 30) break;
    }
    inspector.innerHTML = rows.join('');
  }

  async function draw() {
    const cpe = (cpeInput.value || '').trim();
    const mode = modeSel.value || 'full';
    if (!cpe) {
      alert('Укажите cpe23Uri');
      return;
    }
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
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    draw();
  });

  // Предзаполнение поля из query-параметра ?cpe=...
  try {
    const sp = new URLSearchParams(window.location.search);
    const qCpe = sp.get('cpe');
    if (qCpe && cpeInput) cpeInput.value = qCpe;
  } catch {}
})();
