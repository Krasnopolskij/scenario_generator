(() => {
  const DEFAULT_METRIC = 'epss_norm';
  const METRIC_TITLES = {
    epss_norm: 'Вероятность эксплуатации',
    damage: 'Ущерб',
    risk: 'Риск',
    damage_C: 'Ущерб конфиденциальности',
    damage_I: 'Ущерб целостности',
    damage_A: 'Ущерб доступности',
    risk_C: 'Риск нарушения конфиденциальности',
    risk_I: 'Риск нарушения целостности',
    risk_A: 'Риск нарушения доступности',
  };
  const METRIC_DIGITS = {
    risk: 5, risk_C: 5, risk_I: 5, risk_A: 5,
  };
  const AXIS_PADDING = 0.6;

  const SEP = '<span style="display:block;border-top:2px solid rgba(255,255,255,0.45);margin:6px 0;"></span>';
  const DEFAULT_CAMERA = { eye: { x: 1.45, y: 1.65, z: 1.05 } };

  function safeNum(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : 0;
  }

  function fmt(v, digits = 4) {
    const n = safeNum(v);
    return n.toFixed(digits);
  }

  function clamp01(x) {
    if (!Number.isFinite(x) || x <= 0) return 0;
    if (x >= 1) return 1;
    return x;
  }

  function lerp(a, b, t) {
    return a + (b - a) * t;
  }

  function valueToColor(value, maxValue, mono=false) {
    const maxv = maxValue > 0 ? maxValue : 1;
    const t = clamp01(Math.pow(value / maxv, 0.65));
    if (mono) {
      const g = Math.round(lerp(210, 60, t));
      return `rgb(${g},${g},${g})`;
    }
    const start = { r: 73, g: 119, b: 255 };
    const end = { r: 199, g: 66, b: 216 };
    const r = Math.round(lerp(start.r, end.r, t));
    const g = Math.round(lerp(start.g, end.g, t));
    const b = Math.round(lerp(start.b, end.b, t));
    return `rgb(${r},${g},${b})`;
  }

  function formatTacticLabel(tactic, translateTactic) {
    try {
      const raw = String(tactic || '');
      const stripped = raw.replace(/^\s*\d+\s*[).,-]?\s*/,'').trim();
      return translateTactic ? translateTactic(stripped) : stripped;
    } catch { return tactic; }
  }

  function collectPrimaryCves(mega, translateTactic) {
    const byKey = new Map();
    for (const col of mega || []) {
      const tactic = col && col.tactic ? String(col.tactic) : '?';
      const tacticOrder = safeNum(col && col.tactic_order);
      for (const st of (col && col.techniques) || []) {
        for (const cv of (st && st.cves) || []) {
          const props = (cv && cv.props) || {};
          const ident = props.identifier || cv.id;
          if (!ident) continue;
          const key = `${tactic}__${ident}`;
          const rec = byKey.get(key) || {
            id: String(ident),
            tactic,
            tacticOrder,
            cvss: 0,
            epss: 0,
            epss_norm: 0,
            damage: 0,
            risk: 0,
            damage_C: 0,
            damage_I: 0,
            damage_A: 0,
            risk_C: 0,
            risk_I: 0,
            risk_A: 0,
          };
          rec.cvss = Math.max(rec.cvss, safeNum(props.cvss));
          rec.epss = Math.max(rec.epss, safeNum(props.epss));
          rec.epss_norm = Math.max(rec.epss_norm, safeNum(props.epss_norm));
          rec.damage = Math.max(rec.damage, safeNum(props.damage));
          rec.risk = Math.max(rec.risk, safeNum(props.risk));
          rec.damage_C = Math.max(rec.damage_C, safeNum(props.damage_C));
          rec.damage_I = Math.max(rec.damage_I, safeNum(props.damage_I));
          rec.damage_A = Math.max(rec.damage_A, safeNum(props.damage_A));
          rec.risk_C = Math.max(rec.risk_C, safeNum(props.risk_C));
          rec.risk_I = Math.max(rec.risk_I, safeNum(props.risk_I));
          rec.risk_A = Math.max(rec.risk_A, safeNum(props.risk_A));
          byKey.set(key, rec);
        }
      }
    }
    return Array.from(byKey.values()).map((item) => ({
      ...item,
      tacticLabel: formatTacticLabel(item.tactic, translateTactic),
    }));
  }

  function pickTop(items, metric) {
    const key = metric || DEFAULT_METRIC;
    return [...items]
      .sort((a, b) => {
        const diff = safeNum(b[key]) - safeNum(a[key]);
        if (diff !== 0) return diff;
        const rdiff = safeNum(b.risk) - safeNum(a.risk);
        if (rdiff !== 0) return rdiff;
        return String(a.id).localeCompare(String(b.id));
      })
      .slice(0, 20);
  }

  function buildBarSurfaces(bar, pos, metricKey, metricValue, maxValue, hoverBg, hoverText, mono=false) {
    const hw = 0.45;
    const x0 = pos.x - hw; const x1 = pos.x + hw;
    const y0 = pos.y - hw; const y1 = pos.y + hw;
    const z0 = 0; const z1 = metricValue;
    const color = valueToColor(metricValue, maxValue, mono);

    const faces = [
      { x: [[x0, x1], [x0, x1]], y: [[y0, y0], [y1, y1]], z: [[z1, z1], [z1, z1]], hover: true }, // верх
      { x: [[x0, x1], [x0, x1]], y: [[y0, y0], [y1, y1]], z: [[z0, z0], [z0, z0]] }, // низ
      { x: [[x0, x1], [x0, x1]], y: [[y0, y0], [y0, y0]], z: [[z0, z0], [z1, z1]] }, // перед
      { x: [[x0, x1], [x0, x1]], y: [[y1, y1], [y1, y1]], z: [[z0, z0], [z1, z1]] }, // зад
      { x: [[x0, x0], [x0, x0]], y: [[y0, y1], [y0, y1]], z: [[z0, z0], [z1, z1]] }, // левая
      { x: [[x1, x1], [x1, x1]], y: [[y0, y1], [y0, y1]], z: [[z0, z0], [z1, z1]] }, // правая
    ];

    const metricLabel = METRIC_TITLES[metricKey] || 'Значение';
    const digits = Number.isFinite(METRIC_DIGITS[metricKey]) ? METRIC_DIGITS[metricKey] : (String(metricKey || '').startsWith('risk') ? 5 : 4);
    const hover = [
      `<b>ID:</b> ${bar.id}`,
      `<b>CVSS:</b> ${fmt(bar.cvss, 2)}`,
      `<b>EPSS:</b> ${fmt(bar.epss, 4)}`,
      SEP,
      `<b>${metricLabel}:</b> ${fmt(metricValue, digits)}`,
      `<b>Вероятность:</b> ${fmt(bar.epss_norm, 4)}`,
      `<b>Ущерб:</b> ${fmt(bar.damage, 4)}`,
      `<b>Риск:</b> ${fmt(bar.risk, 5)}`,
      `<b>Тактика:</b> ${bar.tacticLabel}`,
    ].join('<br>') + '<extra></extra>';

    return faces.map((f) => ({
      type: 'surface',
      name: bar.id,
      showscale: false,
      colorscale: [[0, color], [1, color]],
      opacity: 1,
      x: f.x, y: f.y, z: f.z,
      hoverinfo: f.hover ? 'text' : 'skip',
      hovertemplate: f.hover ? hover : undefined,
      lighting: { diffuse: 0.9, specular: 0.1, roughness: 0.6 },
      hoverlabel: { bgcolor: hoverBg, font: { color: hoverText } },
    }));
  }

  function buildLayout(params) {
    const { xCount, xLabels, yLabels, metric, colors, showTactics, showCves, camera, ranges } = params;
    const xMax = Math.max(0, xCount - 1);
    const yMax = Math.max(0, yLabels.length - 1);
    const ratioX = Math.min(2.0, Math.max(1, (xCount || 1) / Math.max(1, yLabels.length) * 0.9));
    const xTicks = Array.from({ length: xCount }, (_, idx) => idx);
    const showXLabels = !!showCves;
    const xTickText = showXLabels ? xTicks.map((_, idx) => {
      const label = xLabels && xLabels[idx];
      return label ? String(label) : '';
    }) : xTicks.map(() => '');
    const xRange = ranges && ranges.x ? ranges.x : { min: -0.6, max: xMax + 0.6 };
    const yRange = ranges && ranges.y ? ranges.y : { min: -0.6, max: yMax + 0.6 };
    const zRange = ranges && ranges.z ? ranges.z : null;
    return {
      paper_bgcolor: colors.paper,
      plot_bgcolor: colors.paper,
      showlegend: false,
      margin: { l: 0, r: 0, b: 0, t: 0, pad: 0 },
      scene: {
        bgcolor: colors.canvas,
        xaxis: {
          title: showXLabels ? '' : 'CVE',
          tickmode: 'array',
          tickvals: xTicks,
          ticktext: xTickText,
          showticklabels: showXLabels,
          ticks: showXLabels ? 'outside' : '',
          tickangle: showXLabels ? -90 : 0,
          tickfont: showXLabels ? { size: 11 } : undefined,
          showgrid: true,
          range: [xRange.min, xRange.max],
          gridcolor: colors.grid,
          gridwidth: 2,
          zerolinecolor: colors.grid,
          showspikes: false,
        },
        yaxis: showTactics ? {
          title: '',
          tickmode: 'array',
          tickvals: yLabels.map((_, idx) => idx),
          ticktext: yLabels,
          tickfont: { size: 12 },
          tickangle: -25,
          ticklen: 16,
          ticks: 'outside',
          range: [yRange.min, yRange.max],
          gridcolor: colors.grid,
          gridwidth: 2,
          zerolinecolor: colors.grid,
          showgrid: true,
          showspikes: false,
        } : {
          title: 'Тактики',
          tickmode: 'array',
          tickvals: yLabels.map((_, idx) => idx),
          ticktext: [],
          ticks: '',
          showticklabels: false,
          showgrid: true,
          range: [yRange.min, yRange.max],
          gridcolor: colors.grid,
          gridwidth: 2,
          zerolinecolor: colors.grid,
          showspikes: false,
        },
        zaxis: {
          title: METRIC_TITLES[metric] || 'Значение',
          gridcolor: colors.grid,
          gridwidth: 2,
          zerolinecolor: colors.grid,
          range: zRange ? [zRange.min, zRange.max] : undefined,
          showspikes: false,
        },
        camera: camera || { eye: { x: 1.6, y: 1.3, z: 1.3 } },
        aspectmode: 'manual',
        aspectratio: { x: ratioX, y: 1, z: 0.9 },
        dragmode: 'orbit',
      },
      hoverlabel: { bgcolor: colors.hoverBg, bordercolor: colors.grid, font: { color: colors.hoverText } },
    };
  }

  function buildAxisTraces(ranges, colors) {
    const axisColor = colors.axis || '#000';
    const textFont = { size: 12, color: '#000' };
    const lineWidth = 5;
    const opacity = 1;
    const arrowSize = (len) => {
      if (!Number.isFinite(len) || len <= 0) return 0.18;
      return Math.min(0.6, Math.max(0.18, len * 0.08));
    };
    const xr = ranges.x || { min: -0.6, max: 1 };
    const yr = ranges.y || { min: -0.6, max: 1 };
    const zr = ranges.z || { min: 0, max: 1 };
    const xLen = xr.max - xr.min;
    const yLen = yr.max - yr.min;
    const zLen = zr.max - zr.min;
    const traces = [
      {
        type: 'scatter3d',
        mode: 'lines+text',
        x: [xr.min, xr.max],
        y: [0, 0],
        z: [0, 0],
        line: { color: axisColor, width: lineWidth },
        text: ['', 'x'],
        textposition: 'top center',
        textfont: { ...textFont, size: 13 },
        hoverinfo: 'skip',
        showlegend: false,
        opacity,
      },
      {
        type: 'scatter3d',
        mode: 'lines+text',
        x: [0, 0],
        y: [yr.min, yr.max],
        z: [0, 0],
        line: { color: axisColor, width: lineWidth },
        text: ['', 'y'],
        textposition: 'top center',
        textfont: { ...textFont, size: 13 },
        hoverinfo: 'skip',
        showlegend: false,
        opacity,
      },
      {
        type: 'scatter3d',
        mode: 'lines+text',
        x: [0, 0],
        y: [0, 0],
        z: [zr.min, zr.max],
        line: { color: axisColor, width: lineWidth },
        text: ['', 'z'],
        textposition: 'top center',
        textfont: { ...textFont, size: 13 },
        hoverinfo: 'skip',
        showlegend: false,
        opacity,
      },
      {
        type: 'cone',
        x: [xr.max],
        y: [0],
        z: [0],
        u: [1],
        v: [0],
        w: [0],
        sizemode: 'absolute',
        sizeref: arrowSize(xLen),
        anchor: 'tip',
        colorscale: [[0, axisColor], [1, axisColor]],
        showscale: false,
        hoverinfo: 'skip',
        name: '',
        opacity,
      },
      {
        type: 'cone',
        x: [0],
        y: [yr.max],
        z: [0],
        u: [0],
        v: [1],
        w: [0],
        sizemode: 'absolute',
        sizeref: arrowSize(yLen),
        anchor: 'tip',
        colorscale: [[0, axisColor], [1, axisColor]],
        showscale: false,
        hoverinfo: 'skip',
        name: '',
        opacity,
      },
      {
        type: 'cone',
        x: [0],
        y: [0],
        z: [zr.max],
        u: [0],
        v: [0],
        w: [1],
        sizemode: 'absolute',
        sizeref: arrowSize(zLen),
        anchor: 'tip',
        colorscale: [[0, axisColor], [1, axisColor]],
        showscale: false,
        hoverinfo: 'skip',
        name: '',
        opacity,
      },
    ];
    return traces;
  }

  function create(opts) {
    const {
      backdrop,
      plotEl,
      metricSelect,
      exportBtn,
      exportCsvBtn,
      closeBtn,
      noticeEl,
      translateTactic,
      getColors,
      buildFileName,
      getMonoFlag,
      getShowCves,
      getShowTactics,
    } = opts || {};

    let megaData = [];
    let currentMetric = DEFAULT_METRIC;
    let ready = false;
    let lastCamera = DEFAULT_CAMERA;

    function hasData() {
      return Array.isArray(megaData) && megaData.length > 0;
    }

    function openBackdrop() {
      if (!backdrop) return;
      try { backdrop.classList.add('open'); backdrop.removeAttribute('hidden'); } catch {}
    }

    function closeBackdrop() {
      if (!backdrop) return;
      try { backdrop.classList.remove('open'); backdrop.setAttribute('hidden', ''); } catch {}
    }

    function showNotice(msg) {
      if (!noticeEl) return;
      noticeEl.textContent = msg;
      noticeEl.removeAttribute('hidden');
      if (plotEl) plotEl.style.display = 'none';
      ready = false;
    }

    function hideNotice() {
      if (!noticeEl) return;
      noticeEl.setAttribute('hidden', '');
      if (plotEl) plotEl.style.display = '';
    }

    function render() {
      if (!plotEl) return;
      if (!window.Plotly) {
        showNotice('Plotly не загружен, проверьте подключение');
        ready = false;
        return;
      }
      if (!hasData()) {
        showNotice('Сначала нужно сгенерировать сценарий');
        ready = false;
        return;
      }
      const items = collectPrimaryCves(megaData, translateTactic);
      const top = pickTop(items, currentMetric);
      if (!top.length) {
        showNotice('Нет данных для выбранной метрики');
        ready = false;
        return;
      }
      hideNotice();
      const tactics = [];
      const tacticOrder = new Map();
      top.forEach((item) => {
        const key = item.tactic;
        if (!tacticOrder.has(key)) tacticOrder.set(key, safeNum(item.tacticOrder));
      });
      Array.from(tacticOrder.entries())
        .sort((a, b) => a[1] - b[1])
        .forEach(([t]) => tactics.push(t));

      const tacticToPos = new Map();
      tactics.forEach((t, idx) => tacticToPos.set(t, idx));

      const values = top.map((t) => safeNum(t[currentMetric]));
      const cveLabels = top.map((t) => t.id);
      const maxVal = Math.max(...values, 0);
      const xMaxIdx = Math.max(0, top.length - 1);
      const yMaxIdx = Math.max(0, tactics.length - 1);
      const xRange = { min: -AXIS_PADDING, max: xMaxIdx + AXIS_PADDING + 0.4 };
      const yRange = { min: -AXIS_PADDING, max: yMaxIdx + AXIS_PADDING + 0.4 };
      const zMax = Math.max(maxVal * 1.1 + 0.05, 1);
      const zRange = { min: 0, max: zMax };
      const colors = getColors ? getColors() : {
        paper: '#0f1326',
        canvas: '#0b1023',
        grid: '#1e2748',
        hoverBg: 'rgba(16,20,37,0.92)',
        hoverText: '#e5e7ef',
      };
      const mono = typeof getMonoFlag === 'function' ? !!getMonoFlag() : false;
      const showCves = typeof getShowCves === 'function' ? !!getShowCves() : true;
      const traces = [];
      top.forEach((item, idx) => {
        const faces = buildBarSurfaces(
          item,
          { x: idx, y: tacticToPos.get(item.tactic) || 0 },
          currentMetric,
          safeNum(item[currentMetric]),
          maxVal,
          colors.hoverBg || 'rgba(16,20,37,0.92)',
          colors.hoverText || '#e5e7ef',
          mono,
        );
        faces.forEach(f => traces.push(f));
      });

      const axisTraces = buildAxisTraces({ x: xRange, y: yRange, z: zRange }, { ...colors, axis: colors.axis || colors.grid });
      axisTraces.forEach((t) => traces.push(t));

      const layout = buildLayout({
        xCount: top.length,
        xLabels: cveLabels,
        yLabels: tactics.map((t) => formatTacticLabel(t, translateTactic)),
        metric: currentMetric,
        showCves,
        showTactics: typeof getShowTactics === 'function' ? !!getShowTactics() : true,
        camera: lastCamera || DEFAULT_CAMERA,
        colors: {
          paper: colors.paper || '#0f1326',
          canvas: colors.canvas || '#0b1023',
          grid: colors.grid || '#1e2748',
          hoverBg: colors.hoverBg || 'rgba(16,20,37,0.92)',
          hoverText: colors.hoverText || '#e5e7ef',
        },
        ranges: { x: xRange, y: yRange, z: zRange },
      });

      Plotly.react(plotEl, traces, layout, { displaylogo: false, responsive: true, modeBarButtonsToRemove: ['toImage'] })
        .then(() => {
          try {
            const sc = plotEl && plotEl._fullLayout && plotEl._fullLayout.scene;
            if (sc && sc.camera) lastCamera = sc.camera;
          } catch {}
        });
      ready = true;
    }

    async function handleExport() {
      if (!plotEl || !window.Plotly) return;
      if (!ready) {
        render();
        if (!ready) return;
      }
      try {
        const w = Math.max(1000, plotEl.clientWidth || 1000);
        const h = Math.max(720, plotEl.clientHeight || 720);
        const fname = buildFileName ? buildFileName() : 'landscape.png';
        const url = await Plotly.toImage(plotEl, { format: 'png', scale: 2, width: w, height: h });
        const a = document.createElement('a');
        a.href = url;
        a.download = fname;
        a.click();
      } catch (e) {
        console.warn('landscape export', e);
      }
    }

    function handleExportCsv() {
      if (!hasData()) {
        showNotice('Сначала нужно сгенерировать сценарий');
        return;
      }
      const top = pickTop(collectPrimaryCves(megaData, translateTactic), currentMetric);
      if (!top.length) {
        showNotice('Нет данных для выбранной метрики');
        return;
      }
      const sep = ';';
      const metricLabel = METRIC_TITLES[currentMetric] || (currentMetric || 'Метрика');
      const metricDigits = Number.isFinite(METRIC_DIGITS[currentMetric])
        ? METRIC_DIGITS[currentMetric]
        : (String(currentMetric || '').startsWith('risk') ? 5 : 4);
      const formatNum = (v, digits = 4) => fmt(v, digits).replace('.', ',');
      const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
      const rows = [];
      rows.push(['CVE', 'Тактика', 'Порядок тактики', 'CVSS', 'EPSS', 'Вероятность', 'Ущерб', 'Риск', metricLabel].join(sep));
      top.forEach((item) => {
        rows.push([
          esc(item.id),
          esc(formatTacticLabel(item.tactic, translateTactic)),
          String(safeNum(item.tacticOrder)),
          formatNum(item.cvss, 2),
          formatNum(item.epss, 4),
          formatNum(item.epss_norm, 4),
          formatNum(item.damage, 4),
          formatNum(item.risk, 5),
          formatNum(item[currentMetric], metricDigits),
        ].join(sep));
      });
      const csv = rows.join('\n');
      const baseName = (buildFileName ? buildFileName() : 'landscape.png').replace(/\.png$/i, '') || 'landscape';
      const fname = `${baseName}_data.csv`;
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fname;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function open() {
      showNotice('Загрузка...');
      openBackdrop();
      setTimeout(() => render(), 0);
    }

    function setData(mega) {
      megaData = Array.isArray(mega) ? mega : [];
      if (metricSelect && metricSelect.value) currentMetric = metricSelect.value;
    }

    function clearData() {
      megaData = [];
      ready = false;
    }

    if (metricSelect) {
      metricSelect.addEventListener('change', () => {
        currentMetric = metricSelect.value || DEFAULT_METRIC;
        render();
      });
    }
    if (exportBtn) exportBtn.addEventListener('click', handleExport);
    if (exportCsvBtn) exportCsvBtn.addEventListener('click', handleExportCsv);
    if (closeBtn) closeBtn.addEventListener('click', closeBackdrop);
    if (backdrop) {
      backdrop.addEventListener('click', (e) => { if (e.target === backdrop) closeBackdrop(); });
    }

    return {
      open,
      setData,
      clearData,
      showEmpty: () => { showNotice('Сначала нужно сгенерировать сценарий'); openBackdrop(); },
      render,
    };
  }

  window.SGLandscape = { create };
})();
