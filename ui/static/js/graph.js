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
  const closeAllKeys = document.getElementById('close-all-keys');
  const genScenariosBtn = document.getElementById('gen-scenarios');
  const clearScenariosBtn = document.getElementById('clear-scenarios');
  const scenariosList = document.getElementById('scenarios-list');
  const drawBtn = document.getElementById('draw-btn');
  // Переключатели профиля и темы
  const profileBtn = document.getElementById('profile-toggle');
  const themeToggleBtn = document.getElementById('theme-toggle');
  // Элементы управления сворачиванием инспектора
  const insp = document.querySelector('.page-graph .inspector');
  const inspToggle = document.getElementById('insp-toggle');
  const mainGrid = document.querySelector('.page-graph main');
  // Настройки темы
  const themeBtn = document.getElementById('open-theme');
  const themeBackdrop = document.getElementById('theme-backdrop');
  // Экспорт
  const exportBtn = document.getElementById('open-export');
  const exportBackdrop = document.getElementById('export-backdrop');
  const exportPngBtn = document.getElementById('export-png');
  const exportSvgBtn = document.getElementById('export-svg');
  const exportJsonBtn = document.getElementById('export-json');
  const exportCloseBtn = document.getElementById('export-close');
  const exportTransparent = document.getElementById('export-transparent');
  // 3D ландшафт
  const landscapeBtn = document.getElementById('open-landscape');
  const landscapeBackdrop = document.getElementById('landscape-backdrop');
  const landscapeMetricSel = document.getElementById('landscape-metric');
  const landscapeExportBtn = document.getElementById('landscape-export');
  const landscapeExportCsvBtn = document.getElementById('landscape-export-csv');
  const landscapeCloseBtn = document.getElementById('landscape-close');
  const landscapePlot = document.getElementById('landscape-plot');
  const landscapeNotice = document.getElementById('landscape-notice');
  const landscapeMono = document.getElementById('landscape-mono');
  const landscapeShowCves = document.getElementById('landscape-show-cves');
  const landscapeShowTactics = document.getElementById('landscape-show-tactics');
  const themeCanvasInput = document.getElementById('theme-canvas');
  const themeLabelInput = document.getElementById('theme-label');
  const themeNodeInputs = {
    CPE: document.getElementById('theme-node-cpe'),
    CVE: document.getElementById('theme-node-cve'),
    CWE: document.getElementById('theme-node-cwe'),
    CAPEC: document.getElementById('theme-node-capec'),
    Technique: document.getElementById('theme-node-tech'),
  };
  // Управление цветами рёбер убрано из пользовательских настроек
  const themeResetBtn = document.getElementById('theme-reset');
  const themeCancelBtn = document.getElementById('theme-cancel');
  const themeApplyBtn = document.getElementById('theme-apply');
  const LS_FORM = 'sg:graph:form';
  const LS_SNAP = 'sg:graph:snapshot';
  const LS_SCEN = 'sg:graph:scenarios';
  const LS_SC_FORM = 'sg:graph:scform';
  const LS_THEME = 'sg:graph:theme';
  const LS_INSP = 'sg:graph:inspCollapsed';
  const LS_PROFILE = 'sg:ui:profile'; // 'color' | 'mono'
  const SNAP_LIMIT = 2 * 1024 * 1024; // 2 МБ
  // Масштаб экспорта изображений
  const EXPORT_SCALE = 2;
  // Толщина рёбер CVE в ч/б профиле сценариев
  const SC_MONO_EDGE_WIDTH = 2;

  let cy = null;
  let isScenarioView = false;
  let currentScenarioId = null;
  const scenarioShowBtns = new Map();
  let currentScenarioData = null; // выбранный сценарий для повторной перерисовки
  let lastMega = null; // mega для первичного сценария
  let landscape = null; // контроллер 3D ландшафта
  // Состояние ключей в сценариях
  let linearClosedKeyByTactic = new Map();
  let primaryClosedKeyByTactic = new Map();
  let followKeysHandler = null;
  let syncingKeys = false;

  // Перевод названий тактик ATT&CK для отображения
  function translateTacticName(name) {
    try {
      const raw = String(name || '').trim();
      if (!raw) return raw;
      const key = raw.toLowerCase().replace(/[ _]+/g, '-');
      const map = {
        'reconnaissance': 'Разведка',
        'resource-development': 'Подготовка ресурсов',
        'initial-access': 'Первоначальный доступ',
        'execution': 'Выполнение',
        'persistence': 'Закрепление',
        'privilege-escalation': 'Повышение привилегий',
        'defense-evasion': 'Обход защиты',
        'credential-access': 'Получение учетных данных',
        'discovery': 'Изучение',
        'lateral-movement': 'Перемещение внутри периметра',
        'collection': 'Сбор данных',
        'command-and-control': 'Организация управления',
        'exfiltration': 'Эксфильтрация данных',
        'impact': 'Деструктивное воздействие',
      };
      return map[key] || raw;
    } catch { return name; }
  }

  // Перевод тактики в многострочную подпись (одно слово на строку)
  function tacticLabelMultiline(label) {
    try {
      const s = String(label || '').trim();
      if (!s) return s;
      return s.split(/\s+/).join('\n');
    } catch { return label; }
  }

  // Перевод названий свойств для панели инспектора
  const INSPECTOR_PROP_NAMES = {
    common: {
      identifier: 'Идентификатор',
      name: 'Название',
      description: 'Описание',
      label: 'Метка на графе',
      external_link: 'Внешняя ссылка',
      tactic: 'Тактика',
      tactics: 'Тактики',
      primary_tactic: 'Основная тактика',
      tactic_order: 'Порядок тактики',
    },
    Technique: {},
    CVE: {
      cvss: 'CVSS (базовый балл)',
      cvss_C_score: 'CVSS: конфиденциальность',
      cvss_I_score: 'CVSS: целостность',
      cvss_A_score: 'CVSS: доступность',
      epss: 'EPSS',
      epss_norm: 'Нормированная вероятность',
      cvss_epss_ratio: 'Отношение CVSS/EPSS',
      cvss_epss_max_ratio: 'Макс. CVSS/EPSS по тактике',
      damage: 'Потенциальный ущерб',
      risk: 'Риск',
      damage_C: 'Ущерб конфиденциальности',
      damage_I: 'Ущерб целостности',
      damage_A: 'Ущерб доступности',
      risk_C: 'Риск нарушения конфиденциальности',
      risk_I: 'Риск нарушения целостности',
      risk_A: 'Риск нарушения доступности',
      cvss_C_epss_ratio: 'Отношение Conf/EPSS',
      cvss_I_epss_ratio: 'Отношение Integ/EPSS',
      cvss_A_epss_ratio: 'Отношение Avail/EPSS',
      cvss_C_epss_max_ratio: 'Макс. Conf/EPSS по тактике',
      cvss_I_epss_max_ratio: 'Макс. Integ/EPSS по тактике',
      cvss_A_epss_max_ratio: 'Макс. Avail/EPSS по тактике',
      published: 'Дата публикации',
      epss_from_first: 'EPSS из FIRST',
      patch_vendor: 'Патч от вендора',
      patch_third_party: 'Патч от третьих сторон',
      in_cisa_kev: 'В каталоге CISA KEV',
      cisa_kev_due_date: 'Срок устранения CISA KEV',
    },
    CPE: {
      cpe23Uri: 'CPE 2.3 URI',
      part: 'Часть (part)',
      vendor: 'Производитель',
      product: 'Продукт',
      version: 'Версия',
      update: 'Обновление',
      edition: 'Редакция',
      language: 'Язык',
      sw_edition: 'Редакция ПО',
      target_sw: 'Целевая платформа (ПО)',
      target_hw: 'Целевое оборудование',
      other: 'Другое',
    },
    Target: {
      targetUri: 'URI Target',
      name: 'Имя объекта',
      input_total: 'Всего CVE',
      found_count: 'Найдено CVE',
      missing_count: 'Отсутствует CVE',
      created_at: 'Создан',
      updated_at: 'Обновлён',
    },
    CWE: {
      abstraction: 'Абстракция',
      status: 'Статус',
    },
    CAPEC: {},
  };

  function translatePropName(key, group) {
    const safeKey = String(key || '');
    const groupMap = INSPECTOR_PROP_NAMES[group] || {};
    if (Object.prototype.hasOwnProperty.call(groupMap, safeKey)) return groupMap[safeKey];
    if (Object.prototype.hasOwnProperty.call(INSPECTOR_PROP_NAMES.common, safeKey)) return INSPECTOR_PROP_NAMES.common[safeKey];
    return safeKey;
  }

  function escapeHtml(val) {
    return String(val || '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[ch] || ch));
  }

  function formatInspectorValue(key, value) {
    const k = String(key || '');
    let v = value;
    if (Array.isArray(v) && k === 'tactics') {
      v = v.map(t => translateTacticName(t) || t);
    } else if (typeof v === 'string' && (k === 'primary_tactic' || k === 'tactic')) {
      const translated = translateTacticName(v);
      v = translated || v;
    }
    if (Array.isArray(v)) v = v.join(', ');
    if (v == null) v = '';
    if (k === 'external_link' && typeof v === 'string' && v) {
      const safe = escapeHtml(v);
      return `<a href="${safe}" target="_blank" rel="noreferrer noopener">${safe}</a>`;
    }
    const vs = String(v);
    return vs.length > 800 ? vs.slice(0, 800) : vs;
  }

  function addInspectorRow(rows, key, value, group) {
    const label = translatePropName(key, group);
    const val = formatInspectorValue(key, value);
    rows.push(`<div class="row"><div class="k">${label}</div><div class="v">${val}</div></div>`);
  }

  function appendExternalLink(rows, props, group) {
    if (!props) return;
    const link = props.external_link;
    if (!link) return;
    addInspectorRow(rows, 'external_link', link, group);
  }

  // Обработка сворачивания инспектора
  function setInspectorCollapsed(flag, save=true) {
    try {
      if (mainGrid) mainGrid.classList.toggle('insp-collapsed', !!flag);
      if (insp) insp.classList.toggle('collapsed', !!flag);
      if (save) { try { localStorage.setItem(LS_INSP, JSON.stringify(!!flag)); } catch {} }
      // Сообщаем Cytoscape об изменении размера контейнера
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

  // вспомогательные функции CSS
  const cssVar = (name, fallback='') => {
    try { const v = getComputedStyle(document.body).getPropertyValue(name).trim(); return v || fallback; } catch { return fallback; }
  };
  const labelColorFromCss = () => cssVar('--text', '#e5e7ef');
  const mutedColorFromCss = () => cssVar('--muted', '#9aa0b4');
  const gridColorFromCss = () => cssVar('--line-soft', '#1e2748');

  function initLandscapeController() {
    if (!window.SGLandscape || landscape) return;
    landscape = window.SGLandscape.create({
      backdrop: landscapeBackdrop,
      plotEl: landscapePlot,
      metricSelect: landscapeMetricSel,
      exportBtn: landscapeExportBtn,
      exportCsvBtn: landscapeExportCsvBtn,
      closeBtn: landscapeCloseBtn,
      noticeEl: landscapeNotice,
      translateTactic: translateTacticName,
      getColors: () => ({
        paper: cssVar('--panel', '#0f1326'),
        canvas: cssVar('--bg', '#0b1023'),
        grid: gridColorFromCss(),
        hoverBg: cssVar('--panel', 'rgba(15,19,38,0.94)'),
        hoverText: cssVar('--text', '#e5e7ef'),
      }),
      buildFileName: buildLandscapeFileName,
      getMonoFlag: () => (landscapeMono && !landscapeMono.disabled ? !!landscapeMono.checked : false),
      getShowCves: () => (landscapeShowCves ? !!landscapeShowCves.checked : true),
      getShowTactics: () => (landscapeShowTactics ? !!landscapeShowTactics.checked : true),
    });
    if (landscapeBtn) {
      landscapeBtn.addEventListener('click', () => {
        if (Array.isArray(lastMega) && lastMega.length > 0) {
          landscape.setData(lastMega);
          landscape.open();
        } else {
          landscape.showEmpty();
        }
      });
    }
    if (landscapeMono) {
      const applyMonoAvailability = () => {
        const mode = getUiThemeMode();
        const isDark = mode === 'dark';
        if (isDark) {
          landscapeMono.checked = false;
          landscapeMono.disabled = true;
          landscapeMono.title = 'Ч/Б режим недоступен в тёмной теме';
        } else {
          landscapeMono.disabled = false;
          landscapeMono.title = 'Переключить палитру в Ч/Б';
        }
      };
      applyMonoAvailability();
      document.addEventListener('sg:theme-change', applyMonoAvailability);
      landscapeMono.addEventListener('change', () => { if (landscape) landscape.render && landscape.render(); });
    }
    if (landscapeShowCves) {
      landscapeShowCves.addEventListener('change', () => { if (landscape) landscape.render && landscape.render(); });
    }
    if (landscapeShowTactics) {
      landscapeShowTactics.addEventListener('change', () => { if (landscape) landscape.render && landscape.render(); });
    }
  }

  function syncLandscapeData(mega) {
    lastMega = Array.isArray(mega) ? mega : [];
    if (landscape) landscape.setData(lastMega);
  }

  // профили и вспомогательные функции для Ч/Б
  function getUiThemeMode() {
    try { const m = localStorage.getItem('sg:ui:mode'); return (m === 'light' || m === 'dark') ? m : 'dark'; } catch { return 'dark'; }
  }
  function getProfile() {
    try { const v = localStorage.getItem(LS_PROFILE); return v === 'mono' ? 'mono' : 'color'; } catch { return 'color'; }
  }
  function setProfile(p) {
    try { localStorage.setItem(LS_PROFILE, p === 'mono' ? 'mono' : 'color'); } catch {}
    // В Ч/Б профиле принудительно убираем пользовательский фон холста
    try { if (p === 'mono' && container) container.style.background = ''; } catch {}
    updateProfileUI();
    rerenderAccordingToProfile();
  }
  function updateProfileUI() {
    const profile = getProfile();
    const mode = getUiThemeMode();
    const isLight = mode === 'light';
    if (profileBtn) {
      profileBtn.textContent = profile === 'mono' ? 'Профиль: Ч/Б с тонированием' : 'Профиль: Стандартный';
      if (!isLight) {
        profileBtn.disabled = true;
        profileBtn.title = 'Профиль доступен только в светлой теме';
      } else {
        profileBtn.disabled = false;
        profileBtn.title = 'Переключить профиль визуализации';
      }
    }
    if (themeToggleBtn) {
      if (profile === 'mono') {
        themeToggleBtn.disabled = true;
        themeToggleBtn.title = 'Смена темы интерфейса не поддерживается для выбранного профиля';
      } else {
        themeToggleBtn.disabled = false;
        themeToggleBtn.title = (mode === 'light') ? 'Тёмная тема' : 'Светлая тема';
      }
    }
    // Отключаем локальные настройки визуализации в профиле Ч/Б
    if (themeBtn) {
      if (profile === 'mono') {
        themeBtn.disabled = true;
        themeBtn.title = 'Настройки недоступны для выбранного профиля';
      } else {
        themeBtn.disabled = false;
        themeBtn.title = 'Настройки отображения';
      }
    }
    // Чекбокс «Замкнуть все ключи» имеет смысл только в Ч/Б профиле
    if (closeAllKeys) {
      const wrap = closeAllKeys.closest('.field') || closeAllKeys.parentElement;
      if (profile === 'mono') {
        if (wrap) wrap.style.display = '';
        closeAllKeys.disabled = false;
      } else {
        if (wrap) wrap.style.display = 'none';
        closeAllKeys.checked = false;
        closeAllKeys.disabled = true;
      }
    }
  }
  function bindProfileUI() {
    if (profileBtn) profileBtn.addEventListener('click', () => { if (!profileBtn.disabled) setProfile(getProfile() === 'mono' ? 'color' : 'mono'); });
    document.addEventListener('sg:theme-change', updateProfileUI);
    updateProfileUI();
  }

  function cvssSumFromRaw(raw) {
    try {
      const p = raw && (raw.props || raw) || {};
      const c = Number(p.cvss_C_score || 0);
      const i = Number(p.cvss_I_score || 0);
      const a = Number(p.cvss_A_score || 0);
      let s = c + i + a;
      if (!isFinite(s)) s = 0; if (s < 0) s = 0; if (s > 10) s = 10; return s;
    } catch { return 0; }
  }
  const KEV_STRIPE_IMG_DARK = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2IiBoZWlnaHQ9IjYiIHZpZXdCb3g9IjAgMCA2IDYiPgogIDxkZWZzPgogICAgPHBhdHRlcm4gaWQ9InAiIHBhdHRlcm5Vbml0cz0idXNlclNwYWNlT25Vc2UiIHdpZHRoPSI2IiBoZWlnaHQ9IjYiPgogICAgICA8cGF0aCBkPSJNMCA2IEw2IDAiIHN0cm9rZT0iIzAwMDAwMCIgc3Ryb2tlLXdpZHRoPSIxLjIiIG9wYWNpdHk9IjAuNTUiIGZpbGw9Im5vbmUiIC8+CiAgICA8L3BhdHRlcm4+CiAgPC9kZWZzPgogIDxyZWN0IHdpZHRoPSI2IiBoZWlnaHQ9IjYiIGZpbGw9InVybCgjcCkiIC8+Cjwvc3ZnPg==';
  const KEV_STRIPE_IMG_LIGHT = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2IiBoZWlnaHQ9IjYiIHZpZXdCb3g9IjAgMCA2IDYiPgogIDxkZWZzPgogICAgPHBhdHRlcm4gaWQ9InAiIHBhdHRlcm5Vbml0cz0idXNlclNwYWNlT25Vc2UiIHdpZHRoPSI2IiBoZWlnaHQ9IjYiPgogICAgICA8cGF0aCBkPSJNMCA2IEw2IDAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIxLjIiIG9wYWNpdHk9IjAuNTUiIGZpbGw9Im5vbmUiIC8+CiAgICA8L3BhdHRlcm4+CiAgPC9kZWZzPgogIDxyZWN0IHdpZHRoPSI2IiBoZWlnaHQ9IjYiIGZpbGw9InVybCgjcCkiIC8+Cjwvc3ZnPg==';
  function kevStripeImageForEle(ele) {
    try {
      if (!ele || ele.data('group') !== 'CVE') return 'none';
      const raw = ele.data('raw') || {};
      const p = (raw && (raw.props || raw)) || {};
      if (!p.in_cisa_kev) return 'none';
      const s = cvssSumFromRaw(raw);
      const lbl = (s > 6.7) ? '#ffffff' : '#111';
      return (lbl === '#ffffff') ? KEV_STRIPE_IMG_LIGHT : KEV_STRIPE_IMG_DARK;
    } catch { return 'none'; }
  }
  function grayFromScore0to10(v) {
    const s = Math.max(0, Math.min(10, Number(v) || 0));
    const l = 92 - (s / 10) * 70; // 92% -> 22%
    return `hsl(0, 0%, ${l.toFixed(1)}%)`;
  }
  function clamp01(x) {
    if (!Number.isFinite(x) || x <= 0) return 0;
    if (x >= 1) return 1;
    return x;
  }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function monoEdgeColorFromEpssNorm(v) {
    const t = Math.pow(clamp01(Number(v || 0)), 0.65);
    const start = { r: 224, g: 224, b: 224 }; // светло-серый
    const end = { r: 16, g: 16, b: 16 };      // почти чёрный
    const r = Math.round(lerp(start.r, end.r, t));
    const g = Math.round(lerp(start.g, end.g, t));
    const b = Math.round(lerp(start.b, end.b, t));
    return `rgb(${r},${g},${b})`;
  }
  function epssWidth(v) {
    let e = Number(v || 0); if (!isFinite(e) || e < 0) e = 0; if (e > 1) e = 1; return 1.2 + 9.0 * e; // более заметная толщина
  }
  function edgeEpssNorm(ele) {
    try {
      const direct = Number(ele.data('epss_norm'));
      if (Number.isFinite(direct)) return clamp01(direct);
      const keyNorm = Number(ele.data('keyEpssNorm'));
      if (Number.isFinite(keyNorm)) return clamp01(keyNorm);
      const keyEpss = Number(ele.data('keyEpss'));
      if (Number.isFinite(keyEpss)) return clamp01(keyEpss);
      const cveId = ele.data('keyCveNodeId') || ele.data('stepCveId');
      if (cveId && cy) {
        const node = cy.getElementById(String(cveId));
        if (node && node.length) {
          const raw = node.data('raw') || {};
          const props = (raw.props || raw) || {};
          const v = Number(props.epss_norm);
          if (Number.isFinite(v)) return clamp01(v);
          const eVal = Number(props.epss);
          if (Number.isFinite(eVal)) return clamp01(eVal);
        }
      }
    } catch {}
    return 0;
  }
  function monoEdgeColor(ele) {
    const n = edgeEpssNorm(ele);
    return monoEdgeColorFromEpssNorm(n);
  }
  function cveKey(cv) {
    try {
      const props = (cv && cv.props) || {};
      if (props.identifier) return String(props.identifier);
      if (cv && cv.id) return String(cv.id);
    } catch {}
    return '';
  }
  function isPredictedEdge(score) {
    const s = Number(score);
    return Number.isFinite(s) && s > 0 && s < 1;
  }
  function predictedData(score) {
    return isPredictedEdge(score) ? { predictedEdge: true } : {};
  }
  function shapeMono(group) {
    switch (group) {
      case 'Technique': return 'rectangle';
      case 'CVE': return 'ellipse';
      case 'CPE': return 'octagon';
      case 'Target': return 'octagon';
      case 'CWE': return 'diamond';
      case 'CAPEC': return 'pentagon';
      case 'ScenarioEndpoint': return 'ellipse';
      default: return 'ellipse';
    }
  }

  function graphStyleForProfile(profile) {
    const lblColor = labelColorFromCss();
    const muted = mutedColorFromCss();
    if (profile === 'mono') {
      return [
        { selector: 'node', style: {
          'label': 'data(label)', 'color': ele => {
            if (ele.data('group') === 'CVE') { const s = cvssSumFromRaw(ele.data('raw')); return (s > 6.7) ? '#ffffff' : '#111'; }
            return lblColor;
          }, 'font-size': 12,
          'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'none',
          'shape': ele => shapeMono(ele.data('group')),
          'background-image': ele => kevStripeImageForEle(ele),
          'background-fit': 'none',
          'background-repeat': 'repeat',
          'background-color': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return '#ffffff';
            if (g === 'CVE') { const sum = cvssSumFromRaw(ele.data('raw')); return grayFromScore0to10(sum); }
            if (g === 'TacticGroup') return '#e7e9f0';
            return '#dddddd';
          },
          'border-width': 1.2, 'border-color': '#7a8094',
          'width': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return 50;
            if (g === 'CVE') return 40;
            return 46;
          },
          'height': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return 50;
            if (g === 'CVE') return 40;
            return 46;
          },
          'padding': 0
        }},
        { selector: 'node[group="ScenarioEndpoint"]', style: { 'font-size': 16, 'width': 80, 'height': 46, 'shape': 'ellipse' }},
        { selector: 'node[group="TechLabel"]', style: { 'background-opacity': 0, 'border-width': 0, 'label': 'data(label)', 'font-size': 16, 'color': muted, 'text-halign': 'center', 'text-valign':'center', 'text-margin-y': -2, 'events': 'no' }},
        { selector: 'node.sel', style: { 'border-width': 5, 'border-color': '#000000', 'z-index': 999 }},
        { selector: 'node.neigh', style: { 'border-width': 2, 'border-color': '#9aa3b9' }},
        { selector: 'edge', style: { 'curve-style': 'bezier', 'target-arrow-shape': 'none', 'line-color': '#9aa3b2', 'width': 1.2, 'opacity': 0.9 }},
        { selector: 'edge[type="CAPEC_TO_TECHNIQUE_PRED"]', style: { 'line-style': 'dashed' } },
      ];
    }
    return [
      { selector: 'node', style: {
        'label': 'data(label)','color': lblColor,'font-size': 12,'text-valign':'center','text-halign':'center','text-wrap': 'none',
        'background-color': ele => colorByGroup(ele.data('group')),'shape': 'ellipse','border-width': 1,'border-color': '#2a3052','width': 46,'height': 46,'padding': 0 }},
      
      { selector: 'node.sel', style: { 'border-width': 3, 'border-color': '#4f8cff', 'z-index': 999 }},
      { selector: 'node.neigh', style: { 'border-width': 2, 'border-color': '#3b4775' }},
      { selector: 'edge', style: { 'curve-style': 'bezier', 'target-arrow-shape': 'none', 'line-color': ele => edgeColor(ele.data('type')), 'width': 1.2, 'opacity': 0.85 }},
      { selector: 'edge[type="CAPEC_TO_TECHNIQUE_PRED"]', style: { 'line-style': 'dashed' } },
    ];
  }

  function scenarioStyleForProfile(profile) {
    const lblColor = labelColorFromCss();
    const muted = mutedColorFromCss();
    const isLightMode = (getUiThemeMode() === 'light');
    const canvasColor = cssVar('--canvas', '#f2f4fb');
    if (profile === 'mono') {
      return [
        { selector: 'node', style: {
          'label': 'data(label)','color': ele => {
            if (ele.data('group') === 'CVE') { const s = Number(ele.data('cvss') || 0); return (s > 6.7) ? '#ffffff' : '#111'; }
            return lblColor;
          },'font-size': 12,'text-valign':'center','text-halign':'center','text-wrap':'none',
          'shape': ele => shapeMono(ele.data('group')),
          'background-image': ele => kevStripeImageForEle(ele),
          'background-fit': 'none',
          'background-repeat': 'repeat',
          'background-color': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return '#ffffff';
            if (g === 'CVE') { const sum = Number(ele.data('cvss') || 0); return grayFromScore0to10(sum); }
            if (g === 'TacticGroup') return '#e7e9f0';
            return '#dddddd';
          },
          'border-width': 1.2, 'border-color': '#7a8094',
          'width': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return 50;
            if (g === 'CVE') return 40;
            return 46;
          },
          'height': ele => {
            const g = ele.data('group');
            if (g === 'Technique') return 50;
            if (g === 'CVE') return 40;
            return 46;
          },
          'padding': 0
        }},
        { selector: 'node[group="ScenarioEndpoint"]', style: { 'font-size': 16, 'width': 80, 'height': 46, 'shape': 'ellipse' }},
        { selector: 'node[group="KeyContact"]', style: {
          'shape': 'ellipse',
          'background-color': canvasColor,
          'border-width': 1,
          'border-color': '#9aa3b2',
          'width': 5,
          'height': 5,
          'label': '',
          'z-index': 1001
        }},
        { selector: 'node[group="KeyPivot"]', style: {
          'shape': 'ellipse',
          'background-color': canvasColor,
          'border-width': 1,
          'border-color': '#9aa3b2',
          'width': 5,
          'height': 5,
          'label': '',
          'z-index': 1000
        }},
        { selector: 'node[group="TechLabel"]', style: { 'background-opacity': 0, 'border-width': 0, 'label': 'data(label)', 'font-size': 16, 'color': muted, 'text-halign': 'center', 'text-valign':'center', 'text-margin-y': -2, 'events': 'no' }},
        { selector: 'node[group="TacticGroup"]', style: { 'shape': 'round-rectangle', 'background-color':'#e7e9f0', 'background-opacity': 1, 'label': 'data(label)', 'text-valign': 'top', 'text-halign':'center', 'border-color': '#bfc6d8', 'border-width': 1, 'padding': 14, 'color': muted, 'font-size': 20, 'text-margin-y': -15, 'text-wrap': 'wrap', 'text-max-width': 140 }},
        { selector: 'node.sel', style: { 'border-width': 5, 'border-color':'#000000', 'z-index': 999 }},
        { selector: 'node.neigh', style: { 'border-width': 2, 'border-color': '#9aa3b9' }},
        { selector: 'edge', style: { 'curve-style':'bezier','target-arrow-shape':'none','line-color':'#9aa3b2','width': 1.2,'opacity': 0.9 }},
        { selector: 'edge[predictedEdge]', style: { 'line-style': 'dashed' }},
        { selector: 'edge[type="SC_TECH_TO_CVE"]', style: { 'line-color': ele => monoEdgeColor(ele), 'width': SC_MONO_EDGE_WIDTH }},
        { selector: 'edge[type="SC_STEP"]', style: { 'opacity': 0, 'line-opacity': 0, 'target-arrow-shape': 'none' }},
        { selector: 'edge[type="SC_GROUP"]', style: { 'opacity': 0, 'line-opacity': 0, 'target-arrow-shape': 'none' }},
        { selector: 'edge[type="SC_GROUP_LINK"]', style: { 'target-arrow-shape': 'triangle', 'target-arrow-color': '#9aa3b2' }},
        { selector: 'edge[type="SC_KEY_SEG"]', style: { 'line-color': ele => monoEdgeColor(ele), 'width': SC_MONO_EDGE_WIDTH }},
        { selector: 'edge[type="SC_KEY_SWITCH"]', style: { 'line-color': ele => monoEdgeColor(ele), 'width': SC_MONO_EDGE_WIDTH }},
        { selector: 'edge[type="SC_KEY_ARROW"]', style: {
          'line-color': ele => monoEdgeColor(ele),
          'width': SC_MONO_EDGE_WIDTH,
          'target-arrow-shape': 'triangle',
          'target-arrow-color': ele => monoEdgeColor(ele)
        }},
      ];
    }
    return [
      { selector: 'node', style: {
        'label': 'data(label)',
        'color': lblColor,
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
      { selector: 'node[group="TechLabel"]', style: { 'background-opacity': 0, 'border-width': 0, 'label': 'data(label)', 'font-size': 16, 'color': muted, 'text-halign': 'center', 'text-valign':'center', 'text-margin-y': -2, 'events': 'no' }},
      // Стиль карточек тактик
      { selector: 'node[group="TacticGroup"]', style: {
        'shape':'round-rectangle',
        'background-color': isLightMode ? '#3b6eea' : '#141939',
        'background-opacity': isLightMode ? 0.14 : 0.22,
        'label':'data(label)',
        'text-valign':'top','text-halign':'center','border-color':'#3b4775','border-width':1,'padding':14,'font-size':20,'text-margin-y':-15,'text-wrap':'wrap','text-max-width':140
      }},
      { selector: 'node.sel', style: { 'border-width': 3, 'border-color': '#4f8cff', 'z-index': 999 }},
      { selector: 'node.neigh', style: { 'border-width': 2, 'border-color': '#3b4775' }},
      { selector: 'edge', style: { 'curve-style': 'bezier', 'target-arrow-shape': 'none', 'line-color': ele => edgeColor(ele.data('type')), 'width': 1.2, 'opacity': 0.85 }},
      { selector: 'edge[predictedEdge]', style: { 'line-style': 'dashed' }},
      // Стрелки от CVE к следующей тактике
      { selector: 'edge[type="SC_GROUP"]', style: { 'target-arrow-shape': 'triangle', 'target-arrow-color': '#8e44ad' }},
      { selector: 'edge[type="SC_GROUP_LINK"]', style: { 'target-arrow-shape': 'triangle', 'target-arrow-color': '#7f8c8d' }},
    ];
  }

  // Геометрия ключа между CVE и следующим шагом
  function computeKeyGeometry(cvePos, targetPos, state) {
    try {
      const c = cvePos || { x: 0, y: 0 };
      const t = targetPos || { x: c.x + 1, y: c.y };
      const dx = Number(t.x) - Number(c.x);
      const dir = (dx >= 0) ? 1 : -1;
      const BASE_OFFSET = 30; // от центра CVE до левого контакта
      const KEY_LEN = 16;     // длина перемычки ключа
      const left = {
        x: c.x + dir * BASE_OFFSET,
        y: c.y,
      };
      const right = {
        x: left.x + dir * KEY_LEN,
        y: left.y,
      };
      let pivot = { x: right.x, y: right.y };
      if (state === 'open') {
        const vx = right.x - left.x;
        const vy = right.y - left.y;
        const angle = (dir >= 0) ? -Math.PI / 4 : Math.PI / 4;
        const cosA = Math.cos(angle);
        const sinA = Math.sin(angle);
        const rx = vx * cosA - vy * sinA;
        const ry = vx * sinA + vy * cosA;
        pivot = {
          x: left.x + rx,
          y: left.y + ry,
        };
      }
      return { left, right, pivot };
    } catch {
      return { left: cvePos, right: targetPos, pivot: targetPos };
    }
  }

  function syncKeyPositionsForPivot(pivot) {
    if (!cy || !pivot || !pivot.length) return;
    try {
      const cveId = String(pivot.data('keyCveNodeId') || '');
      const targetId = String(pivot.data('keyTargetId') || '');
      const leftId = String(pivot.data('keyLeftId') || '');
      const rightId = String(pivot.data('keyRightId') || '');
      if (!cveId || !targetId || !leftId || !rightId) return;
      const cve = cy.getElementById(cveId);
      const target = cy.getElementById(targetId);
      const left = cy.getElementById(leftId);
      const right = cy.getElementById(rightId);
      if (!cve.length || !target.length || !left.length || !right.length) return;
      const state = pivot.data('keyState') === 'closed' ? 'closed' : 'open';
      const geom = computeKeyGeometry(cve.position(), target.position(), state);
      left.position(geom.left);
      right.position(geom.right);
      pivot.position(geom.pivot);
    } catch {}
  }

  function syncAllKeyPositions() {
    if (!cy) return;
    if (syncingKeys) return;
    syncingKeys = true;
    try {
      const pivots = cy.nodes("[group='KeyPivot']");
      if (!pivots || pivots.length === 0) return;
      pivots.forEach(p => syncKeyPositionsForPivot(p));
    } catch {} finally {
      syncingKeys = false;
    }
  }

  function bindKeyFollow() {
    if (!cy) return;
    if (followKeysHandler) {
      try { cy.off('position', 'node', followKeysHandler); } catch {}
    }
    followKeysHandler = (evt) => {
      try {
        if (syncingKeys) return;
        syncAllKeyPositions();
      } catch {}
    };
    cy.on('position', 'node', followKeysHandler);
    syncAllKeyPositions();
  }

  function autoCloseBestKeys(kind) {
    if (!cy) return;
    const pivots = cy.nodes("[group='KeyPivot']");
    if (!pivots || pivots.length === 0) return;
    const byTactic = new Map();
    pivots.forEach(p => {
      const tacticId = String(p.data('keyTacticId') || '');
      if (!tacticId) return;
      const epss = Number(p.data('keyEpss') || 0);
      const cur = byTactic.get(tacticId);
      if (!cur || epss > cur.epss) byTactic.set(tacticId, { pivot: p, epss });
    });
    byTactic.forEach(({ pivot }) => {
      toggleKeyForPivot(pivot, kind);
    });
  }

  function toggleKeyForPivot(pivot, kind) {
    if (!pivot || !pivot.length) return;
    const tacticId = String(pivot.data('keyTacticId') || '');
    if (!tacticId) {
      pivot.data('keyState', pivot.data('keyState') === 'closed' ? 'open' : 'closed');
      syncKeyPositionsForPivot(pivot);
      return;
    }
    const map = (kind === 'primary') ? primaryClosedKeyByTactic : linearClosedKeyByTactic;
    const curState = pivot.data('keyState') === 'closed' ? 'closed' : 'open';
    if (curState === 'closed') {
      pivot.data('keyState', 'open');
      if (map.get(tacticId) === String(pivot.id())) map.delete(tacticId);
      syncKeyPositionsForPivot(pivot);
      return;
    }
    const prevId = map.get(tacticId);
    if (prevId && prevId !== String(pivot.id())) {
      const prev = cy ? cy.getElementById(prevId) : null;
      if (prev && prev.length) {
        prev.data('keyState', 'open');
        syncKeyPositionsForPivot(prev);
      }
    }
    map.set(tacticId, String(pivot.id()));
    pivot.data('keyState', 'closed');
    syncKeyPositionsForPivot(pivot);
  }

  function bindKeyClick(kind) {
    if (!cy) return;
    const handlerNode = (evt) => {
      if (closeAllKeys && closeAllKeys.checked) return;
      const n = evt.target;
      if (!n || !n.length) return;
      const g = n.data('group');
      if (g !== 'KeyContact' && g !== 'KeyPivot') return;
      let pivotId = '';
      if (g === 'KeyPivot') pivotId = String(n.id());
      else pivotId = String(n.data('keyPivotId') || '');
      if (!pivotId) return;
      const pivot = cy.getElementById(pivotId);
      if (!pivot || !pivot.length) return;
      toggleKeyForPivot(pivot, kind);
      try { evt.stopPropagation(); } catch {}
    };
    const handlerEdge = (evt) => {
      if (closeAllKeys && closeAllKeys.checked) return;
      const e = evt.target;
      if (!e || !e.length) return;
      const t = String(e.data('type') || '');
      if (t !== 'SC_KEY_SEG' && t !== 'SC_KEY_SWITCH' && t !== 'SC_KEY_ARROW') return;
      let pivotId = '';
      const src = e.source(); const tgt = e.target();
      if (src && src.length) {
        if (src.data('group') === 'KeyPivot') pivotId = String(src.id());
        else if (src.data('group') === 'KeyContact') pivotId = String(src.data('keyPivotId') || '');
      }
      if (!pivotId && tgt && tgt.length) {
        if (tgt.data('group') === 'KeyPivot') pivotId = String(tgt.id());
        else if (tgt.data('group') === 'KeyContact') pivotId = String(tgt.data('keyPivotId') || '');
      }
      if (!pivotId) return;
      const pivot = cy.getElementById(pivotId);
      if (!pivot || !pivot.length) return;
      toggleKeyForPivot(pivot, kind);
      try { evt.stopPropagation(); } catch {}
    };
    try { cy.off('tap', 'node[group=\"KeyContact\"]', handlerNode); } catch {}
    try { cy.off('tap', 'node[group=\"KeyPivot\"]', handlerNode); } catch {}
    try { cy.off('tap', 'edge', handlerEdge); } catch {}
    cy.on('tap', 'node[group=\"KeyContact\"]', handlerNode);
    cy.on('tap', 'node[group=\"KeyPivot\"]', handlerNode);
    cy.on('tap', 'edge', handlerEdge);
  }

  function initScenarioKeysLinear() {
    if (!cy) return;
    if (getProfile() !== 'mono') return;
    try {
      const edges = cy.edges("[type='SC_STEP']");
      edges.forEach(e => {
        try {
          if (e.data('keyInited')) return;
          const src = String(e.data('source') || e.source().id());
          const tgt = String(e.data('target') || e.target().id());
          const techId = String(e.data('stepTechId') || '');
          const tacticId = String(e.data('stepTactic') || '');
          const srcNode = cy.getElementById(src);
          const tgtNode = cy.getElementById(tgt);
          if (!srcNode.length || !tgtNode.length) { e.data('keyInited', true); return; }
          let keyEpss = 0;
          let keyEpssNorm = 0;
          let predictedEdge = false;
          try {
            const te = cy.edges(`[type = 'SC_TECH_TO_CVE'][source = '${techId}'][target = '${src}']`);
            if (te && te.length > 0) {
              keyEpss = Number(te[0].data('epss') || 0);
              keyEpssNorm = Number(te[0].data('epss_norm') || te[0].data('epss') || 0);
              predictedEdge = !!te[0].data('predictedEdge');
            }
          } catch {}
          if (e && e.data && e.data('predictedEdge')) predictedEdge = true;
          const baseId = String(e.id() || `${src}_${tgt}`);
          const prefix = `k_${baseId}`;
          const leftId = `${prefix}_lc`;
          const rightId = `${prefix}_rc`;
          const pivotId = `${prefix}_pv`;
          if (cy.getElementById(pivotId).length) { e.data('keyInited', true); return; }
          const geom = computeKeyGeometry(srcNode.position(), tgtNode.position(), 'open');
          try {
            cy.add({ group: 'nodes', data: { id: leftId, label: '', group: 'KeyContact', keyPivotId: pivotId, keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyEpssNorm: keyEpssNorm }, position: geom.left, grabbable: false, selectable: false });
            cy.add({ group: 'nodes', data: { id: rightId, label: '', group: 'KeyContact', keyPivotId: pivotId, keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyRight: true, keyEpssNorm: keyEpssNorm }, position: geom.right, grabbable: false, selectable: false });
            cy.add({ group: 'nodes', data: { id: pivotId, label: '', group: 'KeyPivot', keyState: 'open', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyLeftId: leftId, keyRightId: rightId, keyEpss: keyEpss, keyEpssNorm: keyEpssNorm }, position: geom.pivot, grabbable: false, selectable: false });
            const predData = predictedEdge ? { predictedEdge: true } : {};
            cy.add({ group: 'edges', data: { id: `${prefix}_e1`, source: src, target: leftId, type: 'SC_KEY_SEG', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm, ...predData } });
            cy.add({ group: 'edges', data: { id: `${prefix}_e2`, source: leftId, target: pivotId, type: 'SC_KEY_SWITCH', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm, ...predData } });
            cy.add({ group: 'edges', data: { id: `${prefix}_e3`, source: rightId, target: tgt, type: 'SC_KEY_ARROW', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm, ...predData } });
          } catch {}
          try { e.data('keyInited', true); e.style('display', 'none'); } catch {}
        } catch {}
      });
      syncAllKeyPositions();
      autoCloseBestKeys('linear');
    } catch {}
  }

	  function initPrimaryKeysForEdges() {
	    if (!cy) return;
	    if (getProfile() !== 'mono') return;
	    try {
	      const edges = cy.edges("[type='SC_GROUP']");
	      edges.forEach(e => {
	        try {
	          if (e.data('keyInited')) return;
	          const src = String(e.data('source') || e.source().id());
	          const tgt = String(e.data('target') || e.target().id());
	          const techId = String(e.data('stepTechId') || '');
	          const tacticId = String(e.data('stepTactic') || '');
          const srcNode = cy.getElementById(src);
          const tgtNode = cy.getElementById(tgt);
          if (!srcNode.length || !tgtNode.length) { e.data('keyInited', true); return; }
          // В первичном сценарии ключи нужны только для путей от CVE
          if (String(srcNode.data('group')) !== 'CVE') { e.data('keyInited', true); return; }
          let keyEpss = 0;
          let keyEpssNorm = 0;
          let predictedEdge = false;
          try {
            const te = cy.edges(`[type = 'SC_TECH_TO_CVE'][source = '${techId}'][target = '${src}']`);
            if (te && te.length > 0) {
                keyEpss = Number(te[0].data('epss') || 0);
                keyEpssNorm = Number(te[0].data('epss_norm') || te[0].data('epss') || 0);
                predictedEdge = !!te[0].data('predictedEdge');
              }
          } catch {}
          if (e && e.data && e.data('predictedEdge')) predictedEdge = true;
          const baseId = String(e.id() || `${src}_${tgt}`);
          const prefix = `k_${baseId}`;
          const leftId = `${prefix}_lc`;
          const rightId = `${prefix}_rc`;
          const pivotId = `${prefix}_pv`;
          if (cy.getElementById(pivotId).length) { e.data('keyInited', true); return; }
          const geom = computeKeyGeometry(srcNode.position(), tgtNode.position(), 'open');
          try {
            const predData = predictedEdge ? { predictedEdge: true } : {};
            cy.add({ group: 'nodes', data: { id: leftId, label: '', group: 'KeyContact', keyPivotId: pivotId, keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyEpssNorm: keyEpssNorm }, position: geom.left, grabbable: false, selectable: false });
            cy.add({ group: 'nodes', data: { id: rightId, label: '', group: 'KeyContact', keyPivotId: pivotId, keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyRight: true, keyEpssNorm: keyEpssNorm }, position: geom.right, grabbable: false, selectable: false });
            cy.add({ group: 'nodes', data: { id: pivotId, label: '', group: 'KeyPivot', keyState: 'open', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyTargetId: tgt, keyLeftId: leftId, keyRightId: rightId, keyEpss: keyEpss, keyEpssNorm: keyEpssNorm }, position: geom.pivot, grabbable: false, selectable: false });
            cy.add({ group: 'edges', data: { id: `${prefix}_e1`, source: src, target: leftId, type: 'SC_KEY_SEG', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm, ...predData } });
            cy.add({ group: 'edges', data: { id: `${prefix}_e2`, source: leftId, target: pivotId, type: 'SC_KEY_SWITCH', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm } });
            cy.add({ group: 'edges', data: { id: `${prefix}_e3`, source: rightId, target: tgt, type: 'SC_KEY_ARROW', keyTechId: techId, keyTacticId: tacticId, keyCveNodeId: src, keyEpssNorm: keyEpssNorm, ...predData } });
          } catch {}
	          try { e.data('keyInited', true); } catch {}
	        } catch {}
	      });
	      syncAllKeyPositions();
	      autoCloseBestKeys('primary');
	    } catch {}
	  }

  function rerenderAccordingToProfile() {
    if (isScenarioView) {
      if (currentScenarioId === 'PRIMARY') {
        if (lastMega) renderPrimaryOnCanvas(lastMega);
      } else if (currentScenarioData) {
        renderScenario(currentScenarioData);
      }
    } else {
      if (!restoreSnapshotFromLS()) restoreSnapshotIfAny();
    }
  }

  // Работа с темой
  function loadTheme() {
    try { const raw = localStorage.getItem(LS_THEME); if (!raw) return null; const t = JSON.parse(raw); if (t && typeof t === 'object') return t; } catch {}
    return null;
  }
  function saveTheme(theme) {
    try {
      if (theme && (theme.nodeColors || theme.canvas || theme.labels)) localStorage.setItem(LS_THEME, JSON.stringify(theme));
      else localStorage.removeItem(LS_THEME);
    } catch {}
  }
  function applyTheme(theme, opts={ save:false }) {
    // В ч/б профиле пользовательские цвета не применяются
    if (getProfile() === 'mono') {
      if (opts.save) saveTheme(theme);
      return;
    }
    // Фон холста
    if (container) {
      if (theme && theme.canvas) container.style.background = theme.canvas; else container.style.background = '';
    }
    if (cy) {
      const nodes = cy.nodes();
      // Цвет надписей
      const labelColor = theme && theme.labels ? String(theme.labels) : null;
      if (labelColor) {
        nodes.forEach(n => { n.style('color', labelColor); });
      } else {
        nodes.forEach(n => { n.removeStyle('color'); });
      }
      // Цвета узлов по группам
      const colors = (theme && theme.nodeColors) || {};
      nodes.forEach(n => {
        const g = n.data('group');
        if (g === 'TechLabel') return;
        const val = colors[g] || (g === 'Target' ? colors.CPE : null);
        if (val) n.style('background-color', val);
        else n.removeStyle('background-color');
      });

      // Цвет рёбер синхронизируем с цветом соответствующих узлов
      try {
        const edges = cy.edges();
        edges.forEach(e => {
          const t = e.data('type');
          const c = edgeColorFromTheme(t, theme);
          if (c) e.style('line-color', c);
          // стрелки меняем только для групповых связей сценариев (остальные без стрелок)
          if (t === 'SC_GROUP' || t === 'SC_GROUP_LINK') {
            e.style('target-arrow-color', t === 'SC_GROUP_LINK' ? '#7f8c8d' : c);
          }
        });
      } catch {}
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
      const theme = { canvas: themeCanvasInput?.value, labels: themeLabelInput?.value, nodeColors };
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
      const theme = { canvas: themeCanvasInput?.value, labels: themeLabelInput?.value, nodeColors };
      applyTheme(theme, { save:false });
    };
    if (themeCanvasInput) themeCanvasInput.addEventListener('input', preview);
    if (themeLabelInput) themeLabelInput.addEventListener('input', preview);
    Object.values(themeNodeInputs).forEach(inp => { if (inp) inp.addEventListener('input', preview); });
  }

  // Экспорт графа (PNG/SVG/JSON)
  function openExportModal() {
    try { if (exportBackdrop) { exportBackdrop.removeAttribute('hidden'); exportBackdrop.classList.add('open'); } } catch {}
  }
  function closeExportModal() {
    try { if (exportBackdrop) { exportBackdrop.classList.remove('open'); exportBackdrop.setAttribute('hidden',''); } } catch {}
  }
  function tryRegisterSvgPlugin() {
    try {
      // Некоторые сборки требуют явной регистрации
      if (window.cytoscape && window.cytoscapeSvg && !window.__cySvgRegistered) {
        try { window.cytoscape.use(window.cytoscapeSvg); window.__cySvgRegistered = true; } catch {}
      }
    } catch {}
  }
  function getGraphBgColor() {
    try {
      if (!container) return '#fff';
      const cs = getComputedStyle(container);
      const bg = cs && (cs.backgroundColor || cs.background);
      if (!bg || bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent') return '#fff';
      return bg;
    } catch { return '#fff'; }
  }
  function inferPrefix() {
    try {
      if (isScenarioView) return (currentScenarioId === 'PRIMARY') ? 'primary' : 'linear';
      const val = String(cpeInput && cpeInput.value || '').trim().toLowerCase();
      if (val.startsWith('custom:')) return 'target';
      return 'cpe';
    } catch { return 'cpe'; }
  }
  function parseCpeParts(rawCpe) {
    let vendor = 'unknown', product = 'unknown', version = 'unknown';
    try {
      const s = String(rawCpe || '').trim();
      if (s.toLowerCase().startsWith('custom:')) {
        const name = s.replace(/^custom:/i, '').trim();
        vendor = 'custom';
        product = name || product;
        version = 'none';
      } else {
        const parts = s.split(':');
        if (parts.length >= 6 && parts[0] === 'cpe' && parts[1] === '2.3') {
          vendor = parts[3] || vendor;
          product = parts[4] || product;
          version = parts[5] || version;
        }
      }
    } catch {}
    const norm = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

    const mapVersion = (v) => (v === '*' ? 'any' : (v === '-' ? 'none' : v));
    return { vendor: norm(vendor), product: norm(product), version: norm(mapVersion(version)) };
  }
  function nowTimestampStr() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const dd = pad(d.getDate());
    const mm = pad(d.getMonth() + 1);
    const yyyy = d.getFullYear();
    const hh = pad(d.getHours());
    const mi = pad(d.getMinutes());
    const ss = pad(d.getSeconds());
    return `${dd}${mm}${yyyy}_${hh}${mi}${ss}`;
  }
  function downloadDataUrl(dataUrl, filename) {
    try {
      const a = document.createElement('a');
      a.href = dataUrl; a.download = filename; a.rel = 'noopener'; a.style.display = 'none';
      document.body.appendChild(a); a.click(); a.remove();
    } catch {}
  }
  function downloadBlob(blob, filename) {
    try {
      const url = URL.createObjectURL(blob);
      downloadDataUrl(url, filename);
      setTimeout(() => { try { URL.revokeObjectURL(url); } catch {} }, 1000);
    } catch {}
  }
  function addSvgBackground(svgStr, color) {
    try {
      if (!color) return svgStr;
      const p = new DOMParser();
      const doc = p.parseFromString(svgStr, 'image/svg+xml');
      const svg = doc.documentElement;
      if (!svg || svg.nodeName.toLowerCase() !== 'svg') return svgStr;
      const rect = doc.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', '0'); rect.setAttribute('y', '0');
      rect.setAttribute('width', '100%'); rect.setAttribute('height', '100%');
      rect.setAttribute('fill', color);
      svg.insertBefore(rect, svg.firstChild);
      const ser = new XMLSerializer();
      return ser.serializeToString(doc);
    } catch { return svgStr; }
  }
  function buildExportFileName(ext) {
    const prefix = inferPrefix();
    const { vendor, product, version } = parseCpeParts(cpeInput && cpeInput.value);
    const ts = nowTimestampStr();
    return `${prefix}_${vendor}_${product}_${version}_${ts}.${ext}`;
  }
  function buildLandscapeFileName() {
    const norm = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    const { vendor, product, version } = parseCpeParts(cpeInput && cpeInput.value);
    const prefix = inferPrefix();
    let base = `${prefix}_${vendor}_${product}_${version}`;
    base = base.replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    if (!base) base = 'landscape';
    return `${base}_landscape.png`;
  }
  function handleExportPng() {
    if (!cy) { alert('Граф ещё не построен'); return; }
    const transparent = !!(exportTransparent && exportTransparent.checked);
    const opts = { full: false, scale: EXPORT_SCALE };
    if (!transparent) {
      const bg = getGraphBgColor();
      if (bg) opts.bg = bg;
    }
    let dataUrl;
    try { dataUrl = cy.png(opts); } catch (e) { alert('Не удалось экспортировать PNG: ' + e); return; }
    const name = buildExportFileName('png');
    downloadDataUrl(dataUrl, name);
  }
  function handleExportSvg() {
    if (!cy) { alert('Граф ещё не построен'); return; }
    tryRegisterSvgPlugin();
    if (typeof cy.svg !== 'function') { alert('SVG экспорт недоступен: плагин не подключён'); return; }
    let svgStr;
    try { svgStr = cy.svg({ full: false, scale: EXPORT_SCALE }); } catch (e) { alert('Не удалось экспортировать SVG: ' + e); return; }
    const transparent = !!(exportTransparent && exportTransparent.checked);
    if (!transparent) {
      const bg = getGraphBgColor() || '#fff';
      svgStr = addSvgBackground(svgStr, bg);
    }
    const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
    const name = buildExportFileName('svg');
    downloadBlob(blob, name);
  }
  async function handleExportJson() {
    try {
      const cpe = (cpeInput && cpeInput.value || '').trim();
      if (!cpe) { alert('Сначала укажите URI объекта и постройте граф'); return; }
      const mode = (scModeSel && scModeSel.value) || 'strict';
      let maxPer = 3;
      try { maxPer = Math.max(1, Math.min(10, parseInt(scMaxPerTacticInput.value || '3'))); } catch {}
      const qs = new URLSearchParams({ cpe, mode, max_per_tactic: String(maxPer) });
      const resp = await fetch(`/api/export?${qs.toString()}`);
      if (!resp.ok) {
        let err = `${resp.status} ${resp.statusText}`;
        try { const data = await resp.json(); if (data && data.error) err += ` — ${data.error}`; } catch {}
        alert(`Ошибка экспорта: ${err}`);
        return;
      }
      // Пытаемся получить имя файла из заголовка Content-Disposition
      let fname = 'export.json';
      try {
        const cd = resp.headers.get('Content-Disposition') || resp.headers.get('content-disposition') || '';
        const m = cd.match(/filename\s*=\s*"?([^";]+)"?/i);
        if (m && m[1]) fname = m[1];
      } catch {}
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fname;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      if (exportBackdrop) closeExportModal();
    } catch (e) {
      alert(`Ошибка экспорта: ${e}`);
    }
  }
  function bindExportUI() {
    if (exportBtn && exportBackdrop) exportBtn.addEventListener('click', openExportModal);
    if (exportCloseBtn) exportCloseBtn.addEventListener('click', closeExportModal);
    if (exportBackdrop) exportBackdrop.addEventListener('click', (e) => { if (e.target === exportBackdrop) closeExportModal(); });
    if (exportPngBtn) exportPngBtn.addEventListener('click', handleExportPng);
    if (exportSvgBtn) exportSvgBtn.addEventListener('click', handleExportSvg);
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', handleExportJson);
    tryRegisterSvgPlugin();
  }

  // Подсказка при наведении на узел
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
      if (group === 'Target') return props.name || props.targetUri || ele.data('label') || '';
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

  // Привязка подписей TechLabel к позициям техник
  let followTechLabelsHandler = null;
  function syncTechLabels() {
    if (!cy) return;
    const labels = cy.nodes('[group="TechLabel"]');
    if (!labels || labels.length === 0) return;
    labels.forEach(lbl => {
      const id = String(lbl.id() || '');
      const tid = id.startsWith('tl_') ? id.slice(3) : null;
      if (!tid) return;
      const tnode = cy.getElementById(tid);
      if (!tnode || tnode.length === 0) return;
      const tpos = tnode.position();
      let dx = lbl.data('dx'); let dy = lbl.data('dy');
      if (typeof dx !== 'number' || typeof dy !== 'number') {
        // Первичная инициализация смещений по текущим позициям
        const lpos = lbl.position();
        dx = lpos.x - tpos.x; dy = lpos.y - tpos.y;
        lbl.data('dx', dx); lbl.data('dy', dy);
      }
      lbl.position({ x: tpos.x + dx, y: tpos.y + dy });
    });
  }
  function bindTechLabelFollow() {
    if (!cy) return;
    // Снимем прежнюю привязку, если была
    if (followTechLabelsHandler) {
      try { cy.off('position', 'node[group="Technique"]', followTechLabelsHandler); } catch {}
    }
    followTechLabelsHandler = (evt) => {
      const n = evt.target; const tid = String(n.id());
      const lbl = cy.getElementById('tl_' + tid);
      if (!lbl || lbl.length === 0) return;
      let dx = lbl.data('dx'); let dy = lbl.data('dy');
      if (typeof dx !== 'number' || typeof dy !== 'number') { dx = 0; dy = -30; }
      const p = n.position();
      lbl.position({ x: p.x + dx, y: p.y + dy });
    };
    cy.on('position', 'node[group="Technique"]', followTechLabelsHandler);
    // Начальная синхронизация
    syncTechLabels();
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
        if (typeof d.mode === 'string') {
          const acceptable = new Set(['full', 'full_relaxed', 'full_gnn', 'simple']);
          modeSel.value = acceptable.has(d.mode) ? d.mode : 'full';
        }
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

  // Оверлей загрузки на холсте графа
  function ensureLoadingOverlay() {
    if (!container) return null;
    let overlay = container.querySelector('.graph-loading');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'graph-loading';
      overlay.textContent = 'Загрузка...';
      container.appendChild(overlay);
    }
    return overlay;
  }
  function showLoading() {
    try {
      const ov = ensureLoadingOverlay();
      if (container) container.classList.add('is-loading');
      if (drawBtn) drawBtn.disabled = true;
      // Также помечаем «занято» для доступности
      if (container) container.setAttribute('aria-busy', 'true');
    } catch {}
  }
  function hideLoading() {
    try {
      if (container) container.classList.remove('is-loading');
      if (drawBtn) drawBtn.disabled = false;
      if (container) container.removeAttribute('aria-busy');
    } catch {}
  }
  
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
        if (scModeSel && typeof d.mode === 'string') {
          const mode = String(d.mode);
          if (mode === 'relaxed' || mode === 'gnn' || mode === 'strict') scModeSel.value = mode;
          else scModeSel.value = 'strict';
        }
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
    if (showAllCves) showAllCves.disabled = false;
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
      const lblColor = labelColorFromCss();
      cy = cytoscape({
        container,
        elements,
        style: graphStyleForProfile(getProfile()),
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
      bindTechLabelFollow();
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
      const lblColor = labelColorFromCss();
      cy = cytoscape({
        container,
        elements,
        style: graphStyleForProfile(getProfile()),
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
      bindTechLabelFollow();
      const th2 = loadTheme(); if (th2) applyTheme(th2);
      isScenarioView = false;
      return true;
    } catch (e) { console.warn('restoreSnapshotFromLS', e); return false; }
  }

  function colorByGroup(group) {
    switch (group) {
      case 'CPE': return '#8e44ad';
      case 'Target': return '#8e44ad';
      case 'CVE': return '#e74c3c';
      case 'CWE': return '#e49659';
      case 'CAPEC': return '#3498db';
      case 'Technique': return '#4fca21';
      default: return '#95a5a6';
    }
  }

  // Возвращает цвет узла с учётом пользовательской темы (если задана)
  function resolvedNodeColor(group, theme) {
    try {
      const t = theme || loadTheme() || {};
      const colors = (t.nodeColors || {});
      const nc = colors[group] || (group === 'Target' ? colors.CPE : null);
      return nc || colorByGroup(group);
    } catch { return colorByGroup(group); }
  }

  // Цвет ребра на основе требуемой «ведущей» стороны
  function edgeColorFromTheme(type, theme) {
    switch (type) {
      // Граф CPE
      case 'AFFECTS':
        return resolvedNodeColor('CVE', theme);
      case 'CWE_TO_CVE':
        return resolvedNodeColor('CVE', theme);
      case 'CAPEC_TO_CWE':
        return resolvedNodeColor('CAPEC', theme);
      case 'CAPEC_PARENT_TO_CAPEC_CHILD': // CAPEC -> CAPEC
        return resolvedNodeColor('CAPEC', theme);
      case 'CAPEC_TO_TECHNIQUE': 
        return resolvedNodeColor('Technique', theme);
      case 'CAPEC_TO_TECHNIQUE_PRED':
        return resolvedNodeColor('Technique', theme);
      // Сценарии оставляем фиксированными цветами
      case 'SC_STEP': return '#8e44ad';
      case 'SC_TECH_TO_CVE': return '#8e44ad';
      case 'SC_GROUP': return '#8e44ad';
      default: return '#7f8c8d';
    }
  }

  function edgeColor(type) {
    // Используем сохранённую тему для соответствия цвету узла
    const th = loadTheme();
    return edgeColorFromTheme(type, th);
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
        addInspectorRow(rows, k, props[k], group);
      }
      // Остальные поля (если есть)
      for (const k of Object.keys(props)) {
        if (order.includes(k) || k === 'external_link') continue;
        addInspectorRow(rows, k, props[k], group);
        if (rows.length > 30) break;
      }
      addInspectorRow(rows, 'label', label, group);
      appendExternalLink(rows, props, group);
      inspector.innerHTML = rows.join('');
      return;
    }

    // Специальный порядок для узлов CVE: identifier, затем основные метрики (C/A/I, EPSS, ущерб/риск)
    if (group === 'CVE') {
      const priority = [
        'identifier', 'cvss',
        'cvss_C_score', 'cvss_I_score', 'cvss_A_score', 'epss', 'epss_norm',
        'damage', 'risk',
        'damage_C', 'damage_I', 'damage_A',
        'risk_C', 'risk_I', 'risk_A',
      ];
      const skip = new Set([
        'cvss_epss_ratio', 'cvss_epss_max_ratio',
        'cvss_C_epss_ratio', 'cvss_I_epss_ratio', 'cvss_A_epss_ratio',
        'cvss_C_epss_max_ratio', 'cvss_I_epss_max_ratio', 'cvss_A_epss_max_ratio',
        'external_link',
      ]);
      const seen = new Set();
      for (const k of priority) {
        if (!(k in props) || skip.has(k)) continue;
        addInspectorRow(rows, k, props[k], group);
        seen.add(k);
      }
      for (const k of Object.keys(props)) {
        if (seen.has(k) || skip.has(k)) continue;
        addInspectorRow(rows, k, props[k], group);
        if (rows.length > 30) break;
      }
      addInspectorRow(rows, 'label', label, group);
      appendExternalLink(rows, props, group);
      inspector.innerHTML = rows.join('');
      return;
    }

    // Поведение по умолчанию для других групп: свойства как есть и label в конце
    for (const k of Object.keys(props)) {
      if (k === 'external_link') continue;
      addInspectorRow(rows, k, props[k], group);
      if (rows.length > 30) break;
    }
    addInspectorRow(rows, 'label', label, group);
    appendExternalLink(rows, props, group);
    inspector.innerHTML = rows.join('');
  }

  // Нормализует список искомых элементов: допускаются строки и объекты { id, techId }
  function normalizeWantedIds(list) {
    const out = [];
    (list || []).forEach(v => {
      if (v == null) return;
      if (typeof v === 'object') {
        const id = v.id != null ? String(v.id) : '';
        if (!id) return;
        const techId = v.techId != null ? String(v.techId) : '';
        out.push(techId ? { id, techId } : { id });
      } else {
        const id = String(v);
        if (id) out.push({ id });
      }
    });
    return out;
  }

  // Находит узлы по id, а также по сырым идентификаторам (raw.id, raw.props.identifier)
  // Если указан techId, пытаемся сопоставить только узлы, привязанные к конкретной технике (моно-сценарий).
  function resolveNodesByIds(ids, group) {
    if (!cy || !Array.isArray(ids) || ids.length === 0) return cy ? cy.collection() : null;
    const wanted = normalizeWantedIds(ids);
    if (wanted.length === 0) return cy.collection();
    const isConnectedToTech = (node, techId) => {
      if (!techId || !node || !node.connectedEdges) return false;
      try {
        let ok = false;
        node.connectedEdges().forEach(e => {
          if (ok) return;
          const s = String(e.data('source') || (e.source && e.source().id && e.source().id()) || '');
          const t = String(e.data('target') || (e.target && e.target().id && e.target().id()) || '');
          if (s === techId || t === techId) ok = true;
        });
        return ok;
      } catch { return false; }
    };
    try {
      const pool = group ? cy.nodes(`[group='${group}']`) : cy.nodes();
      return pool.filter(n => {
        const nid = String(n.id());
        const nTech = n.data('techId') != null ? String(n.data('techId')) : '';
        for (const w of wanted) {
          const wid = w.id;
          const wtech = w.techId || '';
          if (wtech && nTech && wtech !== nTech) continue;
          let matches = false;
          if (nid === wid) matches = true;
          const raw = n.data('raw') || {};
          const rawId = raw.id != null ? String(raw.id) : '';
          if (!matches && rawId && rawId === wid) matches = true;
          const ident = (raw.props && raw.props.identifier != null) ? String(raw.props.identifier) : '';
          if (!matches && ident && ident === wid) matches = true;
          if (!matches) continue;
          if (wtech) {
            if (nTech && nTech === wtech) return true;
            if (isConnectedToTech(n, wtech)) return true;
            continue;
          }
          return true;
        }
        return false;
      });
    } catch {
      return (cy && cy.collection) ? cy.collection() : null;
    }
  }

  function highlightNodesByIds(ids) {
    if (!cy || !Array.isArray(ids) || ids.length === 0) return;
    cy.elements().removeClass('sel neigh');
    const nodes = resolveNodesByIds(ids);
    if (!nodes || nodes.length === 0) return;
    nodes.addClass('sel');
    nodes.closedNeighborhood().difference(nodes).addClass('neigh');
    // Не сохраняем подсветку в снимок; не перетираем снимок, когда отображается сценарий
    if (!isScenarioView) trySaveSnapshot();
  }

  function applyKeySelectionForCves(cveIds) {
    if (!cy || !isScenarioView) return;
    if (closeAllKeys && closeAllKeys.checked) return;
    if (getProfile() !== 'mono') return;
    const pivots = cy.nodes("[group='KeyPivot']");
    if (!pivots || pivots.length === 0) return;
    const kind = (currentScenarioId === 'PRIMARY') ? 'primary' : 'linear';
    const resolvedCves = resolveNodesByIds(cveIds, 'CVE');
    const wanted = normalizeWantedIds(cveIds);
    const idsForKeys = [];
    if (resolvedCves && resolvedCves.length) {
      resolvedCves.forEach(n => idsForKeys.push(String(n.id())));
    }
    if (!idsForKeys.length) {
      wanted.forEach(w => { if (w.id) idsForKeys.push(String(w.id)); });
    }
    const cveSet = new Set(idsForKeys);
    // Открываем все, затем замыкаем нужные
    pivots.forEach(p => { p.data('keyState', 'open'); });
    const best = new Map(); // tactic -> {pivot, epss}
    pivots.forEach(p => {
      const cid = String(p.data('keyCveNodeId') || '');
      const tac = String(p.data('keyTacticId') || '');
      if (!cid || !tac) return;
      if (!cveSet.has(cid)) return;
      const epss = Number(p.data('keyEpss') || 0);
      const cur = best.get(tac);
      if (!cur || epss > cur.epss) best.set(tac, { pivot: p, epss });
    });
    const map = (kind === 'primary') ? primaryClosedKeyByTactic : linearClosedKeyByTactic;
    map.clear();
    best.forEach((val, tac) => {
      const p = val.pivot;
      p.data('keyState', 'closed');
      map.set(tac, String(p.id()));
      syncKeyPositionsForPivot(p);
    });
    syncAllKeyPositions();
  }

  async function generateScenarios() {
    const cpe = (cpeInput.value || '').trim();
    if (!cpe) { alert('Сначала укажите URI объекта и постройте граф'); return; }
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
      syncLandscapeData(data && data.mega);
      renderPrimaryCard(data);
    } else {
      // По умолчанию для линейного режима — галочка включена
      try { if (showAllCves) showAllCves.checked = true; } catch {}
      syncLandscapeData(data && data.mega);
      renderScenarios(data);
    }
  }

  function renderScenarios(data) {
    if (!data || !Array.isArray(data.scenarios)) { scenariosList.innerHTML = '<div class="muted">Нет данных</div>'; return; }
    const frag = document.createDocumentFragment();
    const meta = document.createElement('div');
    meta.className = 'sc-meta';
    let modeName = 'строгий';
    if (data.mode === 'relaxed') modeName = 'нестрогий';
    else if (data.mode === 'gnn') modeName = 'GNN (строгий)';
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
      title.textContent = `Риск сценария ${sc.id}: ${Number(sc.score || 0).toFixed(5)}`;
      const act = document.createElement('div');
      act.className = 'scenario-actions';
      const btn = document.createElement('button');
      btn.textContent = 'Подсветить на графе';
      btn.addEventListener('click', () => {
        const ids = [];
        const cveIds = [];
        for (const step of sc.steps || []) {
          const t = step.technique;
          const tid = t && t.id ? String(t.id) : '';
          if (tid) ids.push({ id: tid });
          for (const c of (step.cves || [])) {
            if (c && c.id) {
              const cid = String(c.id);
              const payload = tid ? { id: cid, techId: tid } : { id: cid };
              ids.push(payload);
              cveIds.push(payload);
            }
          }
          for (const w of (step.cwes || [])) { if (w && w.id) ids.push({ id: String(w.id) }); }
          for (const cp of (step.capecs || [])) { if (cp && cp.id) ids.push({ id: String(cp.id) }); }
        }
        highlightNodesByIds(ids);
        applyKeySelectionForCves(cveIds);
      });
      act.appendChild(btn);
      const btnShow = document.createElement('button');
      btnShow.textContent = 'Отобразить';

      // Вспомогательные функции для унификации состояния кнопок
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
          currentScenarioData = sc;
        } else {
          if (currentScenarioId === sc.id) {
            // Выходим из сценария
            const ok = restoreSnapshotFromLS();
            if (ok) {
              resetAllShowBtns();
              isScenarioView = false;
              currentScenarioId = null;
              currentScenarioData = null;
            }
          } else {
            // Переключаемся на другой сценарий без возврата к графу
            renderScenario(sc);
            resetAllShowBtns();
            setShowBtn(btnShow, true);
            currentScenarioId = sc.id;
            currentScenarioData = sc;
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
        const tacticLabelRu = translateTacticName(st.tactic || '?');
        left.textContent = `${idx+1}. [${tacticLabelRu || '?'}] ${tprops.identifier || ''} ${tprops.name ? '— ' + tprops.name : ''}`;
        const right = document.createElement('div');
        right.className = 'step-cves';
        (st.cves || []).forEach(cv => {
          const chip = document.createElement('span');
          chip.className = 'chip';
          chip.textContent = (cv.props && cv.props.identifier) || '';
          chip.title = (cv.props && cv.props.description) || '';
          chip.addEventListener('click', (e) => {
            e.stopPropagation();
            if (cv && cv.id) {
              const tid = st && st.technique && st.technique.id ? String(st.technique.id) : '';
              const payload = tid ? { id: String(cv.id), techId: tid } : { id: String(cv.id) };
              highlightNodesByIds([payload]);
              applyKeySelectionForCves([payload]);
            }
          });
          right.appendChild(chip);
        });
        row.appendChild(left); row.appendChild(right);
      row.addEventListener('click', () => {
        const ids = [];
        const cveIds = [];
        const t = st.technique;
        const tid = t && t.id ? String(t.id) : '';
        if (tid) ids.push({ id: tid });
        for (const c of (st.cves || [])) {
          if (c && c.id) {
            const cid = String(c.id);
            const payload = tid ? { id: cid, techId: tid } : { id: cid };
            ids.push(payload);
            cveIds.push(payload);
          }
        }
        for (const w of (st.cwes || [])) { if (w && w.id) ids.push({ id: String(w.id) }); }
        for (const cp of (st.capecs || [])) { if (cp && cp.id) ids.push({ id: String(cp.id) }); }
        highlightNodesByIds(ids);
        applyKeySelectionForCves(cveIds);
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
    const profile = getProfile();
    const elements = (profile === 'mono') ? buildScenarioElementsMono(sc) : buildScenarioElements(sc);
    if (cy) { cy.destroy(); cy = null; }
    const lblColor = labelColorFromCss();
    cy = cytoscape({
      container,
      elements,
      style: scenarioStyleForProfile(profile),
      layout: { name: 'preset', fit: true, padding: 20 }
    });
    if (profile === 'mono') {
      linearClosedKeyByTactic = new Map();
      initScenarioKeysLinear();
      bindKeyFollow();
      bindKeyClick('linear');
    }
    cy.on('tap', 'node', (evt) => {
      const ele = evt.target;
      const g = ele.data('group');
      if (g === 'KeyContact' || g === 'KeyPivot') return;
      cy.elements().removeClass('sel neigh');
      ele.addClass('sel');
      ele.closedNeighborhood().difference(ele).addClass('neigh');
      renderInspector(ele);
      // В линейном сценарии при выключенном чекбоксе — показывать CVE только для выбранной техники
      try {
        const grp = ele.data('group');
        if (grp === 'Technique' && showAllCves && !showAllCves.checked) {
          const tid = String(ele.id());
          showLinearCvesForTechnique(tid);
        }
      } catch {}
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        cy.elements().removeClass('sel neigh');
        renderInspector(null);
        // В линейном сценарии при выключенном чекбоксе — скрыть показанные CVE
        try {
          if (isScenarioView && currentScenarioId && currentScenarioId !== 'PRIMARY' && showAllCves && !showAllCves.checked) {
            setLinearCVEsVisible(false);
          }
        } catch {}
      }
    });
    bindTooltipEvents();
    bindTechLabelFollow();
    // Применяем видимость CVE согласно чекбоксу для линейного режима
    try { setLinearCVEsVisible(!!(showAllCves && showAllCves.checked)); } catch {}
    // В режиме сценария снимок не сохраняем, чтобы не перетирать исходный граф в LS
    const th3 = loadTheme(); if (th3) applyTheme(th3);
  }

  // Управление видимостью всех CVE в линейном сценарии
  function setLinearCVEsVisible(flag) {
    if (!cy) return;
    try { cy.nodes("[group='CVE']").style('display', flag ? 'element' : 'none'); } catch {}
    try { cy.edges("[type='SC_TECH_TO_CVE']").style('display', flag ? 'element' : 'none'); } catch {}
    try { cy.edges("[type='SC_STEP']").style('display', flag ? 'element' : 'none'); } catch {}
    try {
      const profile = getProfile();
      if (profile === 'mono') {
        cy.nodes("[group='KeyContact']").style('display', flag ? 'element' : 'none');
        cy.nodes("[group='KeyPivot']").style('display', flag ? 'element' : 'none');
        cy.edges("[type='SC_KEY_SEG']").style('display', flag ? 'element' : 'none');
        cy.edges("[type='SC_KEY_SWITCH']").style('display', flag ? 'element' : 'none');
        cy.edges("[type='SC_KEY_ARROW']").style('display', flag ? 'element' : 'none');

        // Прямые стрелки между техниками и служебными узлами
        const links = cy.edges("[type='SC_GROUP_LINK']");
        links.style('display', flag ? 'none' : 'element');

        // Стрелка от Н до первой техники должна быть видна всегда
        try { cy.edges("[type='SC_GROUP_LINK'][source='sc_start']").style('display', 'element'); } catch {}

        // Стрелка от последнего шага до К:
        // - при скрытых CVE (flag=false) всегда показываем прямую стрелку;
        // - при показанных CVE прячем её только если есть ключевые стрелки к К.
        try {
          const endLink = cy.edges("[type='SC_GROUP_LINK'][target='sc_end']");
          if (endLink && endLink.length) {
            if (!flag) {
              endLink.style('display', 'element');
            } else {
              let hasKeyToEnd = false;
              try {
                const keyToEnd = cy.edges("[type='SC_KEY_ARROW'][target='sc_end']");
                hasKeyToEnd = keyToEnd && keyToEnd.length > 0;
              } catch {}
              endLink.style('display', hasKeyToEnd ? 'none' : 'element');
            }
          }
        } catch {}
      } else {
        cy.edges("[type='SC_GROUP_LINK']").style('display', 'element');
      }
    } catch {}
  }

  // Показать CVE только для выбранной техники (линейный режим при выключенном чекбоксе)
  function showLinearCvesForTechnique(tid) {
    if (!cy) return;
    try {
      // Сначала скрываем все CVE и связи
      setLinearCVEsVisible(false);
      // Прямые стрелки между техниками в цветном профиле оставляем видимыми всегда
      // В чб профиле скрываем стрелку только для выбранной техники
      const profile = getProfile();
      let nextTid = null;
      try {
        const gl = cy.edges(`[type = 'SC_GROUP_LINK'][source = '${tid}']`);
        if (gl && gl.length > 0) {
          nextTid = String(gl[0].data('target'));
          if (profile === 'mono') { gl.style('display','none'); }
        }
      } catch {}
      // Покажем связи техника->CVE для данной техники
      const tEdges = cy.edges(`[type = 'SC_TECH_TO_CVE'][source = '${tid}']`);
      tEdges.style('display', 'element');
      if (profile === 'mono') {
        const contacts = cy.nodes("[group='KeyContact']");
        const pivots = cy.nodes("[group='KeyPivot']");
        const keyEdges = cy.edges().filter(e => {
          const tp = String(e.data('type') || '');
          return tp === 'SC_KEY_SEG' || tp === 'SC_KEY_SWITCH' || tp === 'SC_KEY_ARROW';
        });
        tEdges.forEach(e => {
          try {
            const cid = String(e.data('target'));
            const cvNode = cy.getElementById(cid);
            if (cvNode && cvNode.length) cvNode.style('display', 'element');
            contacts.forEach(n => {
              const kt = String(n.data('keyTechId') || '');
              const kc = String(n.data('keyCveNodeId') || '');
              if (kt === String(tid) && kc === cid) n.style('display', 'element');
            });
            pivots.forEach(n => {
              const kt = String(n.data('keyTechId') || '');
              const kc = String(n.data('keyCveNodeId') || '');
              if (kt === String(tid) && kc === cid) n.style('display', 'element');
            });
            keyEdges.forEach(ed => {
              const kt = String(ed.data('keyTechId') || '');
              const kc = String(ed.data('keyCveNodeId') || '');
              if (kt === String(tid) && kc === cid) ed.style('display', 'element');
            });
          } catch {}
        });
        syncAllKeyPositions();
        return;
      }
      // Для каждой связи делаем видимым целевой CVE и его переход к следующей технике
      tEdges.forEach(e => {
        try {
          const cid = e.data('target');
          const cvNode = cy.getElementById(cid);
          if (cvNode && cvNode.length) cvNode.style('display', 'element');
          // В профиль «color» не рисуем переход CVE -> следующая техника,
          // чтобы CVE не соединялся визуально с несколькими техниками.
          // В профиль «mono» сохраняем прежнюю логику и показываем стрелку только к nextTid.
          if (profile === 'mono' && nextTid) {
            try { cy.edges(`[type = 'SC_STEP'][source = '${cid}'][target = '${nextTid}']`).style('display', 'element'); } catch {}
          }
        } catch {}
      });
    } catch {}
  }

  function buildScenarioElements(sc) {
    const GAP_X = 100;
    const TECH_Y = 80;
    const TECH_LABEL_Y = TECH_Y - 30;
    const CVE_START_Y = 220;
    const CVE_GAP_Y = 46;
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
      elements.push({ data: { id: tid, label: 'T', group: 'Technique', raw: t }, position: { x, y: TECH_Y } });
      // Надпись над техникой с её идентификатором (для обоих профилей)
      const tIdLabel = (t.props && t.props.identifier) ? String(t.props.identifier) : '';
      if (tIdLabel) {
        const lid = `tl_${tid}`;
        elements.push({ data: { id: lid, label: tIdLabel, group: 'TechLabel' }, position: { x, y: TECH_LABEL_Y } });
      }
      // Цветной профиль: добавим тонкую «дорогу» между соседними техниками
      if (i < steps.length - 1) {
        const nextT = steps[i+1].technique;
        if (nextT && nextT.id) {
          const nextTid = String(nextT.id);
          const eid = `sc_tt_${tid}_${nextTid}`;
          elements.push({ data: { id: eid, source: tid, target: nextTid, type: 'SC_GROUP_LINK' } });
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

    // Рёбра техника -> CVE + CVE -> следующая техника
    // Подготовим множество пар (technique, cve), чтобы избежать дублирования
    // связи между одной техникой и одной CVE в обоих направлениях.
    const tcPairs = new Set(); // key: `${tid}::${cid}`
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i];
      const t = st.technique; if (!t || !t.id) continue;
      const tid = String(t.id);
      const cves = Array.isArray(st.cves) ? st.cves : [];
      for (const cv of cves) {
        if (!cv || !cv.id) continue;
        const cid = String(cv.id);
        tcPairs.add(`${tid}::${cid}`);
      }
    }
    const edgeIds = new Set();
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i];
      const t = st.technique; if (!t || !t.id) continue;
      const tid = String(t.id);
      const predData = predictedData(st && st.edge_score);
      const nextT = (i < steps.length - 1) ? steps[i+1].technique : null;
      const nextTid = (nextT && nextT.id) ? String(nextT.id) : null;
      const cves = Array.isArray(st.cves) ? st.cves : [];
      for (const cv of cves) {
        if (!cv || !cv.id) continue;
        const cid = String(cv.id);
        const props = (cv && cv.props) || {};
        const epss = Number(props.epss || 0);
        const epssNorm = Number(props.epss_norm || 0);
        const eid1 = `sc_tc_${tid}_${cid}`;
        if (!edgeIds.has(eid1)) { edgeIds.add(eid1); elements.push({ data: { id: eid1, source: tid, target: cid, type: 'SC_TECH_TO_CVE', epss, EPSS: epss, epss_norm: epssNorm, ...predData } }); }
        if (nextTid) {
          const eid2 = `sc_cv_${cid}_${nextTid}`;
          // Если для пары (nextTid, cid) уже существует связь Technique->CVE,
          // не добавляем обратную связь CVE->Technique, чтобы избежать двух
          // параллельных рёбер между теми же узлами.
          if (!tcPairs.has(`${nextTid}::${cid}`)) {
            if (!edgeIds.has(eid2)) { edgeIds.add(eid2); elements.push({ data: { id: eid2, source: cid, target: nextTid, type: 'SC_STEP', stepCveId: cid, epss_norm: epssNorm, epss: epss, ...predData } }); }
          }
        }
      }
    }
    
    return elements;
  }

  // ч/б сценарий, CVE вертикально справа от соответствующей техники
  function buildScenarioElementsMono(sc) {
    const GAP_X = 160;
    const TECH_Y = 100;
    const CVE_OFFSET_X = Math.round(GAP_X * 0.35);
    const CVE_GAP_Y = 54;
    const elements = [];
    const steps = sc.steps || [];

    const techPos = new Map();
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i]; const t = st.technique; if (!t || !t.id) continue;
      const tid = String(t.id); const x = i * GAP_X; const y = TECH_Y;
      techPos.set(tid, { x, y });
      elements.push({ data: { id: tid, label: 'T', group: 'Technique', raw: t }, position: { x, y } });
      // Надпись с идентификатором техники
      const tIdLabel = (t.props && t.props.identifier) ? String(t.props.identifier) : '';
      if (tIdLabel) {
        const lid = `tl_${tid}`;
        elements.push({ data: { id: lid, label: tIdLabel, group: 'TechLabel' }, position: { x, y: y - 30 } });
      }
      // Прямая стрелка к следующей технике (для базового отображения пути)
      if (i < steps.length - 1) {
        const nextT = steps[i+1].technique;
        if (nextT && nextT.id) {
          const nextTid = String(nextT.id);
          const eid = `sc_tt_${tid}_${nextTid}`;
          elements.push({ data: { id: eid, source: tid, target: nextTid, type: 'SC_GROUP_LINK' } });
        }
      }
    }

    // Служебные узлы начала и конца маршрута
    const startId = 'sc_start';
    const endId = 'sc_end';
    if (steps.length > 0) {
      const firstX = 0;
      const lastX = (steps.length - 1) * GAP_X;
      elements.push({ data: { id: startId, label: 'Начало', group: 'ScenarioEndpoint' }, position: { x: firstX - GAP_X * 0.7, y: TECH_Y } });
      elements.push({ data: { id: endId, label: 'Конец', group: 'ScenarioEndpoint' }, position: { x: lastX + GAP_X, y: TECH_Y } });
      const firstStep = steps[0];
      if (firstStep && firstStep.technique && firstStep.technique.id) {
        const firstTid = String(firstStep.technique.id);
        const eidStart = `sc_tt_${startId}_${firstTid}`;
        elements.push({ data: { id: eidStart, source: startId, target: firstTid, type: 'SC_GROUP_LINK' } });
      }
      const lastStep = steps[steps.length - 1];
      if (lastStep && lastStep.technique && lastStep.technique.id) {
        const lastTid = String(lastStep.technique.id);
        const eidEnd = `sc_tt_${lastTid}_${endId}`;
        elements.push({ data: { id: eidEnd, source: lastTid, target: endId, type: 'SC_GROUP_LINK' } });
      }
    }

    // Для каждой техники отдельная колонка CVE справа
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i]; const t = st.technique; if (!t || !t.id) continue;
      const tid = String(t.id); const pos = techPos.get(tid); if (!pos) continue;
      const x = pos.x + CVE_OFFSET_X;
      const predData = predictedData(st && st.edge_score);
      const list = Array.isArray(st.cves) ? st.cves : [];
      for (let j = 0; j < list.length; j++) {
        const cv = list[j]; if (!cv || !cv.id) continue; const cid = String(cv.id);
        const y = pos.y + (j - (list.length-1)/2) * CVE_GAP_Y;
        const id = `cve_${tid}_${cid}`;
        const cvss = cvssSumFromRaw(cv);
        elements.push({ data:{ id, label:'CVE', group:'CVE', raw: cv, cvss: cvss, techId: tid }, position:{ x, y } });
        const props = (cv && cv.props) || {};
        const epss = Number(props.epss || 0);
        const epssNorm = Number(props.epss_norm || 0);
        const eid = `tc_${tid}_${cid}`;
        elements.push({ data:{ id:eid, source: tid, target: id, type:'SC_TECH_TO_CVE', epss: epss, EPSS: epss, epss_norm: epssNorm, ...predData } });
        // связь CVE -> следующая техника или служебный конец
        let targetId = null;
        if (i < steps.length - 1 && steps[i+1].technique && steps[i+1].technique.id) {
          targetId = String(steps[i+1].technique.id);
        } else {
          targetId = endId;
        }
        if (targetId) {
          const e2 = `cv_${tid}_${cid}_to_${targetId}`;
          elements.push({ data:{ id: e2, source: id, target: targetId, type: 'SC_STEP', stepTechId: tid, stepTactic: st.tactic || '', stepCveId: cid, epss_norm: epssNorm, epss: epss, ...predData } });
        }
      }
    }

    return elements;
  }

  async function draw() {
    const cpe = (cpeInput.value || '').trim();
    const mode = modeSel.value || 'full';
      if (!cpe) {
      alert('Укажите URI объекта');
        return;
      }
    saveForm();
    showLoading();
    // Дать браузеру шанс показать оверлей до тяжёлой работы
    await new Promise((r) => requestAnimationFrame(() => r()))
      .catch(() => {});
    try {
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
        const lbl = (n && n.group === 'Technique') ? 'T' : n.label;
        elements.push({ data: { id: n.id, label: lbl, group: n.group, raw: n } });
      }
      for (const e of data.edges || []) {
        elements.push({ data: { id: e.id, source: e.source, target: e.target, type: e.type } });
      }

      if (ncount === 0 && ecount === 0) {
        container.innerHTML = '<div style="padding:8px;color:#666">Подграф пуст — проверьте URI объекта.</div>';
        return;
      }

      if (cy) { cy.destroy(); cy = null; }
      const lblColor2 = labelColorFromCss();
      cy = cytoscape({
        container,
        elements,
        style: graphStyleForProfile(getProfile()),
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
    } finally {
      hideLoading();
    }
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
  // Интерфейс темы и начальное применение
  bindThemeUI();
  const initTheme = loadTheme(); if (initTheme) applyTheme(initTheme);
  // Интерфейс переключения профиля
  bindProfileUI();
  // Интерфейс экспорта (PNG/SVG/JSON)
  bindExportUI();
  // Интерфейс 3D ландшафта
  initLandscapeController();

  // Реакция на смену темы UI, обновляем цвета надписей, если они не переопределены темой графа
  document.addEventListener('sg:theme-change', () => {
    try {
      const saved = loadTheme();
      const lbl = labelColorFromCss();
      const mut = mutedColorFromCss();
      if (cy) {
        if (!(saved && saved.labels)) {
          cy.nodes().forEach(n => { n.style('color', lbl); });
        }
        cy.nodes('[group="TechLabel"]').forEach(n => { n.style('color', mut); });
        // Перекрашиваем карточки тактик в зависимости от текущей темы
        if (getProfile() === 'color') {
          const isLight = (getUiThemeMode() === 'light');
          const bg = isLight ? '#3b6eea' : '#141939';
          const op = isLight ? 0.14 : 0.22;
          cy.nodes('[group="TacticGroup"]').forEach(n => {
            n.style('background-color', bg);
            n.style('background-opacity', op);
            n.style('border-color', '#3b4775');
            n.style('color', mut);
          });
        }
      }
    } catch {}
  });

  if (genScenariosBtn) {
    genScenariosBtn.addEventListener('click', generateScenarios);
  }
  if (clearScenariosBtn) {
    clearScenariosBtn.addEventListener('click', () => {
      scenariosList.innerHTML = '';
      if (cy) { cy.elements().removeClass('sel neigh'); }
      // Если сейчас отображается сценарий, возврат к исходному графу
      if (isScenarioView) {
        restoreSnapshotFromLS();
        isScenarioView = false;
        currentScenarioId = null;
        currentScenarioData = null;
      }
      syncLandscapeData([]);
      // Чистим кэш сценариев в LS чтобы не переполнять
      try { localStorage.removeItem(LS_SCEN); } catch {}
    });
  }
  if (scModeSel) scModeSel.addEventListener('change', saveScForm);
  if (scMaxPerTacticInput) scMaxPerTacticInput.addEventListener('input', debounce(saveScForm, 200));
  if (viewModeSel) viewModeSel.addEventListener('change', () => { applyViewModeAvailability(); saveScForm(); });
  if (showAllCves) showAllCves.addEventListener('change', () => {
    if (isScenarioView && currentScenarioId === 'PRIMARY') {
      if (showAllCves.checked) showPrimaryAllCVEs();
      else { try { renderPrimaryOnCanvas(lastMega || []); } catch { cy.elements("edge[type='SC_TECH_TO_CVE']").remove(); cy.elements("node[group='CVE']").remove(); } }
      const th = loadTheme(); if (th) applyTheme(th);
    } else if (isScenarioView && currentScenarioId) {
      // Линейный сценарий: показать/скрыть все CVE и связанные рёбра
      try { setLinearCVEsVisible(!!showAllCves.checked); } catch {}
      const th = loadTheme(); if (th) applyTheme(th);
    }
  });
  if (closeAllKeys) closeAllKeys.addEventListener('change', () => {
    if (!cy) return;
    const kind = (isScenarioView && currentScenarioId === 'PRIMARY') ? 'primary' : 'linear';
    try {
      const pivots = cy.nodes("[group='KeyPivot']");
      if (!pivots || pivots.length === 0) return;
      if (closeAllKeys.checked) {
        // Замкнуть все ключи без ограничения по технике
        pivots.forEach(p => {
          p.data('keyState', 'closed');
          const tac = String(p.data('keyTacticId') || '');
          if (kind === 'primary') primaryClosedKeyByTactic.set(tac, String(p.id()));
          else linearClosedKeyByTactic.set(tac, String(p.id()));
          syncKeyPositionsForPivot(p);
        });
      } else {
        // Вернуть поведение по умолчанию и автозамкнуть один ключ на шаг
        if (kind === 'primary') primaryClosedKeyByTactic = new Map();
        else linearClosedKeyByTactic = new Map();
        pivots.forEach(p => { p.data('keyState', 'open'); });
        syncAllKeyPositions();
        autoCloseBestKeys(kind);
      }
    } catch {}
  });

  // первичный сценарий (primary) — визуализация групп тактик
  function renderPrimaryCard(data) {
    const frag = document.createDocumentFragment();
    const box = document.createElement('div'); box.className = 'scenario primary';
    const head = document.createElement('div'); head.className = 'scenario-head';
    const title = document.createElement('div'); title.className = 'scenario-title'; title.textContent = 'Общий сценарий';
    const act = document.createElement('div'); act.className = 'scenario-actions';
    const btnShow = document.createElement('button'); btnShow.textContent = 'Отобразить';
    // фиксированная ширина, чтобы текст не менял размер
    try { btnShow.style.width = '220px'; } catch {}
    const mega = Array.isArray(data.mega) ? data.mega : [];
    buildPrimaryStepIndex(mega);
    syncLandscapeData(mega);
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

    // Если уже открыт первичный сценарий и пользователь заново сгенерировал, не возвращаемся к графу, а перерисовываем
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
      style: scenarioStyleForProfile(getProfile()),
      layout: { name: 'preset', fit: true, padding: 20 }
    });
    if (getProfile() === 'mono') {
      primaryClosedKeyByTactic = new Map();
      bindKeyFollow();
      bindKeyClick('primary');
    }
    cy.on('tap', 'node', (evt) => {
      const ele = evt.target;
      const g = ele.data('group');
      if (g === 'KeyContact' || g === 'KeyPivot') return;
      const grp = ele.data('group');
      if (showAllCves && showAllCves.checked) {
        showPrimaryAllCVEs();
      } else if (grp === 'TacticGroup') {
        // Всегда сначала восстанавливаем прямые связи между тактиками,
        // затем скрываем только у выбранной тактики
        clearPrimaryCVEs(true);
        showPrimaryGroupDetails(ele);
      } else if (grp === 'Technique') {
        // То же поведение при выборе техники: вернуть связи, затем скрыть только у её тактики
        clearPrimaryCVEs(true);
        addCVEsForTechnique(ele);
      }
      cy.elements().removeClass('sel neigh'); ele.addClass('sel'); ele.closedNeighborhood().difference(ele).addClass('neigh'); renderInspector(ele);
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        if (!(showAllCves && showAllCves.checked)) clearPrimaryCVEs(true);
        cy.elements().removeClass('sel neigh');
        renderInspector(null);
      }
    });
    bindTooltipEvents();

    // При включённом флаге — сразу показать все CVE
    if (showAllCves && showAllCves.checked) {
      showPrimaryAllCVEs();
    }
    const th5 = loadTheme(); if (th5) applyTheme(th5);
  }

	  function buildPrimaryElements(mega) {
	    const isMono = (getProfile() === 'mono');
	    const COL_GAP = isMono ? 210 : 160;
	    const ROW_GAP=70, TOP_Y=80, CENTER_Y=150; const elements=[]; const cols=(mega||[]).slice().sort((a,b)=>(a.tactic_order||0)-(b.tactic_order||0));
	    const groupIds=[];
	    for (let ci=0; ci<cols.length; ci++) {
	      const col = cols[ci]; const gid = `tg_${ci}`; groupIds.push(gid);
	      const tgLabel = translateTacticName(col.tactic);
	      elements.push({ data: { id: gid, label: tacticLabelMultiline(tgLabel||''), group:'TacticGroup' }, position: { x: ci*COL_GAP, y: TOP_Y } });
	      const items = col.techniques || [];
	      for (let ri=0; ri<items.length; ri++) { const st=items[ri]; const t=st.technique; if (!t||!t.id) continue; const x=ci*COL_GAP; const y=CENTER_Y + (ri - (items.length-1)/2)*ROW_GAP; elements.push({ data: { id:String(t.id), label:'T', group:'Technique', raw:t, parent: gid }, position:{x,y} }); }
	    }
	    // Служебные узлы начала и конца маршрута только в ч/б профиле
	    if (isMono && groupIds.length > 0) {
	      const startId = 'pg_start';
	      const endId = 'pg_end';
	      const firstX = 0;
	      const lastX = (groupIds.length - 1) * COL_GAP;
	      elements.push({ data: { id: startId, label: 'Начало', group:'ScenarioEndpoint' }, position: { x: firstX - COL_GAP * 0.7, y: CENTER_Y } });
	      elements.push({ data: { id: endId, label: 'Конец', group:'ScenarioEndpoint' }, position: { x: lastX + COL_GAP, y: CENTER_Y } });
	      const firstGid = groupIds[0];
	      const lastGid = groupIds[groupIds.length - 1];
	      elements.push({ data: { id: `sc_group_start_${firstGid}`, source: startId, target: firstGid, type:'SC_GROUP_LINK' } });
	      elements.push({ data: { id: `sc_group_${lastGid}_end`, source: lastGid, target: endId, type:'SC_GROUP_LINK' } });
	    }
	    // Простые связи между соседними группами (скрываются при показе CVE)
	    for (let i=0; i<groupIds.length-1; i++) { const s=groupIds[i], t=groupIds[i+1]; const eid=`sc_group_${i}_${i+1}`; elements.push({ data: { id:eid, source:s, target:t, type:'SC_GROUP_LINK' } }); }
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
	    const CVE_GAP_Y=54;
	    const OFFSET_X = (getProfile() === 'mono') ? 80 : 70;
    const usedY = [];
    const placeY = (y) => { const MIN=44, STEP=6; let dy=0, dir=1, it=0, yy=y; while (usedY.some(v=>Math.abs(v-yy)<MIN) && it<200) { yy = y + dir*dy; dir=-dir; dy+=STEP; it++; } usedY.push(yy); return yy; };
    kids.forEach(k => {
      const tid = String(k.id());
      const st = primaryStepByTechId.get(tid); if (!st) return; const cves = Array.isArray(st.cves)?st.cves:[]; const edgeScores = st.edge_scores || {};
      const base = k.position(); const x = base.x + OFFSET_X;
      for (let i=0; i<cves.length; i++) {
        const cv = cves[i]; if (!cv || !cv.id) continue; const cid = String(cv.id);
        const predData = predictedData(edgeScores[cveKey(cv)]);
        const nodeId = `pg_cve_${tid}_${cid}`;
        const y = placeY(base.y + (i - (cves.length-1)/2) * CVE_GAP_Y);
        const cvss = cvssSumFromRaw(cv);
        if (cy.getElementById(nodeId).length === 0) {
          try { cy.add({ group:'nodes', data:{ id: nodeId, label:'CVE', group:'CVE', raw: cv, cvss: cvss, techId: tid }, position:{ x, y } }); } catch {}
        }
        const eid = `pg_tc_${tid}_${cid}`;
	        if (cy.getElementById(eid).length === 0) {
	          const epss = Number((cv.props && cv.props.epss) || 0);
	          const epssNorm = Number((cv.props && cv.props.epss_norm) || 0);
	          try { cy.add({ group:'edges', data:{ id: eid, source: tid, target: nodeId, type: 'SC_TECH_TO_CVE', epss: epss, EPSS: epss, epss_norm: epssNorm, ...predData } }); } catch {}
	        }
	        // Добавим связь CVE -> следующая тактика
	        const profileMono = (getProfile() === 'mono');
	        const nextG = findNextTacticGroup(groupEle);
	        let targetId = null;
	        if (nextG) targetId = nextG.id();
	        else if (profileMono) targetId = 'pg_end';
	        if (targetId) {
	          const e2 = `pg_cv_${tid}_${cid}_to_${targetId}`;
	          if (cy.getElementById(e2).length === 0) {
	            try {
                cy.add({ group:'edges', data:{ id: e2, source: nodeId, target: targetId, type: 'SC_GROUP', stepTechId: tid, stepTactic: st.tactic || '', stepCveId: cid, epss_norm: Number((cv.props && cv.props.epss_norm) || 0), epss: Number((cv.props && cv.props.epss) || 0), ...predData } });
              } catch {}
	          }
	        }
      }
    });
    // Если показаны CVE, скрываем прямые связи только для этой тактики
    try { hideGroupLinkFromGroup(groupEle.id()); } catch {}
    // Применяем тему к только что добавленным элементам
    const th = loadTheme(); if (th) applyTheme(th);
    if (getProfile() === 'mono') initPrimaryKeysForEdges();
  }

	  function addCVEsForTechnique(techEle) {
    const tid = String(techEle.id());
	    const st = primaryStepByTechId.get(tid); if (!st) return;
		    const list = Array.isArray(st.cves) ? st.cves : [];
        const edgeScores = st.edge_scores || {};
		    const base = techEle.position(); const x = base.x + ((getProfile() === 'mono') ? 80 : 70); const CVE_GAP_Y = 54;
    const usedY2 = [];
    const placeY2 = (y) => { const MIN=44, STEP=6; let dy=0, dir=1, it=0, yy=y; while (usedY2.some(v=>Math.abs(v-yy)<MIN) && it<200) { yy = y + dir*dy; dir=-dir; dy+=STEP; it++; } usedY2.push(yy); return yy; };
    for (let i = 0; i < list.length; i++) {
      const cv = list[i]; if (!cv || !cv.id) continue; const cid = String(cv.id);
      const predData = predictedData(edgeScores[cveKey(cv)]);
      const nodeId = `pg_cve_${tid}_${cid}`;
      const y = placeY2(base.y + (i - (list.length-1)/2) * CVE_GAP_Y);
      const cvss = cvssSumFromRaw(cv);
      if (cy.getElementById(nodeId).length === 0) {
        try { cy.add({ group:'nodes', data:{ id: nodeId, label:'CVE', group:'CVE', raw: cv, cvss: cvss, techId: tid }, position:{ x, y } }); } catch {}
      }
      const eid = `pg_tc_${tid}_${cid}`;
      if (cy.getElementById(eid).length === 0) {
        const epss = Number((cv.props && cv.props.epss) || 0);
        const epssNorm = Number((cv.props && cv.props.epss_norm) || 0);
        try { cy.add({ group:'edges', data:{ id: eid, source: tid, target: nodeId, type: 'SC_TECH_TO_CVE', epss: epss, EPSS: epss, epss_norm: epssNorm, ...predData } }); } catch {}
      }
	      const profileMono = (getProfile() === 'mono');
	      const nextG = findNextTacticGroup(techEle.parent());
	      let targetId = null;
	      if (nextG) targetId = nextG.id();
	      else if (profileMono) targetId = 'pg_end';
	      if (targetId) {
	        const e2 = `pg_cv_${tid}_${cid}_to_${targetId}`;
        if (cy.getElementById(e2).length === 0) {
          try {
            cy.add({ group:'edges', data:{ id: e2, source: nodeId, target: targetId, type: 'SC_GROUP', stepTechId: tid, stepTactic: st.tactic || '', stepCveId: cid, epss_norm: Number((cv.props && cv.props.epss_norm) || 0), epss: Number((cv.props && cv.props.epss) || 0), ...predData } });
          } catch {}
        }
	      }
    }
    // Если показаны CVE — скрываем прямые связи только для этой тактики
    try { hideGroupLinkFromGroup(techEle.parent().id()); } catch {}
    const th = loadTheme(); if (th) applyTheme(th);
    if (getProfile() === 'mono') initPrimaryKeysForEdges();
  }

  function setGroupLinksVisible(flag) {
    try {
      const edges = cy.edges("[type='SC_GROUP_LINK']");
      edges.forEach(e => {
        const src = String(e.data('source') || (e.source && e.source().id && e.source().id()) || '');
        const tgt = String(e.data('target') || (e.target && e.target().id && e.target().id()) || '');
        const isStartEdge = (src === 'pg_start' || src === 'sc_start');
        const isEndEdge = (tgt === 'pg_end' || tgt === 'sc_end');
        if (isStartEdge) {
          // Стрелка от Н к первой тактике/технике всегда видна
          e.style('display', 'element');
        } else if (isEndEdge) {
          if (!flag) {
            // Показаны CVE/ключи: прячем прямую стрелку, если есть ключевые стрелки к К
            let hasKeys = false;
            try {
              const keyToEnd = cy.edges("[type='SC_KEY_ARROW'][target='pg_end']");
              hasKeys = keyToEnd && keyToEnd.length > 0;
            } catch {}
            e.style('display', hasKeys ? 'none' : 'element');
          } else {
            // CVE скрыты: всегда показываем прямую стрелку к К
            e.style('display', 'element');
          }
        } else {
          e.style('display', flag ? 'element' : 'none');
        }
      });
    } catch {}
  }
  function hideGroupLinkFromGroup(gid) {
    try { cy.edges(`[type = 'SC_GROUP_LINK'][source = '${gid}']`).style('display','none'); } catch {}
  }
  function clearPrimaryCVEs(showLinks=false) {
    try { cy.elements("edge[type='SC_TECH_TO_CVE']").remove(); } catch {}
    try { cy.nodes("[group='CVE']").remove(); } catch {}
    try { cy.nodes("[group='KeyContact']").remove(); } catch {}
    try { cy.nodes("[group='KeyPivot']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_SEG']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_SWITCH']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_ARROW']").remove(); } catch {}
    if (showLinks) setGroupLinksVisible(true);
    if (getProfile() === 'mono') primaryClosedKeyByTactic = new Map();
  }

  function findNextTacticGroup(groupEle) {
    try {
      const gx = groupEle.position('x');
      let next = null; let dx = Infinity;
      cy.nodes("[group='TacticGroup']").forEach(g => {
        const x = g.position('x');
        if (x > gx && (x - gx) < dx) { dx = x - gx; next = g; }
      });
      return next;
    } catch { return null; }
  }

  function showPrimaryAllCVEs() {
    // Полностью перестраиваем CVE-слой
    cy.elements("edge[type='SC_TECH_TO_CVE']").remove();
    cy.elements("node[group='CVE']").remove();
    try { cy.nodes("[group='KeyContact']").remove(); } catch {}
    try { cy.nodes("[group='KeyPivot']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_SEG']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_SWITCH']").remove(); } catch {}
    try { cy.edges("[type='SC_KEY_ARROW']").remove(); } catch {}
    if (getProfile() === 'mono') primaryClosedKeyByTactic = new Map();
    const groups = cy.nodes("[group = 'TacticGroup']");
    groups.forEach(g => addCVEsForGroup(g, true));
    setGroupLinksVisible(false);
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
