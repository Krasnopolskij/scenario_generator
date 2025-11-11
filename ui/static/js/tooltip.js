// Высплывающее окно подсказки
(function() {
  const TIP_MARGIN = 8;
  let tipEl = null;
  let tipHost = null;

  function ensureTip() {
    if (tipEl) return tipEl;
    tipEl = document.createElement('div');
    tipEl.className = 'ui-tooltip';
    document.body.appendChild(tipEl);
    return tipEl;
  }

  function placeTipFor(el) {
    if (!tipEl) return;
    const rect = el.getBoundingClientRect();
    tipEl.style.left = '-9999px';
    tipEl.style.top = '-9999px';
    tipEl.classList.add('visible');
    const tw = Math.min(600, Math.max(360, tipEl.offsetWidth || 360));
    const th = tipEl.offsetHeight || 40;
    // По умолчанию показ окна справа, по необходимости слева
    const canRight = rect.right + TIP_MARGIN + tw <= window.innerWidth;
    let left = canRight ? (rect.right + TIP_MARGIN) : (rect.left - TIP_MARGIN - tw);
    if (left < TIP_MARGIN) left = TIP_MARGIN;
    if (left + tw > window.innerWidth - TIP_MARGIN) left = Math.max(TIP_MARGIN, window.innerWidth - TIP_MARGIN - tw);
    let top = rect.top;
    if (top < TIP_MARGIN) top = TIP_MARGIN;
    if (top + th > window.innerHeight - TIP_MARGIN) top = Math.max(TIP_MARGIN, window.innerHeight - TIP_MARGIN - th);
    tipEl.style.left = `${Math.round(left)}px`;
    tipEl.style.top = `${Math.round(top)}px`;
  }

  function showTip(el) {
    try {
      const txt = el.getAttribute('data-tip');
      if (!txt) return;
      ensureTip();
      tipEl.textContent = txt;
      tipHost = el;
      placeTipFor(el);
    } catch {}
  }

  function hideTip() {
    if (!tipEl) return;
    tipEl.classList.remove('visible');
    tipHost = null;
  }

  function bindTips(root=document) {
    const tips = root.querySelectorAll('.help-icon[data-tip]');
    tips.forEach(el => {
      el.addEventListener('mouseenter', () => showTip(el));
      el.addEventListener('mouseleave', hideTip);
      el.addEventListener('focus', () => showTip(el));
      el.addEventListener('blur', hideTip);
    });
    window.addEventListener('resize', () => { if (tipHost) placeTipFor(tipHost); });
    window.addEventListener('scroll', () => { if (tipHost) placeTipFor(tipHost); }, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => bindTips(document));
  } else {
    bindTips(document);
  }
})();

