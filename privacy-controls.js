(() => {
  // Use the provider's supported readiness queue; never fabricate consent.
  let pending = false;
  let cancelPending = () => {};
  window.addEventListener('pagehide', () => cancelPending());
  function unavailable() {
    const status = document.querySelector('[data-privacy-status]');
    if (status) status.textContent = document.documentElement.lang.startsWith('zh')
      ? '此页面的同意管理器不可用，未更改任何同意选择。请使用下方的广告偏好、浏览器设置说明或联系链接。'
      : 'The consent manager is unavailable on this page. No consent choice has been changed. Use the advertising preferences, browser settings guidance, or contact link below.';
  }
  document.addEventListener('click', (event) => {
    const link = event.target.closest?.('[data-privacy-settings]');
    if (!link || event.button > 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const manager = window.googlefc;
    if (typeof manager?.callbackQueue?.push === 'function') {
      event.preventDefault();
      if (pending) return;
      pending = true;
      let active = true;
      const fallback = () => {
        if (!active) return;
        active = false; pending = false;
        clearTimeout(timer);
        unavailable();
        window.location.assign(link.href);
      };
      const timer = setTimeout(fallback, 2000);
      cancelPending = () => { active = false; pending = false; clearTimeout(timer); };
      try {
        manager.callbackQueue.push({ CONSENT_DATA_READY: () => {
          // A callback arriving after fallback must not clear consent later.
          if (!active) return;
          if (typeof manager.showRevocationMessage !== 'function') return fallback();
          try { manager.showRevocationMessage(); }
          catch { fallback(); return; }
          active = false; pending = false; clearTimeout(timer);
        } });
      } catch { fallback(); }
      return;
    }
    unavailable();
  });
})();
