/* Filter by explicit report status and severity; no innerHTML or inference from prose. */
(() => {
  const status = document.querySelector('#finding-filter');
  const severity = document.querySelector('#severity-filter');
  const root = document.querySelector('#checks');
  if (!status || !severity || !root) return;
  let checks = [];
  function refresh() {
    let count = 0;
    const rows = [...root.querySelectorAll('.check')];
    rows.forEach((row, i) => {
      const check = checks[i];
      const kind = check?.status === 'Needs attention' ? 'attention' :
        check?.status === 'Passed' ? 'passed' :
        check?.status === 'Not applicable' ? 'na' : row.dataset.status || 'unknown';
      const sev = check?.severity || 'Informational';
      const shown = (status.value === 'all' || status.value === kind) &&
        (severity.value === 'all' || severity.value === sev);
      row.hidden = !shown;
      if (shown) count += 1;
    });
    root.setAttribute('aria-label', count + ' findings displayed');
  }
  document.addEventListener('securescan:report', event => {
    checks = Array.isArray(event.detail?.checks) ? event.detail.checks : [];
    refresh();
  });
  status.addEventListener('change', refresh);
  severity.addEventListener('change', refresh);
  new MutationObserver(refresh).observe(root, {childList: true});
  refresh();
})();
