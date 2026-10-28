/* SecureScan intelligence overview: API-derived metrics, never fabricated values. */
(() => {
  const byId = id => document.getElementById(id);
  const set = (id, value) => { const node = byId(id); if (node) node.textContent = String(value); };
  function showTLS(tls) {
    const root = byId('overview-tls-content');
    if (!root) return;
    root.replaceChildren();
    if (!tls || typeof tls !== 'object') {
      root.textContent = 'No TLS certificate inspection recorded for this assessment.';
      return;
    }
    const fields = [
      ['Status', tls.status || 'Unknown'],
      ['Protocol', tls.tls_version || 'Not available'],
      ['Days remaining', tls.days_remaining ?? 'Not available'],
      ['Expires', tls.expires_at || 'Not available'],
      ['Details', tls.reason || '']
    ];
    for (const [label, value] of fields) {
      if (value === '') continue;
      const row = document.createElement('div');
      row.className = 'tls-detail';
      const key = document.createElement('span');
      key.textContent = label;
      const val = document.createElement('strong');
      val.textContent = String(value);
      row.append(key, val);
      root.append(row);
    }
  }
  function showReport(item) {
    if (!item || typeof item !== 'object') return;
    const score = Number(item.score);
    const valid = Number.isFinite(score) && score >= 0 && score <= 100;
    set('overview-score', valid ? Math.round(score) + '%' : '—');
    const gauge = byId('overview-gauge');
    if (gauge) {
      gauge.style.setProperty('--score', valid ? score + '%' : '0%');
      gauge.setAttribute('aria-label', valid ? 'Configuration score ' + Math.round(score) + ' percent' : 'Score unavailable');
    }
    set('overview-risk', item.risk ? 'Reported risk: ' + item.risk : 'Configuration assessment');
    const failed = item.summary && Number.isFinite(Number(item.summary.failed))
      ? Number(item.summary.failed)
      : Array.isArray(item.checks) ? item.checks.filter(c => c.status === 'Needs attention').length : null;
    set('overview-open', failed === null ? '—' : failed);
    set('overview-latest', (item.url || 'Saved assessment') + (item.scanned_at ? ' · ' + item.scanned_at : ''));
    showTLS(item.tls);
  }
  function renderActivity(history) {
    const root = byId('recent-activity');
    if (!root) return;
    root.replaceChildren();
    if (!Array.isArray(history) || !history.length) {
      root.textContent = 'No assessments available yet.';
      return;
    }
    for (const item of history.slice(0, 4)) {
      const row = document.createElement('div');
      row.className = 'recent-activity-row';
      const info = document.createElement('div');
      const url = document.createElement('strong');
      url.textContent = item.url || 'Saved assessment';
      const date = document.createElement('small');
      date.textContent = item.scanned_at || 'Date unavailable';
      info.append(url, date);
      const score = document.createElement('span');
      score.className = 'recent-score';
      score.textContent = typeof item.score === 'number' ? item.score + '%' : '—';
      row.append(info, score);
      root.append(row);
    }
  }
  async function getJSON(path) {
    const response = await (typeof apiFetch === 'function' ? apiFetch(path) : fetch(path));
    if (!response.ok) throw new Error('API returned ' + response.status);
    return response.json();
  }
  async function refresh() {
    try {
      const [stats, history] = await Promise.all([getJSON('/api/analytics'), getJSON('/api/history?limit=100')]);
      set('overview-total', stats.total_scans ?? '—');
      set('overview-targets', stats.unique_targets ?? '—');
      if (!Array.isArray(history) || !history.length) {
        set('overview-mode', 'No saved assessments');
        set('overview-open', '—');
        showTLS(null);
        renderActivity([]);
        return;
      }
      renderActivity(history);
      const latest = history[0];
      set('overview-mode', 'Based on saved assessments');
      try {
        const full = await getJSON('/api/history/' + encodeURIComponent(latest.id));
        showReport(full);
      } catch (_) {
        showReport(latest);
      }
    } catch (_) {
      set('overview-mode', 'Private data requires authorization');
      set('overview-total', '—');
      set('overview-targets', '—');
      set('overview-open', '—');
      set('overview-score', '—');
      const root = byId('recent-activity');
      if (root) root.textContent = 'Assessment history requires authorized access.';
    }
  }
  document.addEventListener('securescan:report', event => {
    if (event.detail) showReport(event.detail);
  });
  document.querySelector('#private-token')?.addEventListener('change', refresh);
  refresh();
})();
