/* Read-only public demo setup. Uses textContent to avoid markup injection. */
(async () => {
  try {
    const response = await fetch('/api/config');
    const config = await response.json();
    if (!config.demo_mode) return;
    document.querySelector('.private-auth')?.remove();
    const panel = document.querySelector('#scan-panel');
    const heading = document.createElement('div');
    heading.className = 'demo-banner';
    heading.textContent = 'PUBLIC DEMO · SYNTHETIC DATA · Live scanning is disabled for visitor safety.';
    panel.prepend(heading);
    document.querySelector('#form').classList.add('hidden-in-demo');
    const hint = panel.querySelector('.hint');
    hint.textContent = 'Browse the synthetic history, inspect sample analytics and download demonstration PDF reports.';
    const button = document.createElement('button');
    button.textContent = 'Explore sample assessment →';
    button.className = 'download';
    button.id = 'demo-assessment-button';
    button.addEventListener('click', async () => {
      const r = await fetch('/api/history/demo-003');
      const sample = await r.json();
      report = sample;
      document.dispatchEvent(new CustomEvent('securescan:report', {detail: sample}));
      const summary = document.querySelector('#summary');
      summary.replaceChildren();
      for (const [k,v] of [['Checks passed', sample.score+'%'],['Overall risk',sample.risk],['HTTP status',sample.status_code]]) {
        const b=document.createElement('div');b.className='metric';
        const a=document.createElement('div');a.className='k';a.textContent=k;
        const c=document.createElement('div');c.className='v';c.textContent=v;
        b.append(a,c);summary.append(b);
      }
      const checks = document.querySelector('#checks');checks.replaceChildren();
      for (const item of sample.checks) {
        const row=document.createElement('div');row.className='check';
        const info=document.createElement('div');
        const name=document.createElement('strong');name.textContent=item.name;
        const status=document.createElement('div');status.className='detail';status.textContent=item.status + ' · ' + item.evidence;
        info.append(name,status);row.append(info);checks.append(row);
      }
      document.querySelector('#note').textContent=sample.note;
      document.querySelector('#results').style.display='block';
      const compare=document.querySelector('#compare');
      compare.textContent='Select a saved report to view differences. Sample values are illustrative.';
      window.scrollTo({top:document.querySelector('#results').getBoundingClientRect().top + window.scrollY - 12,behavior:'smooth'});
    });
    panel.append(button);
  } catch (_) { /* Keep local UI usable if demo config endpoint is unavailable. */ }
})();
