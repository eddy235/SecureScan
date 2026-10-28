/* Progressive enhancement of existing report rows; no HTML injection. */
(() => {
  const root = document.getElementById('checks');
  if (!root) return;
  function enhance() {
    for (const row of root.querySelectorAll('.check:not([data-enhanced])')) {
      row.dataset.enhanced = 'true';
      const status = row.querySelector('.pill');
      const name = row.querySelector('strong');
      const details = [...row.querySelectorAll('.detail')];
      if (!name) continue;
      const state = (status?.textContent || details[0]?.textContent || '').toLowerCase();
      row.dataset.status = state.includes('needs attention') ? 'attention' :
        state.includes('not applicable') ? 'na' : state.includes('passed') ? 'passed' : 'unknown';
      const header = document.createElement('button');
      header.type = 'button';
      header.className = 'finding-toggle';
      header.setAttribute('aria-expanded', 'false');
      header.setAttribute('aria-label', 'Show evidence and remediation for ' + name.textContent);
      const heading = document.createElement('span');
      heading.className = 'finding-heading';
      heading.textContent = name.textContent;
      const label = document.createElement('span');
      label.className = 'finding-status';
      label.textContent = row.dataset.status === 'attention' ? 'Needs attention' :
        row.dataset.status === 'na' ? 'Not applicable' :
        row.dataset.status === 'passed' ? 'Passed' : 'Finding';
      const chevron = document.createElement('span');
      chevron.className = 'finding-chevron';
      chevron.textContent = '⌄';
      header.append(heading, label, chevron);
      const body = document.createElement('div');
      body.className = 'finding-body';
      body.hidden = true;
      for (const detail of details) {
        const line = document.createElement('p');
        line.textContent = detail.textContent;
        body.append(line);
      }
      if (!details.length) {
        const line = document.createElement('p');
        line.textContent = 'No additional evidence provided by this assessment.';
        body.append(line);
      }
      header.addEventListener('click', () => {
        const open = body.hidden;
        body.hidden = !open;
        header.setAttribute('aria-expanded', String(open));
      });
      row.replaceChildren(header, body);
    }
  }
  new MutationObserver(enhance).observe(root, {childList: true});
  enhance();
})();
