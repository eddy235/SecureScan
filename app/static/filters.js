/* Accessible client-side filtering; never interpolates report data as HTML. */
(() => {
  const select = document.querySelector('#finding-filter');
  const root = document.querySelector('#checks');
  if (!select || !root) return;
  function refresh() {
    const choice = select.value;
    let visible = 0;
    for (const item of root.querySelectorAll('.check')) {
      const text = item.textContent.toLowerCase();
      const passes = choice === 'all' ||
        (choice === 'attention' && text.includes('needs attention')) ||
        (choice === 'passed' && text.includes('passed')) ||
        (choice === 'na' && text.includes('not applicable'));
      item.hidden = !passes;
      if (passes) visible += 1;
    }
    root.setAttribute('aria-label', visible + ' findings displayed');
  }
  select.addEventListener('change', refresh);
  new MutationObserver(refresh).observe(root, {childList: true});
  refresh();
})();
