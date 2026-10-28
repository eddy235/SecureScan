/* Navigation follows visible sections; Findings loads the demo report on first visit. */
(() => {
  const links = [...document.querySelectorAll('.side-link[href^="#"]')];
  const entries = links.map(link => ({
    link, target: document.querySelector(link.getAttribute('href'))
  })).filter(entry => entry.target);

  function activate(link) {
    for (const entry of entries) {
      const selected = entry.link === link;
      entry.link.classList.toggle('active', selected);
      if (selected) entry.link.setAttribute('aria-current', 'location');
      else entry.link.removeAttribute('aria-current');
    }
  }

  for (const entry of entries) {
    entry.link.addEventListener('click', event => {
      if (entry.link.getAttribute('href') === '#results') {
        const results = document.querySelector('#results');
        if (results && getComputedStyle(results).display === 'none') {
          event.preventDefault();
          // The public demo adds its own button after /api/config resolves.
          const demoButton = document.querySelector('#demo-assessment-button');
          if (demoButton) {
            demoButton.click();
          } else {
            const form = document.querySelector('#scan-panel');
            form?.scrollIntoView({behavior: 'smooth', block: 'start'});
          }
          activate(entry.link);
          return;
        }
      }
      activate(entry.link);
    });
  }

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(records => {
      const visible = records.filter(entry => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (visible.length) {
        const match = entries.find(entry => entry.target === visible[0].target);
        if (match) activate(match.link);
      }
    }, {rootMargin: '-10% 0px -65% 0px', threshold: [0, .1, .3]});
    for (const entry of entries) observer.observe(entry.target);
  }
})();
