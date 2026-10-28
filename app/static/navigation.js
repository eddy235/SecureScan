/* Keep sidebar location clear for keyboard, pointer and scrolling navigation. */
(() => {
  const links = [...document.querySelectorAll('.side-link[href^="#"]')];
  const entries = links.map(link => ({link, target: document.querySelector(link.getAttribute('href'))})).filter(x => x.target);
  function activate(link) {
    for (const item of entries) {
      const active = item.link === link;
      item.link.classList.toggle('active', active);
      if (active) item.link.setAttribute('aria-current', 'location');
      else item.link.removeAttribute('aria-current');
    }
  }
  for (const item of entries) item.link.addEventListener('click', () => activate(item.link));
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(records => {
      const visible = records.filter(x => x.isIntersecting).sort((a,b) => b.intersectionRatio-a.intersectionRatio);
      if (visible.length) {
        const match = entries.find(x => x.target === visible[0].target);
        if (match) activate(match.link);
      }
    }, {rootMargin: '-10% 0px -65% 0px', threshold: [0, .1, .3]});
    for (const item of entries) observer.observe(item.target);
  }
})();
