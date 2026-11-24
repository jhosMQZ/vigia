// Applies the saved appearance before the first paint (external file: the CSP forbids inline scripts).
(function () {
  try {
    var p = localStorage.getItem('vigia.theme');
    var dark = p === 'dark' || (p !== 'light' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  } catch (e) { /* storage unavailable: light */ }
})();
