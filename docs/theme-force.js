// Force light theme — clear any stored dark preference from localStorage
(function () {
  var stored = localStorage.getItem('mdbook-theme');
  if (!stored || stored === 'coal' || stored === 'navy' || stored === 'ayu') {
    localStorage.setItem('mdbook-theme', 'light');
    // If the body already has a dark class, swap it immediately
    var html = document.documentElement;
    var body = document.body;
    var dark = ['coal', 'navy', 'ayu', 'rust'];
    dark.forEach(function (cls) {
      if (html) { html.classList.remove(cls); }
      if (body) { body.classList.remove(cls); }
    });
    if (html) html.classList.add('light');
    if (body) body.classList.add('light');
  }
})();
