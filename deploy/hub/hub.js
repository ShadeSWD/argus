/* Хаб-оглавление учебных проектов. Подключение на любом сайте одной строкой:
     <script src="/hub.js" defer></script>
   Список проектов правится ТОЛЬКО в /hub.json (одно место на сервере).
   Работает на относительных путях (переживает переезд домена) и молча
   отключается, если сайт запущен отдельно и /hub.json недоступен. */
(function () {
  'use strict';
  if (window.__eduHubLoaded) return;
  window.__eduHubLoaded = true;
  function mount(d) {
    if (!d || !Array.isArray(d.sites)) return;
    var here = location.pathname;
    var others = d.sites.filter(function (s) {
      return s && s.path && here.indexOf(s.path) !== 0;
    });
    if (!others.length) return;
    var box = document.createElement('div');
    box.style.cssText = 'margin:28px auto 10px;padding:12px 16px;max-width:960px;' +
      'font:14px/1.6 system-ui,sans-serif;color:inherit;opacity:.85;' +
      'border-top:1px solid rgba(128,128,128,.35)';
    var head = document.createElement('div');
    head.textContent = '🎓 ' + (d.title || 'Другие проекты') + ':';
    head.style.cssText = 'font-weight:600;margin-bottom:6px';
    box.appendChild(head);
    others.forEach(function (s) {
      var a = document.createElement('a');
      a.href = s.path;
      a.textContent = (s.emoji ? s.emoji + ' ' : '') + s.name;
      if (s.desc) a.title = s.desc;
      a.style.cssText = 'display:inline-block;margin:2px 10px 2px 0;' +
        'padding:3px 10px;border-radius:14px;text-decoration:none;' +
        'color:inherit;background:rgba(128,128,128,.16)';
      box.appendChild(a);
    });
    (document.body || document.documentElement).appendChild(box);
  }
  function boot() {
    try {
      fetch('/hub.json', {cache: 'no-cache'})
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(mount)
        .catch(function () {});
    } catch (e) { /* сайт живёт без хаба */ }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else { boot(); }
})();
