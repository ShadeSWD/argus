# -*- coding: utf-8 -*-
"""Веб-дашборд мониторинга: состояние сервисов, ресурсы, журнал инцидентов.

Аутентификация: email+пароль из локального конфига (хэш), подписанная
HMAC-кука на 365 дней («запомнить это устройство») — на своих устройствах
вход выполняется один раз. Работает за nginx (TLS терминируется там).
"""
import hashlib
import hmac
import json
import os
import time

from flask import (Flask, jsonify, make_response, redirect, render_template_string,
                   request)

from . import atop, weblog, claude

app = Flask(__name__)
CONFIG_PATH = os.environ.get('ARGUS_CONFIG', '/root/argus/local/config.json')


def cfg():
    with open(CONFIG_PATH, encoding='utf-8') as fh:
        return json.load(fh)


def _sign(value, secret):
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


OWNER_IPS_PATH = '/var/lib/argus/owner_ips.json'
_owner_seen = {}


def _remember_owner(req):
    """IP авторизованного захода → «свои» устройства для веб-аналитики."""
    ip = req.headers.get('X-Real-IP') or req.remote_addr
    if not ip or ip == '127.0.0.1':
        return
    now = time.time()
    if now - _owner_seen.get(ip, 0) < 3600:
        return
    _owner_seen[ip] = now
    try:
        try:
            with open(OWNER_IPS_PATH, encoding='utf-8') as fh:
                ips = json.load(fh)
        except (OSError, ValueError):
            ips = {}
        ips[ip] = int(now)
        fd = os.open(OWNER_IPS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(ips, fh)
    except OSError:
        pass


def _auth_ok(req):
    c = cfg()
    token = (req.cookies.get('argus_auth')
             or req.cookies.get('sentinel_auth', ''))  # старое имя куки
    if '|' not in token:
        return False
    payload, sig = token.rsplit('|', 1)
    if not hmac.compare_digest(_sign(payload, c['web_secret']), sig):
        return False
    try:
        email, exp = payload.rsplit(':', 1)
        ok = email == c['web_email'] and float(exp) > time.time()
    except ValueError:
        return False
    if ok:
        _remember_owner(req)
    return ok


LOGIN_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus — вход</title><style>
body{font-family:system-ui;display:flex;justify-content:center;align-items:center;
height:100vh;margin:0;background:#0f172a;color:#e2e8f0}
form{background:#1e293b;padding:2rem;border-radius:12px;min-width:300px}
input{width:100%;padding:.6rem;margin:.4rem 0;border-radius:8px;border:1px solid #334155;
background:#0f172a;color:#e2e8f0;box-sizing:border-box}
button{width:100%;padding:.6rem;margin-top:.6rem;border:0;border-radius:8px;
background:#38bdf8;color:#0f172a;font-weight:600;cursor:pointer}
.err{color:#f87171}</style></head><body>
<form method="post"><h3>🛰 Argus</h3>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<input name="email" type="email" placeholder="email" required>
<input name="password" type="password" placeholder="пароль" required>
<button>Войти и запомнить это устройство</button></form></body></html>"""

DASH_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus — мониторинг сервера</title><style>
body{font-family:system-ui;margin:0;background:#0f172a;color:#e2e8f0}
header{padding:1rem 1.5rem;background:#1e293b;display:flex;justify-content:space-between}
main{padding:1rem 1.5rem;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{background:#1e293b;border-radius:12px;padding:1rem}
.ok{color:#4ade80}.bad{color:#f87171}.warn{color:#fbbf24}
table{width:100%;border-collapse:collapse;font-size:.9rem}
td,th{padding:.35rem .5rem;border-bottom:1px solid #334155;text-align:left}
small{color:#94a3b8}h4{margin:.2rem 0 .6rem}
.glbl{display:block;margin:14px 0 6px;color:#64748b;font-size:.78rem;
text-transform:uppercase;letter-spacing:.06em}
.glbl:first-child{margin-top:0}</style></head><body>
<header><b>🛰 Argus · мониторинг сервера</b>
<small>снимок: {{ snap.ts }} · автообновление 60 с ·
инцидентов открыто: {{ open_count }}</small></header><main>
<span class="glbl">Ресурсы</span>
<div class="grid">
<div class="card"><h4>Ресурсы</h4>
Диск: <b class="{{ 'bad' if snap.resources.disk_used_pct >= 90 else 'ok' }}">{{ snap.resources.disk_used_pct }}%</b><br>
Память свободна: <b class="{{ 'warn' if snap.resources.mem_available_pct <= 10 else 'ok' }}">{{ snap.resources.mem_available_pct }}%</b><br>
Загрузка/ядро: <b class="{{ 'warn' if snap.resources.load1_per_core >= 2 else 'ok' }}">{{ snap.resources.load1_per_core }}</b></div>
</div>
<span class="glbl">Контейнеры</span>
<div class="grid">
{% for name, c in snap.containers.items() %}{% if name in watch %}
<div class="card"><h4>🐳 {{ name }}</h4>
<span class="{{ 'ok' if c.running else 'bad' }}">{{ '● работает' if c.running else '■ остановлен' }}</span><br>
<small>{{ c.status }}</small></div>
{% endif %}{% endfor %}
</div>
<span class="glbl">Сайты</span>
<div class="grid">
{% for url, r in snap.http.items() %}
<div class="card"><h4>🌐 {{ url.replace('https://','').replace('http://','')[:34] }}</h4>
<span class="{{ 'ok' if r.ok else 'bad' }}">{{ r.code or 'нет ответа' }}</span>
· {{ r.ms }} мс{% if r.error %}<br><small>{{ r.error[:60] }}</small>{% endif %}
{% if uptime.get(url) is not none %}<br><small title="Доля успешных проверок за 24 часа">аптайм 24ч: <b class="{{ 'ok' if uptime[url] >= 99 else 'warn' }}">{{ uptime[url] }}%</b></small>{% endif %}
{% set host = url.split('/')[2].split(':')[0] %}
{% if snap.certs and snap.certs.get(host) is not none %}<br><small title="Дней до истечения TLS-сертификата">SSL: <b class="{{ 'ok' if snap.certs[host] > 14 else 'warn' }}">{{ snap.certs[host] }} дн.</b></small>{% endif %}</div>
{% endfor %}
</div>
<span class="glbl">Claude</span>
<div class="card">
<h4>Статус Claude Code
<span id="cl-sub" style="float:right;font-size:.8rem;font-weight:400"></span></h4>
<div id="cl-auth" style="font-size:.85rem;margin-bottom:8px"></div>
<div id="cl-tiles" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:10px"></div>
<canvas id="cl-chart" height="80"></canvas>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:8px">
<div><b style="font-size:.85rem;color:#c084fc">По моделям (30 дн)</b><table id="cl-models"></table></div>
<div><b style="font-size:.85rem;color:#38bdf8">Потребление по окнам</b><table id="cl-windows"></table></div>
</div>
<small id="cl-note"></small>
</div>
<div class="card" style="margin-top:14px">
<h4>Сейчас <small style="font-weight:400">— живые графики, шаг 2 с
(счётчики ядра, те же, что читает btop)</small></h4>
<canvas id="lv-cpu" height="64"></canvas>
<div id="lv-cores" style="display:flex;flex-wrap:wrap;gap:6px;margin:2px 0 8px;font-size:.72rem;color:#94a3b8"></div>
<canvas id="lv-mem" height="64"></canvas>
<canvas id="lv-net" height="64"></canvas>
<canvas id="lv-dsk" height="64"></canvas>
<small>Окно ~5 минут, переживает автообновление страницы. btop истории не
хранит, поэтому живой ряд копится прямо в браузере.</small>
</div>
<div class="card" style="margin-top:14px">
<h4>Процессы <small style="font-weight:400">— кто сколько ест, обновление 3 с</small></h4>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px">
<div><b style="font-size:.85rem;color:#38bdf8">CPU</b><table id="pt-cpu"></table></div>
<div><b style="font-size:.85rem;color:#4ade80">Память</b><table id="pt-mem"></table></div>
<div><b style="font-size:.85rem;color:#fbbf24">Диск</b><table id="pt-io"></table></div>
</div>
<small id="pt-note"></small>
</div>
<div class="card" style="margin-top:14px">
<h4>История (atop)
<span style="float:right;font-size:.85rem">
<a href="#" class="rng" data-h="6" style="color:#38bdf8">6 ч</a> ·
<a href="#" class="rng" data-h="24" style="color:#38bdf8">24 ч</a> ·
<a href="#" class="rng" data-h="168" style="color:#38bdf8">7 дн</a> ·
<a href="#" class="rng" data-h="672" style="color:#38bdf8">28 дн</a></span></h4>
<canvas id="at-cpu" height="80"></canvas>
<canvas id="at-mem" height="80"></canvas>
<canvas id="at-dsk" height="80"></canvas>
<canvas id="at-net" height="80"></canvas>
<canvas id="g-http" height="80"></canvas>
<small>Ресурсы — из журналов atop (снимок каждые 10 минут, хранятся 28 дней);
отклик сайтов — циклы агента (5 минут), только успешные проверки.</small>
</div>
<div class="card" style="margin-top:14px">
<h4>Посещения сайтов
<span style="float:right;font-size:.85rem">
<a href="#" class="vrng" data-d="7" style="color:#38bdf8">7 дн</a> ·
<a href="#" class="vrng" data-d="14" style="color:#38bdf8">14 дн</a> ·
<a href="#" class="vrng" data-d="30" style="color:#38bdf8">30 дн</a></span></h4>
<div id="vs-sum" style="margin-bottom:6px"></div>
<canvas id="vs-chart" height="90"></canvas>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin-top:8px">
<div><b style="font-size:.85rem;color:#38bdf8">Страницы</b><table id="vs-pages"></table></div>
<div><b style="font-size:.85rem;color:#4ade80">Страны</b><table id="vs-geo"></table></div>
<div><b style="font-size:.85rem;color:#c084fc">Откуда пришли</b><table id="vs-ref"></table></div>
</div>
<h4 style="margin-top:12px">Гости (48 ч)</h4>
<div style="overflow-x:auto"><table id="vs-vis"></table></div>
<h4 style="margin-top:12px">🏠 Мои устройства (48 ч)
<small style="font-weight:400">— IP, с которых заходили в Argus (VPN копятся сами); в статистику гостей не входят</small></h4>
<div style="overflow-x:auto"><table id="vs-own"></table></div>
<small id="vs-note">Источник — access-логи nginx: в код и БД сайтов ничего
не добавляется, новые сайты подхватываются автоматически по nginx-конфигу.
Свои проверки Argus и /monitor/ исключены; боты считаются отдельно.
IP-геолокация офлайн по базе DB-IP (наружу ничего не уходит).</small>
</div>
<script>
function drawSeries(id, label, seriesList, ymax) {
  var cv = document.getElementById(id), ctx = cv.getContext('2d');
  cv.width = cv.parentElement.clientWidth - 32;
  var W = cv.width, H = cv.height, pad = 40;
  ctx.clearRect(0, 0, W, H);
  ctx.font = '11px system-ui'; ctx.fillStyle = '#94a3b8';
  var lx = pad;
  ctx.fillText(label, lx, 12); lx += ctx.measureText(label).width + 12;
  var all = [];
  seriesList.forEach(function (s) { all = all.concat(s.d); });
  if (!all.length) { ctx.fillText('нет данных', pad, H/2); return; }
  seriesList.forEach(function (s) {
    if (!s.n) return;
    ctx.fillStyle = s.c; ctx.fillText('— ' + s.n, lx, 12);
    lx += ctx.measureText('— ' + s.n).width + 10;
  });
  var xs = all.map(function (p) { return p[0]; });
  var ys = all.map(function (p) { return p[1]; });
  var x0 = Math.min.apply(0, xs), x1 = Math.max.apply(0, xs);
  var y1 = ymax || Math.max(1, Math.max.apply(0, ys) * 1.15);
  ctx.strokeStyle = '#334155';
  ctx.beginPath(); ctx.moveTo(pad, H-16); ctx.lineTo(W-4, H-16); ctx.stroke();
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('0', 4, H-16); ctx.fillText(String(Math.round(y1)), 4, 22);
  seriesList.forEach(function (s) {
    ctx.strokeStyle = s.c; ctx.lineWidth = 1.6; ctx.beginPath();
    s.d.forEach(function (p, i) {
      var x = pad + (W-pad-8) * (p[0]-x0) / Math.max(1, x1-x0);
      var y = (H-20) - (H-36) * Math.min(p[1], y1) / y1;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  });
  var d0 = new Date(x0*1000), d1 = new Date(x1*1000);
  ctx.fillStyle = '#94a3b8';
  ctx.fillText(d0.toLocaleString('ru', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}), pad, H-3);
  var t1 = d1.toLocaleString('ru', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  ctx.fillText(t1, W - ctx.measureText(t1).width - 6, H-3);
}
function loadAtop(hours) {
  fetch('atop.json?hours=' + hours).then(function (r) { return r.json(); })
    .then(function (d) {
      var p = d.points || [];
      function col(k) { return p.map(function (q) { return [q.ts, q[k]]; }); }
      drawSeries('at-cpu', 'CPU, %', [
        {d: col('cpu_pct'), c: '#38bdf8', n: 'занято'},
        {d: col('iowait_pct'), c: '#f87171', n: 'iowait'}], 100);
      drawSeries('at-mem', 'Память занята, %', [
        {d: col('mem_pct'), c: '#4ade80'}], 100);
      drawSeries('at-dsk', 'Диск, КБ/с', [
        {d: col('disk_r_kbps'), c: '#38bdf8', n: 'чтение'},
        {d: col('disk_w_kbps'), c: '#fbbf24', n: 'запись'}]);
      drawSeries('at-net', 'Сеть, КБ/с', [
        {d: col('net_rx_kbps'), c: '#38bdf8', n: 'вход'},
        {d: col('net_tx_kbps'), c: '#c084fc', n: 'выход'}]);
    });
}
function loadMetrics(hours) {
  fetch('metrics.json?hours=' + hours).then(function (r) { return r.json(); })
    .then(function (d) {
      var http = [];
      (d.points || []).forEach(function (p) {
        var vals = Object.values(p.http_ms || {});
        if (vals.length) http.push([p.ts, Math.max.apply(0, vals)]);
      });
      drawSeries('g-http', 'Худший отклик сайтов, мс', [{d: http, c: '#f87171'}]);
    });
}
document.querySelectorAll('.rng').forEach(function (a) {
  a.onclick = function (e) {
    e.preventDefault(); loadAtop(a.dataset.h); loadMetrics(a.dataset.h);
  };
});
loadAtop(24); loadMetrics(24);

/* ---- живые графики (стиль btop): клиент считает дельты счётчиков ---- */
var LV_MAX = 150;
var lv = {cpu: [], mem: [], rx: [], tx: [], dr: [], dw: [], cores: [], last: null};
try {
  var saved = JSON.parse(sessionStorage.getItem('lv') || 'null');
  if (saved) { lv = saved; ['cpu','mem','rx','tx','dr','dw'].forEach(function (k) {
    if (!Array.isArray(lv[k])) lv[k] = []; }); }
} catch (e) {}
function lvPush(a, v) { a.push(Math.max(0, v)); if (a.length > LV_MAX) a.shift(); }
function lvLast(a) { return a.length ? a[a.length - 1] : 0; }
function fmtK(v) { return v >= 1024 ? (v/1024).toFixed(1) + ' МБ/с' : Math.round(v) + ' КБ/с'; }
function drawLive(id, label, seriesList, ymax, cur) {
  var cv = document.getElementById(id), ctx = cv.getContext('2d');
  cv.width = cv.parentElement.clientWidth - 32;
  var W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  var y1 = ymax;
  if (!y1) {
    y1 = 1;
    seriesList.forEach(function (s) { s.d.forEach(function (v) { if (v > y1) y1 = v; }); });
    y1 *= 1.15;
  }
  seriesList.forEach(function (s) {
    if (s.d.length < 2) return;
    var step = (W - 8) / (LV_MAX - 1);
    ctx.strokeStyle = s.c; ctx.lineWidth = 1.4; ctx.beginPath();
    s.d.forEach(function (v, i) {
      var x = W - 2 - (s.d.length - 1 - i) * step;
      var y = (H - 4) - (H - 24) * Math.min(v, y1) / y1;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
    if (s.fill) {
      ctx.lineTo(W - 2, H - 4);
      ctx.lineTo(W - 2 - (s.d.length - 1) * step, H - 4);
      ctx.closePath(); ctx.fillStyle = s.c + '2e'; ctx.fill();
    }
  });
  ctx.font = '11px system-ui'; ctx.fillStyle = '#94a3b8';
  ctx.fillText(label + ': ', 8, 12);
  ctx.fillStyle = '#e2e8f0';
  ctx.fillText(cur, 8 + ctx.measureText(label + ': ').width, 12);
  if (!ymax) {
    ctx.fillStyle = '#64748b';
    var pk = 'пик ' + fmtK(y1 / 1.15);
    ctx.fillText(pk, W - ctx.measureText(pk).width - 6, 12);
  }
}
function lvRender(d) {
  drawLive('lv-cpu', 'CPU', [{d: lv.cpu, c: '#38bdf8', fill: 1}], 100,
    Math.round(lvLast(lv.cpu)) + '%');
  var gb = d ? ((d.mem_total_kb - d.mem_avail_kb) / 1048576).toFixed(1) : '?';
  drawLive('lv-mem', 'Память', [{d: lv.mem, c: '#4ade80', fill: 1}], 100,
    Math.round(lvLast(lv.mem)) + '% (' + gb + ' ГБ)');
  drawLive('lv-net', 'Сеть', [{d: lv.rx, c: '#38bdf8'}, {d: lv.tx, c: '#c084fc'}], null,
    '↓ ' + fmtK(lvLast(lv.rx)) + '  ↑ ' + fmtK(lvLast(lv.tx)));
  drawLive('lv-dsk', 'Диск', [{d: lv.dr, c: '#38bdf8'}, {d: lv.dw, c: '#fbbf24'}], null,
    'чтение ' + fmtK(lvLast(lv.dr)) + '  запись ' + fmtK(lvLast(lv.dw)));
  var el = document.getElementById('lv-cores');
  el.innerHTML = '';
  (lv.cores || []).forEach(function (p, i) {
    var s = document.createElement('span');
    s.textContent = 'C' + i + ' ' + p + '%';
    s.style.cssText = 'padding:1px 7px;border-radius:6px;background:#0f172a';
    el.appendChild(s);
  });
}
function lvTick() {
  fetch('live.json').then(function (r) { return r.json(); }).then(function (d) {
    var pr = lv.last; lv.last = d;
    if (pr && d.ts > pr.ts) {
      var dt = d.ts - pr.ts, busy = 0, tot = 0, cores = [];
      d.cpus.forEach(function (c, i) {
        var pc = (pr.cpus || [])[i] || c;
        var b = c[0] - pc[0], t = c[1] - pc[1];
        busy += b; tot += t;
        cores.push(t > 0 ? Math.round(100 * b / t) : 0);
      });
      lvPush(lv.cpu, tot > 0 ? 100 * busy / tot : 0);
      lvPush(lv.rx, (d.net_rx_bytes - pr.net_rx_bytes) / dt / 1024);
      lvPush(lv.tx, (d.net_tx_bytes - pr.net_tx_bytes) / dt / 1024);
      lvPush(lv.dr, (d.disk_read_sect - pr.disk_read_sect) * 512 / dt / 1024);
      lvPush(lv.dw, (d.disk_write_sect - pr.disk_write_sect) * 512 / dt / 1024);
      lv.cores = cores;
    }
    lvPush(lv.mem, d.mem_total_kb
      ? 100 * (d.mem_total_kb - d.mem_avail_kb) / d.mem_total_kb : 0);
    try { sessionStorage.setItem('lv', JSON.stringify(lv)); } catch (e) {}
    lvRender(d);
  }).catch(function () {});
}
lvRender(null); lvTick(); setInterval(lvTick, 2000);

/* ---- топ процессов (диспетчер задач) ---- */
function ptFill(id, rows, val) {
  var tb = document.getElementById(id);
  tb.innerHTML = '';
  rows.forEach(function (p) {
    var tr = document.createElement('tr');
    [p.pid, p.name, val(p)].forEach(function (v, i) {
      var td = document.createElement('td');
      td.textContent = v;
      if (i === 0) td.style.color = '#64748b';
      if (i === 2) { td.style.textAlign = 'right'; td.style.whiteSpace = 'nowrap'; }
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
}
function ptTick() {
  fetch('proc.json').then(function (r) { return r.json(); }).then(function (d) {
    ptFill('pt-cpu', d.cpu, function (p) { return p.cpu_pct.toFixed(1) + '%'; });
    ptFill('pt-mem', d.mem, function (p) {
      return p.rss_mb >= 1024 ? (p.rss_mb/1024).toFixed(1) + ' ГБ'
                              : Math.round(p.rss_mb) + ' МБ';
    });
    ptFill('pt-io', d.io, function (p) { return fmtK(p.io_kbps); });
    document.getElementById('pt-note').textContent =
      'Всего процессов: ' + d.total +
      '. CPU может быть больше 100% (несколько ядер); диск — чтение + запись.';
  }).catch(function () {});
}
ptTick(); setInterval(ptTick, 3000);

/* ---- посещения сайтов (access-логи nginx) ---- */
var VS_COLORS = ['#38bdf8', '#4ade80', '#fbbf24', '#c084fc', '#f87171',
                 '#2dd4bf', '#f472b6', '#94a3b8'];
function flag(cc) {
  if (!/^[A-Z]{2}$/.test(cc)) return cc;
  return cc.replace(/./g, function (c) {
    return String.fromCodePoint(127397 + c.charCodeAt(0));
  }) + ' ' + cc;
}
function vsTable(id, rows) {
  var tb = document.getElementById(id);
  tb.innerHTML = '';
  rows.forEach(function (r) {
    var tr = document.createElement('tr');
    r.forEach(function (v, i) {
      var td = document.createElement('td');
      td.textContent = v;
      if (i === r.length - 1) { td.style.textAlign = 'right'; }
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
}
function loadVisits(days) {
  fetch('visits.json?days=' + days).then(function (r) { return r.json(); })
    .then(function (d) {
      document.getElementById('vs-sum').innerHTML =
        'За период: гостей <b>' + d.visitors + '</b> · их просмотров <b>' +
        d.views + '</b> · <small>🏠 моих устройств: ' + d.own.devices +
        ' (' + d.own.views + ' просм.) · хитов ботов: ' + d.bots + '</small>';
      var series = d.sites.map(function (s, i) {
        return {n: s, c: VS_COLORS[i % VS_COLORS.length],
                d: d.days.map(function (day) {
                  var ts = new Date(day.date + 'T12:00:00').getTime() / 1000;
                  return [ts, (day.sites[s] || {}).visitors || 0];
                })};
      });
      drawSeries('vs-chart', 'Посетители/день', series);
      vsTable('vs-pages', d.pages.map(function (p) { return [p[0], p[1]]; }));
      vsTable('vs-geo', d.countries.map(function (c) { return [flag(c[0]), c[1]]; }));
      vsTable('vs-ref', d.referers.length
        ? d.referers.map(function (r) { return [r[0], r[1]]; })
        : [['(прямые заходы)', '']]);
    });
}
function visRows(list) {
  var rows = [['когда', 'IP', 'страна', 'браузер', 'что смотрел', 'хиты']];
  list.forEach(function (v) {
    rows.push([v.last, v.ip, flag(v.country), v.browser,
               v.pages.map(function (p) {
                 return p[0] + (p[1] > 1 ? '×' + p[1] : '');
               }).join('  '), v.hits]);
  });
  return rows;
}
function loadVisitors() {
  fetch('visitors.json').then(function (r) { return r.json(); })
    .then(function (d) {
      vsTable('vs-vis', d.visitors.length ? visRows(d.visitors)
                                          : [['(гостей не было)']]);
      vsTable('vs-own', d.own.length ? visRows(d.own) : [['(заходов не было)']]);
      document.getElementById('vs-note').textContent =
        'Гостей за 48 ч: ' + d.humans + '; ботов: ' + d.bots_ips +
        ' IP (' + d.bots_hits + ' хитов) — по User-Agent, сканерным путям и ' +
        'поведению (сплошные 404, страницы без стилей/картинок). ' +
        'Источник — access-логи nginx: в код и БД сайтов ничего не ' +
        'добавляется, новые сайты подхватываются сами. IP-гео офлайн (DB-IP).';
    });
}
document.querySelectorAll('.vrng').forEach(function (a) {
  a.onclick = function (e) { e.preventDefault(); loadVisits(a.dataset.d); };
});
loadVisits(14); loadVisitors();

/* ---- статус Claude Code ---- */
function fmtTok(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' млрд';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' млн';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + ' тыс';
  return String(n);
}
function tile(label, big, sub, color) {
  return '<div style="background:#0f172a;border-radius:9px;padding:8px 10px">' +
    '<div style="font-size:.72rem;color:#94a3b8">' + label + '</div>' +
    '<div style="font-size:1.15rem;font-weight:600;color:' + (color || '#e2e8f0') +
    '">' + big + '</div>' +
    '<div style="font-size:.7rem;color:#64748b">' + sub + '</div></div>';
}
function loadClaude() {
  fetch('claude.json').then(function (r) { return r.json(); }).then(function (d) {
    var s = d.subscription || {};
    document.getElementById('cl-sub').innerHTML = s.type
      ? '🟢 подписка <b>' + String(s.type).toUpperCase() + '</b>' +
        (s.tier ? ' <small>(' + s.tier.replace('default_claude_', '') + ')</small>' : '')
      : '';
    var rd = s.refresh_days;
    if (rd != null) {
      var warn = rd < 7;
      document.getElementById('cl-auth').innerHTML =
        (warn ? '⚠️ ' : '🔑 ') + 'Авторизация Claude Code истекает через <b class="' +
        (warn ? 'warn' : 'ok') + '">' + rd.toFixed(1) + ' дн</b> (' +
        (s.refresh_date || '') + ')' +
        (warn ? ' — потребуется повторный вход <code>claude</code>' : '');
    }
    var w = d.windows || {};
    function tokandcost(x) {
      return x.cost_usd ? '≈ $' + x.cost_usd.toLocaleString('ru') + ' по API' : '';
    }
    document.getElementById('cl-tiles').innerHTML =
      tile('За 5 часов (окно тарифа)', fmtTok(w.last5h.output), 'output · ' + tokandcost(w.last5h), '#38bdf8') +
      tile('Сегодня', fmtTok(w.today.output), 'output · ' + w.today.msgs + ' сообщ.', '#4ade80') +
      tile('7 дней', fmtTok(w.last7d.output), 'output · ' + tokandcost(w.last7d), '#fbbf24') +
      tile('Всего (' + d.days_tracked + ' дн)', fmtTok(w.all.output), 'output · ' + tokandcost(w.all), '#c084fc');
    drawSeries('cl-chart', 'Output-токены/день (30 дн)',
      [{d: (d.daily || []).map(function (p) {
        return [new Date(p.date + 'T12:00:00').getTime() / 1000, p.output]; }),
        c: '#4ade80'}]);
    var mrows = Object.keys(d.by_model || {}).sort(function (a, b) {
      return d.by_model[b].total - d.by_model[a].total; }).map(function (m) {
      return [m, fmtTok(d.by_model[m].output) + ' out',
              d.by_model[m].cost_usd ? '$' + d.by_model[m].cost_usd.toLocaleString('ru') : '—'];
    });
    vsTable('cl-models', mrows);
    vsTable('cl-windows', [
      ['5 часов', fmtTok(w.last5h.total), '$' + w.last5h.cost_usd.toLocaleString('ru')],
      ['сегодня', fmtTok(w.today.total), '$' + w.today.cost_usd.toLocaleString('ru')],
      ['7 дней', fmtTok(w.last7d.total), '$' + w.last7d.cost_usd.toLocaleString('ru')],
      ['30 дней', fmtTok(w.last30d.total), '$' + w.last30d.cost_usd.toLocaleString('ru')],
    ]);
    document.getElementById('cl-note').textContent =
      'Токены из локальных транскриптов Claude Code (наружу не уходят). ' +
      '«total» включает чтение кэша (дёшево и много); показатель нагрузки — output. ' +
      '$ — гипотетический эквивалент по ценам API (подписка Max их не тарифицирует). ' +
      'Живого «остатка лимита» в локальных файлах нет — показано потребление по окнам.';
  }).catch(function () {});
}
loadClaude();

/* ---- автообновление без прыжка наверх: восстанавливаем скролл ---- */
try {
  var sy = sessionStorage.getItem('argusScroll');
  if (sy !== null) {
    window.scrollTo(0, parseInt(sy, 10));
    setTimeout(function () { window.scrollTo(0, parseInt(sy, 10)); }, 400);
  }
} catch (e) {}
setInterval(function () {
  try { sessionStorage.setItem('argusScroll', String(window.scrollY)); }
  catch (e) {}
}, 1000);
setTimeout(function () { location.reload(); }, 60000);
</script>

<div class="card" style="margin-top:14px"><h4>💬 Спросить у ИИ о сервере</h4>
<div id="oc-log" style="max-height:220px;overflow-y:auto"></div>
<form id="oc-form" style="display:flex;gap:8px;margin-top:8px">
<input id="oc-in" placeholder="Например: всё ли в порядке? почему падал relmet-web?"
 style="flex:1;padding:.5rem;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0">
<button style="padding:.5rem 1rem;border:0;border-radius:8px;background:#38bdf8;color:#0f172a;font-weight:600;cursor:pointer">➤</button>
</form>
<small>Отвечает локальная модель по текущему снимку, журналу инцидентов и аптайму
(данные не покидают сервер; ответ до минуты).</small></div>
<script>
document.getElementById('oc-form').onsubmit = function (e) {
  e.preventDefault();
  var inp = document.getElementById('oc-in'), log = document.getElementById('oc-log');
  var q = inp.value.trim(); if (!q) return;
  inp.value = '';
  function add(t, col) {
    var d = document.createElement('div');
    d.style.cssText = 'margin:6px 0;padding:7px 10px;border-radius:9px;background:' + col;
    d.textContent = t; log.appendChild(d); log.scrollTop = log.scrollHeight; return d;
  }
  add('Вы: ' + q, '#334155');
  var w = add('…анализирую данные мониторинга', '#1e3a5f');
  fetch('chat', {method: 'POST', headers: {'Content-Type': 'application/json'},
                 body: JSON.stringify({message: q})})
    .then(function (r) { return r.json(); })
    .then(function (d) { w.textContent = d.answer || d.error || 'ошибка'; })
    .catch(function () { w.textContent = 'модель недоступна'; });
};
</script>

<div class="card" style="margin-top:14px"><h4>Как это работает</h4>
<small>
Агент <b>Argus</b> запускается по расписанию каждые 5 минут и делает
полный цикл:<br>
1) <b>Снимок</b> — состояние Docker-контейнеров, HTTP-проверки сайтов
(код и время ответа), хвосты логов, диск/память/загрузка процессора.<br>
2) <b>Детектор</b> — правила: контейнер упал или пропал, сайт не отвечает или
отвечает дольше 8 с, диск &ge; 90 %, свободной памяти &le; 5 %, всплеск
ошибок в логах.<br>
3) <b>Диагноз ИИ</b> — факты инцидента уходят в локальную языковую модель
(Ollama, работает на этом же сервере, данные никуда не передаются); она
возвращает диагноз, вероятную причину, рекомендацию и — если уместно —
предлагает действие из белого списка.<br>
4) <b>Авточинка</b> — исполняются только заранее разрешённые действия
(сейчас: перезапуск веб-контейнера), с ограничениями: не чаще раза в 30 минут,
не более 3 раз в сутки; перезагрузка сервера запрещена в принципе. Модель
никогда не пишет команды сама — она лишь выбирает пункт из списка.<br>
5) <b>Оповещения</b> — аларм в Telegram-канал «🛰 Мониторинг сервера» с
диагнозом; повторные алармы по той же проблеме не шлются; когда проблема
уходит — приходит «восстановлено».<br>
Цвета: <span class="ok">зелёный — норма</span>,
<span class="warn">жёлтый — предупреждение</span>,
<span class="bad">красный — критично</span>. Страница обновляется каждые 60 с.
</small></div>

<div class="card" style="margin-top:14px"><h4>Журнал инцидентов (последние {{ events|length }})</h4>
<table><tr><th>Время</th><th>Событие</th><th>Диагноз ИИ</th><th>Действие</th></tr>
{% for e in events %}
<tr><td><small>{{ e.ts }}</small></td>
<td class="{{ 'ok' if e.event == 'resolved' else ('bad' if e.severity == 'critical' else 'warn') }}">
{{ '✅ ' + e.title if e.event == 'resolved' else e.title }}</td>
<td><small>{{ e.verdict.diagnosis if e.verdict else '' }}
{% if e.verdict and e.verdict.llm %}(LLM){% endif %}</small></td>
<td><small>{% if e.action %}{{ e.action.id }} — {{ e.action.reason }}{% endif %}</small></td></tr>
{% endfor %}</table>
<small>Диагнозы — локальная модель (Ollama), автодействия — только из белого
списка с кулдаунами. Агент: Argus.</small></div>
</main></body></html>"""


@app.route('/', methods=['GET', 'POST'])
def dashboard():
    c = cfg()
    if not _auth_ok(request):
        error = None
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            pw_hash = hashlib.sha256(
                request.form.get('password', '').encode()).hexdigest()
            if email == c['web_email'] and pw_hash == c['web_password_sha256']:
                payload = f'{email}:{time.time() + 365 * 86400}'
                resp = make_response(redirect(request.url))
                resp.set_cookie('argus_auth',
                                payload + '|' + _sign(payload, c['web_secret']),
                                max_age=365 * 86400, httponly=True,
                                secure=True, samesite='Lax')
                return resp
            error = 'Неверный email или пароль.'
        return render_template_string(LOGIN_HTML, error=error)

    data_dir = c.get('data_dir', '/var/lib/argus')
    try:
        with open(os.path.join(data_dir, 'last_snapshot.json'), encoding='utf-8') as fh:
            snap = json.load(fh)
    except (OSError, ValueError):
        snap = {'ts': 'нет данных — агент ещё не отработал', 'containers': {},
                'http': {}, 'resources': {'disk_used_pct': 0,
                                          'mem_available_pct': 0,
                                          'load1_per_core': 0}}
    events = []
    try:
        with open(os.path.join(data_dir, 'incidents.jsonl'), encoding='utf-8') as fh:
            events = [json.loads(ln) for ln in fh.readlines()[-30:]]
        events.reverse()
    except (OSError, ValueError):
        pass
    open_count = 0
    try:
        with open(os.path.join(data_dir, 'state.json'), encoding='utf-8') as fh:
            open_count = len(json.load(fh).get('open', {}))
    except (OSError, ValueError):
        pass
    return render_template_string(DASH_HTML, snap=snap, events=events,
                                  open_count=open_count,
                                  uptime=_uptime(data_dir, 24),
                                  watch=c.get('watch_containers', []))


def _uptime(data_dir, hours):
    """Доля циклов с успешной проверкой по каждому URL за период."""
    since = time.time() - hours * 3600
    total = 0
    ok = {}
    try:
        with open(os.path.join(data_dir, 'metrics.jsonl'), encoding='utf-8') as fh:
            for line in fh:
                try:
                    p = json.loads(line)
                except ValueError:
                    continue
                if p.get('ts', 0) < since:
                    continue
                total += 1
                for u in (p.get('http_ms') or {}):
                    ok[u] = ok.get(u, 0) + 1
    except OSError:
        pass
    return {u: round(100 * n / total, 2) for u, n in ok.items()} if total else {}


@app.route('/chat', methods=['POST'])
def ops_chat():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    c = cfg()
    data_dir = c.get('data_dir', '/var/lib/argus')
    message = str((request.get_json(silent=True) or {}).get('message', '')).strip()[:1000]
    if not message:
        return jsonify({'error': 'пустой вопрос'}), 400
    try:
        with open(os.path.join(data_dir, 'last_snapshot.json'), encoding='utf-8') as fh:
            snap = json.load(fh)
        snap.pop('logs', None)
    except (OSError, ValueError):
        snap = {}
    events = []
    try:
        with open(os.path.join(data_dir, 'incidents.jsonl'), encoding='utf-8') as fh:
            for ln in fh.readlines()[-10:]:
                e = json.loads(ln)
                events.append({'ts': e.get('ts'), 'event': e.get('event'),
                               'title': e.get('title'),
                               'diagnosis': (e.get('verdict') or {}).get('diagnosis')})
    except (OSError, ValueError):
        pass
    context = json.dumps({'snapshot': snap, 'recent_events': events,
                          'uptime_24h_pct': _uptime(data_dir, 24)},
                         ensure_ascii=False)[:6000]
    prompt = ('Ты — ассистент мониторинга сервера. Отвечай кратко по-русски, '
              'ТОЛЬКО по данным ниже; если данных не хватает — так и скажи. '
              'Никаких команд не предлагай.\n\nДАННЫЕ МОНИТОРИНГА:\n' + context +
              '\n\nВОПРОС: ' + message)
    payload = json.dumps({'model': c.get('ollama_model', 'qwen2.5:3b'),
                          'stream': False,
                          'options': {'temperature': 0.3, 'num_predict': 350},
                          'messages': [{'role': 'user', 'content': prompt}]}).encode()
    try:
        import urllib.request
        req = urllib.request.Request(
            c.get('ollama_url', 'http://127.0.0.1:11434').rstrip('/') + '/api/chat',
            data=payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=180) as resp:
            answer = json.loads(resp.read())['message']['content'].strip()
    except Exception:
        return jsonify({'error': 'модель недоступна'}), 503
    return jsonify({'answer': answer})


@app.route('/metrics.json')
def metrics():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    c = cfg()
    hours = min(24 * 35, int(request.args.get('hours', 24)))
    since = time.time() - hours * 3600
    points = []
    try:
        with open(os.path.join(c.get('data_dir', '/var/lib/argus'),
                               'metrics.jsonl'), encoding='utf-8') as fh:
            for line in fh:
                try:
                    p = json.loads(line)
                except ValueError:
                    continue
                if p.get('ts', 0) >= since:
                    points.append(p)
    except OSError:
        pass
    return jsonify({'points': points})


@app.route('/atop.json')
def atop_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    try:
        hours = int(request.args.get('hours', 24))
    except ValueError:
        hours = 24
    return jsonify({'points': atop.history(min(24 * 28, max(1, hours)))})


@app.route('/live.json')
def live_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    return jsonify(atop.live_sample())


@app.route('/proc.json')
def proc_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    return jsonify(atop.process_top())


@app.route('/claude.json')
def claude_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    return jsonify(claude.status())


@app.route('/visits.json')
def visits_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    try:
        days = int(request.args.get('days', 14))
    except ValueError:
        days = 14
    return jsonify(weblog.summary(min(365, max(1, days))))


@app.route('/visitors.json')
def visitors_json():
    if not _auth_ok(request):
        return jsonify({'error': 'auth'}), 401
    return jsonify(weblog.recent_visitors(48))


@app.route('/health')
def health():
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8085)
