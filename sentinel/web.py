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

app = Flask(__name__)
CONFIG_PATH = os.environ.get('SENTINEL_CONFIG', '/root/aiops-sentinel/local/config.json')


def cfg():
    with open(CONFIG_PATH, encoding='utf-8') as fh:
        return json.load(fh)


def _sign(value, secret):
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def _auth_ok(req):
    c = cfg()
    token = req.cookies.get('sentinel_auth', '')
    if '|' not in token:
        return False
    payload, sig = token.rsplit('|', 1)
    if not hmac.compare_digest(_sign(payload, c['web_secret']), sig):
        return False
    try:
        email, exp = payload.rsplit(':', 1)
        return email == c['web_email'] and float(exp) > time.time()
    except ValueError:
        return False


LOGIN_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Мониторинг — вход</title><style>
body{font-family:system-ui;display:flex;justify-content:center;align-items:center;
height:100vh;margin:0;background:#0f172a;color:#e2e8f0}
form{background:#1e293b;padding:2rem;border-radius:12px;min-width:300px}
input{width:100%;padding:.6rem;margin:.4rem 0;border-radius:8px;border:1px solid #334155;
background:#0f172a;color:#e2e8f0;box-sizing:border-box}
button{width:100%;padding:.6rem;margin-top:.6rem;border:0;border-radius:8px;
background:#38bdf8;color:#0f172a;font-weight:600;cursor:pointer}
.err{color:#f87171}</style></head><body>
<form method="post"><h3>🛰 Мониторинг сервера</h3>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<input name="email" type="email" placeholder="email" required>
<input name="password" type="password" placeholder="пароль" required>
<button>Войти и запомнить это устройство</button></form></body></html>"""

DASH_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Мониторинг сервера</title><style>
body{font-family:system-ui;margin:0;background:#0f172a;color:#e2e8f0}
header{padding:1rem 1.5rem;background:#1e293b;display:flex;justify-content:space-between}
main{padding:1rem 1.5rem;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{background:#1e293b;border-radius:12px;padding:1rem}
.ok{color:#4ade80}.bad{color:#f87171}.warn{color:#fbbf24}
table{width:100%;border-collapse:collapse;font-size:.9rem}
td,th{padding:.35rem .5rem;border-bottom:1px solid #334155;text-align:left}
small{color:#94a3b8}h4{margin:.2rem 0 .6rem}</style></head><body>
<header><b>🛰 Мониторинг сервера</b>
<small>снимок: {{ snap.ts }} · автообновление 60 с ·
инцидентов открыто: {{ open_count }}</small></header><main>
<div class="grid">
<div class="card"><h4>Ресурсы</h4>
Диск: <b class="{{ 'bad' if snap.resources.disk_used_pct >= 90 else 'ok' }}">{{ snap.resources.disk_used_pct }}%</b><br>
Память свободна: <b class="{{ 'warn' if snap.resources.mem_available_pct <= 10 else 'ok' }}">{{ snap.resources.mem_available_pct }}%</b><br>
Загрузка/ядро: <b class="{{ 'warn' if snap.resources.load1_per_core >= 2 else 'ok' }}">{{ snap.resources.load1_per_core }}</b></div>
{% for name, c in snap.containers.items() %}{% if name in watch %}
<div class="card"><h4>🐳 {{ name }}</h4>
<span class="{{ 'ok' if c.running else 'bad' }}">{{ '● работает' if c.running else '■ остановлен' }}</span><br>
<small>{{ c.status }}</small></div>
{% endif %}{% endfor %}
{% for url, r in snap.http.items() %}
<div class="card"><h4>🌐 {{ url.replace('https://','').replace('http://','')[:34] }}</h4>
<span class="{{ 'ok' if r.ok else 'bad' }}">{{ r.code or 'нет ответа' }}</span>
· {{ r.ms }} мс{% if r.error %}<br><small>{{ r.error[:60] }}</small>{% endif %}
{% if uptime.get(url) is not none %}<br><small title="Доля успешных проверок за 24 часа">аптайм 24ч: <b class="{{ 'ok' if uptime[url] >= 99 else 'warn' }}">{{ uptime[url] }}%</b></small>{% endif %}
{% set host = url.split('/')[2].split(':')[0] %}
{% if snap.certs and snap.certs.get(host) is not none %}<br><small title="Дней до истечения TLS-сертификата">SSL: <b class="{{ 'ok' if snap.certs[host] > 14 else 'warn' }}">{{ snap.certs[host] }} дн.</b></small>{% endif %}</div>
{% endfor %}
</div>
<div class="card" style="margin-top:14px">
<h4>Графики ресурсов
<span style="float:right;font-size:.85rem">
<a href="#" class="rng" data-h="24" style="color:#38bdf8">24 ч</a> ·
<a href="#" class="rng" data-h="168" style="color:#38bdf8">7 дн</a> ·
<a href="#" class="rng" data-h="720" style="color:#38bdf8">30 дн</a></span></h4>
<canvas id="g-load" height="80"></canvas>
<canvas id="g-mem" height="80"></canvas>
<canvas id="g-disk" height="80"></canvas>
<canvas id="g-http" height="80"></canvas>
<small>Точка — один цикл агента (5 минут). Отклик — только успешные проверки.</small>
</div>
<script>
function drawChart(id, label, series, color, ymax) {
  var cv = document.getElementById(id), ctx = cv.getContext('2d');
  cv.width = cv.parentElement.clientWidth - 32;
  var W = cv.width, H = cv.height, pad = 34;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#94a3b8'; ctx.font = '11px system-ui';
  ctx.fillText(label, pad, 12);
  if (!series.length) { ctx.fillText('нет данных', pad, H/2); return; }
  var xs = series.map(function (p) { return p[0]; });
  var ys = series.map(function (p) { return p[1]; });
  var x0 = Math.min.apply(0, xs), x1 = Math.max.apply(0, xs);
  var y1 = ymax || Math.max(1, Math.max.apply(0, ys) * 1.15);
  ctx.strokeStyle = '#334155';
  ctx.beginPath(); ctx.moveTo(pad, H-16); ctx.lineTo(W-4, H-16); ctx.stroke();
  ctx.fillText('0', 4, H-16); ctx.fillText(String(Math.round(y1)), 4, 22);
  ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.beginPath();
  series.forEach(function (p, i) {
    var x = pad + (W-pad-8) * (p[0]-x0) / Math.max(1, x1-x0);
    var y = (H-20) - (H-36) * Math.min(p[1], y1) / y1;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  var d0 = new Date(x0*1000), d1 = new Date(x1*1000);
  ctx.fillText(d0.toLocaleString('ru', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}), pad, H-3);
  var t1 = d1.toLocaleString('ru', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  ctx.fillText(t1, W - ctx.measureText(t1).width - 6, H-3);
}
function loadMetrics(hours) {
  fetch('metrics.json?hours=' + hours).then(function (r) { return r.json(); })
    .then(function (d) {
      var pts = d.points || [];
      drawChart('g-load', 'Загрузка на ядро (LA1/core)',
        pts.map(function (p) { return [p.ts, p.load1_per_core]; }), '#38bdf8');
      drawChart('g-mem', 'Свободная память, %',
        pts.map(function (p) { return [p.ts, p.mem_available_pct]; }), '#4ade80', 100);
      drawChart('g-disk', 'Диск занят, %',
        pts.map(function (p) { return [p.ts, p.disk_used_pct]; }), '#fbbf24', 100);
      var http = [];
      pts.forEach(function (p) {
        var vals = Object.values(p.http_ms || {});
        if (vals.length) http.push([p.ts, Math.max.apply(0, vals)]);
      });
      drawChart('g-http', 'Худший отклик сайтов, мс', http, '#f87171');
    });
}
document.querySelectorAll('.rng').forEach(function (a) {
  a.onclick = function (e) { e.preventDefault(); loadMetrics(a.dataset.h); };
});
loadMetrics(24);
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
Агент <b>aiops-sentinel</b> запускается по расписанию каждые 5 минут и делает
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
списка с кулдаунами. Агент: aiops-sentinel.</small></div>
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
                resp.set_cookie('sentinel_auth',
                                payload + '|' + _sign(payload, c['web_secret']),
                                max_age=365 * 86400, httponly=True,
                                secure=True, samesite='Lax')
                return resp
            error = 'Неверный email или пароль.'
        return render_template_string(LOGIN_HTML, error=error)

    data_dir = c.get('data_dir', '/var/lib/aiops-sentinel')
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
    data_dir = c.get('data_dir', '/var/lib/aiops-sentinel')
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
        with open(os.path.join(c.get('data_dir', '/var/lib/aiops-sentinel'),
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


@app.route('/health')
def health():
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8085)
