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
        email, exp = payload.split(';')
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
<div class="card"><h4>🌐 {{ url.replace('https://','')[:34] }}</h4>
<span class="{{ 'ok' if r.ok else 'bad' }}">{{ r.code or 'нет ответа' }}</span>
· {{ r.ms }} мс{% if r.error %}<br><small>{{ r.error[:60] }}</small>{% endif %}</div>
{% endfor %}
</div>
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
                payload = f'{email};{time.time() + 365 * 86400}'
                resp = make_response(redirect('/'))
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
                                  watch=c.get('watch_containers', []))


@app.route('/health')
def health():
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8085)
