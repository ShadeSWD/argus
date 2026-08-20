# -*- coding: utf-8 -*-
"""Статус Claude Code: потребление токенов, подписка, срок авторизации.

Источник — локальные транскрипты Claude Code (~/.claude/projects/**/*.jsonl):
у каждого ответа ассистента есть `usage` (input/output/cache) + `model` +
`timestamp`. Ничего наружу не уходит. Подписка и срок токена — из
~/.claude/.credentials.json (значения токенов НЕ читаем и НЕ отдаём, только
тип подписки, tier и даты истечения).

«Остатка лимита» в локальных файлах нет (Claude Max — оконные лимиты, не
баланс токенов), поэтому показываем ПОТРЕБЛЕНИЕ по скользящим окнам
(5 часов — как окно тарифа, сутки, 7 и 30 дней, всё время) — это честный
измеримый прокси. Стоимость — гипотетический эквивалент по ценам API
(подписка их не тарифицирует), для понимания объёма.

Кэш: посуточные агрегаты каждого файла кэшируются по (size, mtime) в
/var/lib/argus/claude-cache/ — переразбирается только изменившийся файл.
5-часовое окно считается живым проходом лишь по недавно менявшимся файлам.
"""
import datetime
import glob
import json
import os
import time

PROJECTS = os.path.expanduser('~/.claude/projects')
CREDS = os.path.expanduser('~/.claude/.credentials.json')
CACHE_DIR = '/var/lib/argus/claude-cache'

# цены API за 1M токенов: (input, output, cache_write, cache_read); None — не тарифицируем
PRICES = {
    'Opus':   (15.0, 75.0, 18.75, 1.50),
    'Sonnet': (3.0, 15.0, 3.75, 0.30),
    'Haiku':  (0.80, 4.0, 1.0, 0.08),
    'Fable':  None,          # цена не публикуется — считаем только токены
}


def _model(name):
    n = (name or '').lower()
    if '<synthetic>' in n or not n:
        return None
    for key in ('opus', 'sonnet', 'haiku', 'fable'):
        if key in n:
            return key.capitalize()
    return name[:16]


def _cost(model, u):
    p = PRICES.get(model)
    if not p:
        return 0.0
    return (u['in'] * p[0] + u['out'] * p[1] +
            u['cw'] * p[2] + u['cr'] * p[3]) / 1_000_000


def _zero():
    return {'in': 0, 'out': 0, 'cw': 0, 'cr': 0, 'msgs': 0}


def _add(dst, u):
    for k in ('in', 'out', 'cw', 'cr', 'msgs'):
        dst[k] += u[k]


def _usage(rec):
    m = rec.get('message', {})
    if rec.get('type') != 'assistant' or 'usage' not in m:
        return None
    u = m['usage']
    model = _model(m.get('model'))
    if model is None:
        return None
    return model, {
        'in': u.get('input_tokens', 0) or 0,
        'out': u.get('output_tokens', 0) or 0,
        'cw': u.get('cache_creation_input_tokens', 0) or 0,
        'cr': u.get('cache_read_input_tokens', 0) or 0,
        'msgs': 1,
    }


def _ts(rec):
    t = rec.get('timestamp')
    if not t:
        return None
    try:
        # ISO 8601 c 'Z'
        dt = datetime.datetime.strptime(t[:19], '%Y-%m-%dT%H:%M:%S')
        return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None


def _file_days(path):
    """Посуточные агрегаты одного транскрипта: date -> model -> counters.
    Кэшируется по (size, mtime); активный/недавний файл переразбирается."""
    try:
        st = os.stat(path)
    except OSError:
        return {}
    key = '%d:%d' % (st.st_size, int(st.st_mtime))
    cache = os.path.join(CACHE_DIR, os.path.basename(path) + '.json')
    # файл, менявшийся за последний час, всегда парсим заново (растёт)
    fresh = time.time() - st.st_mtime < 3600
    if not fresh:
        try:
            with open(cache, encoding='utf-8') as fh:
                c = json.load(fh)
            if c.get('key') == key:
                return c['days']
        except (OSError, ValueError):
            pass
    days = {}
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                if '"usage"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                uu = _usage(rec)
                ts = _ts(rec)
                if not uu or ts is None:
                    continue
                model, u = uu
                date = time.strftime('%Y-%m-%d', time.localtime(ts))
                d = days.setdefault(date, {})
                _add(d.setdefault(model, _zero()), u)
    except OSError:
        return {}
    if not fresh:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            tmp = cache + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump({'key': key, 'days': days}, fh)
            os.replace(tmp, cache)
        except OSError:
            pass
    return days


def _recent_events(hours):
    """Живой проход по недавно менявшимся файлам для скользящего окна."""
    since = time.time() - hours * 3600
    ev = []
    for path in glob.glob(os.path.join(PROJECTS, '**', '*.jsonl'), recursive=True):
        try:
            if os.path.getmtime(path) < since:
                continue
        except OSError:
            continue
        try:
            with open(path, encoding='utf-8') as fh:
                for line in fh:
                    if '"usage"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    ts = _ts(rec)
                    uu = _usage(rec)
                    if ts is None or not uu or ts < since:
                        continue
                    ev.append((ts, uu[0], uu[1]))
        except OSError:
            continue
    return ev


def _window_from_days(all_days, since_date):
    """Свернуть посуточные агрегаты от since_date (вкл.) по моделям."""
    by_model = {}
    for date, models in all_days.items():
        if date < since_date:
            continue
        for model, u in models.items():
            _add(by_model.setdefault(model, _zero()), u)
    return by_model


def _pack(by_model):
    tot = _zero()
    cost = 0.0
    for model, u in by_model.items():
        _add(tot, u)
        cost += _cost(model, u)
    return {
        'input': tot['in'], 'output': tot['out'],
        'cache_write': tot['cw'], 'cache_read': tot['cr'],
        'total': tot['in'] + tot['out'] + tot['cw'] + tot['cr'],
        'msgs': tot['msgs'], 'cost_usd': round(cost, 2),
    }


def _subscription():
    out = {'type': None, 'tier': None, 'access_days': None,
           'refresh_days': None, 'refresh_date': None}
    try:
        c = json.load(open(CREDS, encoding='utf-8')).get('claudeAiOauth', {})
    except (OSError, ValueError):
        return out
    out['type'] = c.get('subscriptionType')
    out['tier'] = c.get('rateLimitTier')
    now = time.time()
    for src, dst in (('expiresAt', 'access_days'),
                     ('refreshTokenExpiresAt', 'refresh_days')):
        v = c.get(src)
        if v:
            out[dst] = round(v / 1000 - now) / 86400.0
    rt = c.get('refreshTokenExpiresAt')
    if rt:
        out['refresh_date'] = time.strftime('%Y-%m-%d %H:%M',
                                             time.localtime(rt / 1000))
    return out


_memo = {'ts': 0.0, 'data': None}


def status():
    """Полный статус для дашборда (память-кэш 60 с)."""
    if _memo['data'] is not None and time.time() - _memo['ts'] < 60:
        return _memo['data']
    data = _status_uncached()
    _memo.update(ts=time.time(), data=data)
    return data


def _status_uncached():
    all_days = {}
    for path in glob.glob(os.path.join(PROJECTS, '**', '*.jsonl'), recursive=True):
        for date, models in _file_days(path).items():
            dd = all_days.setdefault(date, {})
            for model, u in models.items():
                _add(dd.setdefault(model, _zero()), u)

    today = time.strftime('%Y-%m-%d')
    d7 = time.strftime('%Y-%m-%d', time.localtime(time.time() - 7 * 86400))
    d30 = time.strftime('%Y-%m-%d', time.localtime(time.time() - 30 * 86400))

    windows = {
        'today': _pack(_window_from_days(all_days, today)),
        'last7d': _pack(_window_from_days(all_days, d7)),
        'last30d': _pack(_window_from_days(all_days, d30)),
        'all': _pack(_window_from_days(all_days, '0000')),
    }
    # скользящее 5-часовое окно — живой проход
    win5 = {}
    for _ts_, model, u in _recent_events(5):
        _add(win5.setdefault(model, _zero()), u)
    windows['last5h'] = _pack(win5)

    by_model = {m: _pack({m: u})
                for m, u in _window_from_days(all_days, d30).items()}
    daily = []
    for i in range(29, -1, -1):
        date = time.strftime('%Y-%m-%d', time.localtime(time.time() - i * 86400))
        p = _pack(all_days.get(date, {}))
        daily.append({'date': date, 'total': p['total'], 'output': p['output']})

    return {'windows': windows, 'by_model': by_model, 'daily': daily,
            'subscription': _subscription(),
            'days_tracked': len(all_days)}
