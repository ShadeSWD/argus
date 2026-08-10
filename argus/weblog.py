# -*- coding: utf-8 -*-
"""Аналитика посещений сайтов из access-логов nginx — без вмешательства в БД.

Никаких счётчиков в приложениях и таблиц в базах: источник — общий
/var/log/nginx/access.log (+ ротированные .gz, 14 дней). Список сайтов
определяется автоматически по location-префиксам nginx-конфига — новый сайт
появляется в статистике сам. Суточные агрегаты замораживаются в
/var/lib/argus/weblog/YYYY-MM-DD.json (крошечные файлы) и переживают
ротацию логов и переезд сайтов. Гео — офлайн-база DB-IP (country.mmdb),
наружу ничего не отправляется.
"""
import glob
import gzip
import hashlib
import json
import os
import re
import time

LOG_GLOB = '/var/log/nginx/access.log*'
NGINX_SITE_CONF = '/etc/nginx/sites-available/duckdns'
DATA_DIR = '/var/lib/argus/weblog'
CACHE_DIR = '/var/lib/argus/weblog-cache'
GEO_DB = '/var/lib/argus/geo/country.mmdb'

_LINE = re.compile(r'^(\S+) \S+ \S+ \[(\d+)/(\w+)/(\d+):(\d+):\d+:\d+ [^\]]*\] '
                   r'"(\S+) (\S+)[^"]*" (\d+) \d+ "([^"]*)" "([^"]*)"')
_MON = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
_BOT = re.compile(r'bot|crawl|spider|slurp|preview|scan|curl|wget|python|'
                  r'go-http|httpclient|java|libwww|okhttp|zgrab|censys|'
                  r'argus|aiops|uptime|monitor', re.I)
_ASSET = re.compile(r'\.(css|js|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|map|webp|'
                    r'gpx|json|txt|xml)(\?|$)|^/map/api/|/static/|/favicon',
                    re.I)

_sites_cache = {'mtime': 0, 'sites': set()}
_geo = {'reader': None, 'tried': False, 'cache': {}}
_cur = {}          # кэш разбора незакрытых логов: path → {'key','days','visitors'}


def sites():
    """Сайты = location-префиксы nginx-конфига (без monitor и служебных)."""
    try:
        mtime = os.path.getmtime(NGINX_SITE_CONF)
        if mtime != _sites_cache['mtime']:
            with open(NGINX_SITE_CONF, encoding='utf-8') as fh:
                found = set(re.findall(r'location\s+/(\w[\w-]*)/\s*{', fh.read()))
            _sites_cache.update(mtime=mtime,
                                sites=found - {'monitor', 'sitechat'})
    except OSError:
        pass
    return _sites_cache['sites']


def _country(ip):
    if ip in _geo['cache']:
        return _geo['cache'][ip]
    if _geo['reader'] is None and not _geo['tried']:
        _geo['tried'] = True
        try:
            import maxminddb
            _geo['reader'] = maxminddb.open_database(GEO_DB)
        except Exception:
            pass
    cc = '?'
    if _geo['reader'] is not None:
        try:
            rec = _geo['reader'].get(ip)
            cc = rec['country']['iso_code'] if rec else '?'
        except Exception:
            cc = '?'
    if len(_geo['cache']) > 50000:
        _geo['cache'].clear()
    _geo['cache'][ip] = cc
    return cc


def _browser(ua):
    for pat, name in (('YaBrowser', 'Яндекс'), ('Edg', 'Edge'),
                      ('OPR', 'Opera'), ('SamsungBrowser', 'Samsung'),
                      ('Firefox', 'Firefox'), ('Chrome', 'Chrome'),
                      ('Safari', 'Safari')):
        if pat in ua:
            break
    else:
        return (ua.split('/')[0][:20] or '?')
    dev = ' 📱' if ('Android' in ua or 'iPhone' in ua or 'Mobile' in ua) else ''
    return name + dev


def _classify(path):
    seg = path.split('/')[1].split('?')[0] if path.startswith('/') else ''
    return seg if seg in sites() else 'другое'


def _new_day():
    return {'hits': 0, 'views': 0, 'bots': 0, 'visitors': set(),
            'sites': {}, 'pages': {}, 'countries': {}, 'referers': {}}


def _parse(path):
    """Файл лога → (по-дням агрегаты, по-посетителям детали)."""
    days, visitors = {}, {}
    opener = gzip.open if path.endswith('.gz') else open
    try:
        with opener(path, 'rt', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                m = _LINE.match(line)
                if not m:
                    continue
                (ip, dd, mon, yy, hh, method, url, status,
                 referer, ua) = m.groups()
                if method not in ('GET', 'POST') or ua in ('argus', '-'):
                    continue
                if url.startswith('/monitor'):     # свой дашборд не считаем
                    continue
                site = _classify(url)
                date = '%s-%02d-%s' % (yy, _MON.get(mon, 0), dd)
                d = days.setdefault(date, _new_day())
                d['hits'] += 1
                bot = bool(_BOT.search(ua))
                if bot:
                    d['bots'] += 1
                vid = ip + '|' + hashlib.md5(ua.encode()).hexdigest()[:8]
                page = int(status) < 400 and not _ASSET.search(url)
                if not bot:
                    s = d['sites'].setdefault(site, {'hits': 0, 'views': 0,
                                                     'visitors': set()})
                    s['hits'] += 1
                    d['visitors'].add(vid)
                    s['visitors'].add(vid)
                    if page:
                        d['views'] += 1
                        s['views'] += 1
                        p = url.split('?')[0][:80]
                        d['pages'][p] = d['pages'].get(p, 0) + 1
                        cc = _country(ip)
                        d['countries'][cc] = d['countries'].get(cc, 0) + 1
                        if referer not in ('-', '') and 'shadeswd' not in referer:
                            rhost = referer.split('/')[2][:40] if '://' in referer else referer[:40]
                            d['referers'][rhost] = d['referers'].get(rhost, 0) + 1
                # детали посетителей (люди и боты — фильтруем при выдаче)
                ts = time.mktime((int(yy), _MON.get(mon, 1), int(dd),
                                  int(hh), 0, 0, 0, 0, -1))
                v = visitors.setdefault(vid, {
                    'ip': ip, 'ua': ua[:120], 'bot': bot, 'hits': 0,
                    'views': 0, 'sites': set(), 'pages': {},
                    'first': ts, 'last': ts})
                v['hits'] += 1
                v['last'] = max(v['last'], ts)
                v['first'] = min(v['first'], ts)
                if page:
                    v['views'] += 1
                    v['sites'].add(site)
                    p = url.split('?')[0][:80]
                    v['pages'][p] = v['pages'].get(p, 0) + 1
    except OSError:
        pass
    return days, visitors


def _jsonable(days):
    out = {}
    for date, d in days.items():
        out[date] = dict(d, visitors=sorted(d['visitors']),
                         sites={s: dict(v, visitors=sorted(v['visitors']))
                                for s, v in d['sites'].items()})
    return out


def _sets(days):
    for d in days.values():
        d['visitors'] = set(d['visitors'])
        for s in d['sites'].values():
            s['visitors'] = set(s['visitors'])
    return days


def _parse_cached(path):
    """Разбор с кэшем; ротированные файлы разбираются один раз."""
    try:
        st = os.stat(path)
    except OSError:
        return {}, {}
    key = '%d:%d' % (st.st_size, int(st.st_mtime))
    rotated = path.endswith('.gz')
    if rotated:
        cache = os.path.join(CACHE_DIR,
                             os.path.basename(path).replace('.gz', '') + '.json')
        try:
            with open(cache, encoding='utf-8') as fh:
                c = json.load(fh)
            if c.get('key') == key:
                return _sets(c['days']), {}
        except (OSError, ValueError):
            pass
    elif _cur.get(path, {}).get('key') == key:
        return _cur[path]['days'], _cur[path]['visitors']
    days, visitors = _parse(path)
    if rotated:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache, 'w', encoding='utf-8') as fh:
                json.dump({'key': key, 'days': _jsonable(days)}, fh,
                          ensure_ascii=False)
        except OSError:
            pass
    else:
        _cur[path] = {'key': key, 'days': days, 'visitors': visitors}
    return days, visitors


def _merge_day(dst, src):
    dst['hits'] += src['hits']
    dst['views'] += src['views']
    dst['bots'] += src['bots']
    dst['visitors'] |= src['visitors']
    for s, v in src['sites'].items():
        t = dst['sites'].setdefault(s, {'hits': 0, 'views': 0,
                                        'visitors': set()})
        t['hits'] += v['hits']
        t['views'] += v['views']
        t['visitors'] |= v['visitors']
    for k in ('pages', 'countries', 'referers'):
        for name, n in src[k].items():
            dst[k][name] = dst[k].get(name, 0) + n


def _collect_days():
    """Все дни из всех доступных логов + заморозка закрытых дней на диск."""
    merged = {}
    for path in sorted(glob.glob(LOG_GLOB)):
        days, _ = _parse_cached(path)
        for date, d in days.items():
            merged.setdefault(date, _new_day())
            _merge_day(merged[date], d)
    today = time.strftime('%Y-%m-%d')
    os.makedirs(DATA_DIR, exist_ok=True)
    for date, d in merged.items():
        frozen = os.path.join(DATA_DIR, date + '.json')
        if date < today and not os.path.exists(frozen):
            try:
                with open(frozen, 'w', encoding='utf-8') as fh:
                    json.dump(_jsonable({date: d})[date], fh, ensure_ascii=False)
            except OSError:
                pass
    # замороженные дни, чьи логи уже ушли в ротацию
    for frozen in glob.glob(os.path.join(DATA_DIR, '*.json')):
        date = os.path.basename(frozen)[:-5]
        if date not in merged:
            try:
                with open(frozen, encoding='utf-8') as fh:
                    merged[date] = _sets({date: json.load(fh)})[date]
            except (OSError, ValueError):
                pass
    return merged


def summary(days_back=14):
    """Сводка для дашборда: ряды по дням + топы за период."""
    since = time.strftime('%Y-%m-%d',
                          time.localtime(time.time() - days_back * 86400))
    total = _new_day()
    rows = []
    merged = _collect_days()
    for date in sorted(merged):
        if date < since:
            continue
        d = merged[date]
        _merge_day(total, d)
        rows.append({'date': date, 'visitors': len(d['visitors']),
                     'views': d['views'], 'bots': d['bots'],
                     'sites': {s: {'visitors': len(v['visitors']),
                                   'views': v['views']}
                               for s, v in d['sites'].items()}})
    top = lambda c, n: sorted(c.items(), key=lambda kv: -kv[1])[:n]
    return {'days': rows,
            'sites': sorted(total['sites']),
            'visitors': len(total['visitors']), 'views': total['views'],
            'bots': total['bots'],
            'pages': top(total['pages'], 12),
            'countries': top(total['countries'], 12),
            'referers': top(total['referers'], 10)}


def recent_visitors(hours=48, limit=25):
    """Последние посетители с их страницами («кто что тыкал»)."""
    since = time.time() - hours * 3600
    merged = {}
    for path in ('/var/log/nginx/access.log.1', '/var/log/nginx/access.log'):
        _, visitors = _parse_cached(path)
        for vid, v in visitors.items():
            if v['last'] < since:
                continue
            t = merged.setdefault(vid, {'ip': v['ip'], 'ua': v['ua'],
                                        'bot': v['bot'], 'hits': 0, 'views': 0,
                                        'sites': set(), 'pages': {},
                                        'first': v['first'], 'last': v['last']})
            t['hits'] += v['hits']
            t['views'] += v['views']
            t['sites'] |= v['sites']
            t['first'] = min(t['first'], v['first'])
            t['last'] = max(t['last'], v['last'])
            for p, n in v['pages'].items():
                t['pages'][p] = t['pages'].get(p, 0) + n
    humans = [v for v in merged.values() if not v['bot']]
    bots_hits = sum(v['hits'] for v in merged.values() if v['bot'])
    humans.sort(key=lambda v: -v['last'])
    out = []
    for v in humans[:limit]:
        out.append({'ip': v['ip'], 'country': _country(v['ip']),
                    'browser': _browser(v['ua']), 'hits': v['hits'],
                    'views': v['views'], 'sites': sorted(v['sites']),
                    'last': time.strftime('%d.%m %H:%M',
                                          time.localtime(v['last'])),
                    'pages': sorted(v['pages'].items(),
                                    key=lambda kv: -kv[1])[:8]})
    return {'visitors': out, 'bots_hits': bots_hits, 'humans': len(humans)}
