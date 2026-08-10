# -*- coding: utf-8 -*-
"""Источники данных для графиков ресурсов.

История — бинарные журналы atop (/var/log/atop, снимок каждые 10 минут,
хранятся 28 суток): разбираем parseable-вывод `atop -r FILE -P CPU,MEM,DSK,NET`.
Закрытые дни неизменяемы — их разбор кэшируется на диске; сегодняшний файл
кэшируется в памяти по mtime.

«Живые» графики — те же счётчики ядра, которые читает btop (/proc/stat,
/proc/meminfo, /proc/net/dev, /proc/diskstats); btop собственной истории
не пишет, поэтому клиент опрашивает эндпоинт и считает дельты сам.
"""
import datetime
import json
import os
import re
import subprocess
import time

ATOP_DIR = '/var/log/atop'
CACHE_DIR = '/var/lib/argus/atop-cache'
MAX_INTERVAL = 1900          # снимки длиннее (счётчики с загрузки) пропускаем
_VIRTUAL_IFACE = re.compile(r'^(lo|veth|br-|docker|virbr)')
_PHYS_DISK = re.compile(r'^(sd[a-z]+|vd[a-z]+|nvme\d+n\d+|xvd[a-z]+)$')

_today_cache = {'path': None, 'mtime': 0, 'points': []}


def _parse_atop_file(path):
    """Один суточный файл atop → список точек для графиков."""
    try:
        out = subprocess.run(
            ['atop', '-r', path, '-P', 'CPU,MEM,DSK,NET'],
            capture_output=True, text=True, timeout=60).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    points = []
    cur = {}

    def flush():
        if cur.get('skip') or 'ts' not in cur or 'cpu_pct' not in cur:
            cur.clear()
            return
        points.append({
            'ts': cur['ts'],
            'cpu_pct': cur['cpu_pct'],
            'iowait_pct': cur.get('iowait_pct', 0),
            'mem_pct': cur.get('mem_pct', 0),
            'disk_busy_pct': round(cur.get('disk_ms', 0) / cur['iv'] / 10, 1),
            'disk_r_kbps': round(cur.get('sect_r', 0) * 512 / 1024 / cur['iv'], 1),
            'disk_w_kbps': round(cur.get('sect_w', 0) * 512 / 1024 / cur['iv'], 1),
            'net_rx_kbps': round(cur.get('rx', 0) / 1024 / cur['iv'], 1),
            'net_tx_kbps': round(cur.get('tx', 0) / 1024 / cur['iv'], 1),
        })
        cur.clear()

    for line in out.splitlines():
        if line in ('SEP', 'RESET'):
            flush()
            continue
        t = line.split()
        if len(t) < 7:
            continue
        label, iv = t[0], int(t[5])
        if iv <= 0 or iv > MAX_INTERVAL:
            cur['skip'] = True
            continue
        cur.setdefault('ts', int(t[2]))
        cur.setdefault('iv', iv)
        if label == 'CPU':
            ticks, ncpu = int(t[6]), int(t[7])
            total = iv * ticks * ncpu
            idle, wait = int(t[11]), int(t[12])
            cur['cpu_pct'] = round(100 * max(0, total - idle - wait) / total, 1)
            cur['iowait_pct'] = round(100 * wait / total, 1)
        elif label == 'MEM':
            phys, free, cache, buf = int(t[7]), int(t[8]), int(t[9]), int(t[10])
            if phys:
                cur['mem_pct'] = round(100 * (phys - free - cache - buf) / phys, 1)
        elif label == 'DSK' and _PHYS_DISK.match(t[6]):
            cur['disk_ms'] = cur.get('disk_ms', 0) + int(t[7])
            cur['sect_r'] = cur.get('sect_r', 0) + int(t[9])
            cur['sect_w'] = cur.get('sect_w', 0) + int(t[11])
        elif label == 'NET' and t[6] != 'upper' and not _VIRTUAL_IFACE.match(t[6]):
            cur['rx'] = cur.get('rx', 0) + int(t[8])
            cur['tx'] = cur.get('tx', 0) + int(t[10])
    flush()
    return points


def _day_points(day):
    """Точки за сутки YYYYMMDD: закрытый день — из дискового кэша."""
    path = os.path.join(ATOP_DIR, 'atop_' + day)
    if not os.path.exists(path):
        return []
    if day == time.strftime('%Y%m%d'):
        mtime = os.path.getmtime(path)
        if _today_cache['path'] != path or _today_cache['mtime'] != mtime:
            _today_cache.update(path=path, mtime=mtime,
                                points=_parse_atop_file(path))
        return _today_cache['points']
    cache = os.path.join(CACHE_DIR, day + '.json')
    try:
        with open(cache, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        pass
    points = _parse_atop_file(path)
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = cache + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(points, fh)
        os.replace(tmp, cache)
    except OSError:
        pass
    return points


def history(hours):
    """Точки atop за последние N часов (по всем нужным суточным файлам)."""
    since = time.time() - hours * 3600
    day = datetime.date.fromtimestamp(since)
    today = datetime.date.today()
    points = []
    while day <= today:
        points.extend(_day_points(day.strftime('%Y%m%d')))
        day += datetime.timedelta(days=1)
    return [p for p in points if p['ts'] >= since]


_INTERP = ('python', 'python3', 'node', 'java', 'php', 'bash', 'sh', 'perl')
_proc_prev = {'ts': 0.0, 'cpu': {}, 'io': {}}


def _proc_name(pid, comm):
    """Читаемое имя: для интерпретаторов дописываем скрипт из cmdline."""
    if comm not in _INTERP:
        return comm
    try:
        with open('/proc/%s/cmdline' % pid, 'rb') as fh:
            args = fh.read().decode(errors='replace').split('\0')
    except OSError:
        return comm
    for a in args[1:]:
        if a and not a.startswith('-'):
            return (comm + ' ' + os.path.basename(a))[:34]
    return comm


def process_top(limit=8):
    """«Диспетчер задач»: топ процессов по CPU, памяти и диску.

    CPU и дисковый I/O — дельты к предыдущему вызову в этом же процессе
    (первый вызов воркера отдаёт нули, клиент опрашивает часто)."""
    now = time.time()
    hz = os.sysconf('SC_CLK_TCK')
    page = os.sysconf('SC_PAGE_SIZE')
    procs, cpu_now, io_now = [], {}, {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % pid) as fh:
                st = fh.read()
            rp = st.rindex(')')
            comm = st[st.index('(') + 1:rp]
            f = st[rp + 2:].split()
            ticks = int(f[11]) + int(f[12])          # utime + stime
            with open('/proc/%s/statm' % pid) as fh:
                rss_pages = int(fh.read().split()[1])
        except (OSError, ValueError, IndexError):
            continue
        rb = wb = 0
        try:
            with open('/proc/%s/io' % pid) as fh:
                for ln in fh:
                    if ln.startswith('read_bytes:'):
                        rb = int(ln.split()[1])
                    elif ln.startswith('write_bytes:'):
                        wb = int(ln.split()[1])
        except OSError:
            pass
        p = int(pid)
        cpu_now[p] = ticks
        io_now[p] = rb + wb
        procs.append({'pid': p, 'name': _proc_name(pid, comm),
                      'rss_mb': round(rss_pages * page / 1048576, 1)})
    dt = now - _proc_prev['ts']
    fresh = 0 < dt < 600
    for p in procs:
        prev = _proc_prev['cpu'].get(p['pid'])
        p['cpu_pct'] = (round(100 * (cpu_now[p['pid']] - prev) / hz / dt, 1)
                        if fresh and prev is not None else 0.0)
        pio = _proc_prev['io'].get(p['pid'])
        p['io_kbps'] = (round((io_now[p['pid']] - pio) / 1024 / dt, 1)
                        if fresh and pio is not None else 0.0)
    _proc_prev.update(ts=now, cpu=cpu_now, io=io_now)
    return {'ts': now, 'total': len(procs),
            'cpu': sorted(procs, key=lambda p: -p['cpu_pct'])[:limit],
            'mem': sorted(procs, key=lambda p: -p['rss_mb'])[:limit],
            'io': sorted(procs, key=lambda p: -p['io_kbps'])[:limit]}


def live_sample():
    """Сырые счётчики ядра для живых графиков; дельты считает клиент."""
    cpus = []
    with open('/proc/stat') as fh:
        for line in fh:
            if re.match(r'^cpu\d+ ', line):
                v = [int(x) for x in line.split()[1:]]
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                cpus.append([sum(v) - idle, sum(v)])
    mem_total = mem_avail = 0
    with open('/proc/meminfo') as fh:
        for line in fh:
            if line.startswith('MemTotal:'):
                mem_total = int(line.split()[1])
            elif line.startswith('MemAvailable:'):
                mem_avail = int(line.split()[1])
    rx = tx = 0
    with open('/proc/net/dev') as fh:
        for line in fh:
            if ':' not in line:
                continue
            name, rest = line.split(':', 1)
            if _VIRTUAL_IFACE.match(name.strip()):
                continue
            v = rest.split()
            rx += int(v[0])
            tx += int(v[8])
    sect_r = sect_w = 0
    with open('/proc/diskstats') as fh:
        for line in fh:
            v = line.split()
            if len(v) >= 10 and _PHYS_DISK.match(v[2]):
                sect_r += int(v[5])
                sect_w += int(v[9])
    return {'ts': time.time(), 'cpus': cpus,
            'mem_total_kb': mem_total, 'mem_avail_kb': mem_avail,
            'net_rx_bytes': rx, 'net_tx_bytes': tx,
            'disk_read_sect': sect_r, 'disk_write_sect': sect_w}
