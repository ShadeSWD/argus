# -*- coding: utf-8 -*-
"""Сборщики фактов о системе: docker, HTTP-проверки, логи, ресурсы хоста.

Каждый сборщик возвращает обычные dict/list — детектор работает только
с этими фактами и никогда не ходит в систему сам (тестируемость).
"""
import datetime
import json
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request


def _run(cmd, timeout=20):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.returncode, out.stdout.strip(), out.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return -1, '', str(exc)


def docker_containers():
    """Состояние контейнеров: имя → {status, running, started_at}."""
    code, out, _ = _run(['docker', 'ps', '-a', '--format', '{{json .}}'])
    if code != 0:
        return {}
    result = {}
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        result[c.get('Names', '?')] = {
            'status': c.get('Status', ''),
            'running': c.get('State', '') == 'running',
            'image': c.get('Image', ''),
        }
    return result


def http_checks(urls, timeout=15):
    """Проверка эндпоинтов: url → {code, ms, ok, error}."""
    results = {}
    for url in urls:
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'aiops-sentinel'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                results[url] = {'code': resp.status,
                                'ms': int((time.time() - t0) * 1000),
                                'ok': 200 <= resp.status < 400, 'error': None}
        except Exception as exc:
            results[url] = {'code': None, 'ms': int((time.time() - t0) * 1000),
                            'ok': False, 'error': str(exc)[:200]}
    return results


def container_log_tail(name, since='10m', max_lines=120):
    """Хвост логов контейнера за интервал (для детектора и LLM-диагноза)."""
    code, out, err = _run(['docker', 'logs', '--since', since, '--tail',
                           str(max_lines), name], timeout=30)
    return (out + '\n' + err).strip() if code == 0 else ''


def host_resources():
    """Диск, память, загрузка."""
    disk = shutil.disk_usage('/')
    mem_total = mem_available = 0
    with open('/proc/meminfo') as fh:
        for line in fh:
            if line.startswith('MemTotal:'):
                mem_total = int(line.split()[1])
            elif line.startswith('MemAvailable:'):
                mem_available = int(line.split()[1])
    with open('/proc/loadavg') as fh:
        load1 = float(fh.read().split()[0])
    import os
    return {
        'disk_used_pct': round(100 * disk.used / disk.total, 1),
        'mem_available_pct': round(100 * mem_available / mem_total, 1) if mem_total else 0,
        'load1_per_core': round(load1 / (os.cpu_count() or 1), 2),
    }


def collect(config):
    """Полный снимок системы по конфигу."""
    snapshot = {
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'containers': docker_containers(),
        'http': http_checks(config.get('http_checks', [])),
        'resources': host_resources(),
        'logs': {},
    }
    snapshot['certs'] = cert_days_left(config.get('http_checks', []))
    for name in config.get('watch_containers', []):
        snapshot['logs'][name] = container_log_tail(
            name, since=config.get('log_since', '10m'))
    return snapshot


def cert_days_left(urls, timeout=10):
    """Дней до истечения TLS-сертификата по каждому https-хосту."""
    out = {}
    for url in urls:
        if not url.startswith('https://'):
            continue
        host = url.split('/')[2].split(':')[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    exp = tls.getpeercert()['notAfter']
            dt = datetime.datetime.strptime(exp, '%b %d %H:%M:%S %Y %Z')
            out[host] = (dt - datetime.datetime.utcnow()).days
        except Exception:
            out[host] = None
    return out
