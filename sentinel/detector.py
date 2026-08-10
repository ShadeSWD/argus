# -*- coding: utf-8 -*-
"""Детектор инцидентов: правила поверх снимка фактов.

Каждый инцидент: {'key': стабильный ключ для дедупликации, 'severity':
'critical'|'warning', 'title', 'evidence': компактные факты для LLM}.
"""
ERROR_MARKERS = ('Traceback', 'ERROR', 'CRITICAL', 'FATAL',
                 ' 500 ', ' 502 ', ' 503 ', 'OperationalError')


def detect(snapshot, config):
    incidents = []
    watch = config.get('watch_containers', [])
    containers = snapshot.get('containers', {})

    for name in watch:
        c = containers.get(name)
        if c is None:
            incidents.append({'key': f'container-missing:{name}',
                              'severity': 'critical',
                              'title': f'Контейнер {name} отсутствует',
                              'evidence': {'containers': list(containers)}})
        elif not c['running']:
            incidents.append({'key': f'container-down:{name}',
                              'severity': 'critical',
                              'title': f'Контейнер {name} не запущен',
                              'evidence': {'status': c['status'],
                                           'log_tail': snapshot['logs'].get(name, '')[-2000:]}})

    for url, r in snapshot.get('http', {}).items():
        if not r['ok']:
            incidents.append({'key': f'http-fail:{url}', 'severity': 'critical',
                              'title': f'HTTP-проверка не прошла: {url}',
                              'evidence': {'code': r['code'], 'error': r['error'],
                                           'ms': r['ms']}})
        elif r['ms'] > config.get('slow_ms', 8000):
            incidents.append({'key': f'http-slow:{url}', 'severity': 'warning',
                              'title': f'Медленный ответ ({r["ms"]} мс): {url}',
                              'evidence': {'ms': r['ms']}})

    res = snapshot.get('resources', {})
    if res.get('disk_used_pct', 0) >= config.get('disk_pct_max', 90):
        incidents.append({'key': 'disk-full', 'severity': 'critical',
                          'title': f'Диск заполнен на {res["disk_used_pct"]}%',
                          'evidence': res})
    if res.get('mem_available_pct', 100) <= config.get('mem_available_pct_min', 5):
        incidents.append({'key': 'mem-low', 'severity': 'warning',
                          'title': f'Свободной памяти {res["mem_available_pct"]}%',
                          'evidence': res})
    if res.get('load1_per_core', 0) >= config.get('load_per_core_max', 4):
        incidents.append({'key': 'load-high', 'severity': 'warning',
                          'title': f'Загрузка {res["load1_per_core"]} на ядро',
                          'evidence': res})

    for host, days in snapshot.get('certs', {}).items():
        if days is not None and days <= config.get('cert_days_min', 14):
            incidents.append({'key': f'cert-expiring:{host}',
                              'severity': 'warning',
                              'title': f'Сертификат {host} истекает через {days} дн.',
                              'evidence': {'days_left': days}})

    for name, log in snapshot.get('logs', {}).items():
        errors = [ln for ln in log.splitlines()
                  if any(m in ln for m in ERROR_MARKERS)]
        if len(errors) >= config.get('log_errors_min', 5):
            incidents.append({'key': f'log-errors:{name}', 'severity': 'warning',
                              'title': f'Всплеск ошибок в логах {name} '
                                       f'({len(errors)} строк)',
                              'evidence': {'sample': errors[:15]}})
    return incidents
