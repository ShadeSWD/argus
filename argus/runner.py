# -*- coding: utf-8 -*-
"""Главный цикл агента: снимок → детект → дедуп → LLM-диагноз → ремедиация →
журнал и уведомление. Запускается по cron/systemd-таймеру.

Дедупликация: инцидент с тем же key не оповещается повторно, пока не
«закроется» (пропадёт из детекта) — тогда отправляется сообщение о
восстановлении.
"""
import json
import os
import subprocess
import sys
import time

from . import collectors, detector, llm, remediation


def load_config(path):
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


def _state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {'open': {}}


def notify(config, text):
    hook = config.get('notify_cmd')
    if not hook:
        return
    try:
        subprocess.run(hook + [text], timeout=60, capture_output=True)
    except Exception:
        pass


def append_jsonl(path, record):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + '\n')


def run_once(config_path):
    config = load_config(config_path)
    data_dir = config.get('data_dir', '/var/lib/argus')
    os.makedirs(data_dir, exist_ok=True)
    state_path = os.path.join(data_dir, 'state.json')
    incidents_path = os.path.join(data_dir, 'incidents.jsonl')
    state = _state(state_path)

    snapshot = collectors.collect(config)
    with open(os.path.join(data_dir, 'last_snapshot.json'), 'w',
              encoding='utf-8') as fh:
        json.dump(snapshot, fh, ensure_ascii=False)

    # история метрик для графиков дашборда (точка на каждый цикл)
    metrics_path = os.path.join(data_dir, 'metrics.jsonl')
    append_jsonl(metrics_path, {
        'ts': int(time.time()),
        **snapshot['resources'],
        'http_ms': {u: r['ms'] for u, r in snapshot['http'].items() if r['ok']},
        'containers_up': sum(1 for c in snapshot['containers'].values()
                             if c['running']),
    })
    try:  # ограничиваем историю (~35 дней при цикле в 5 минут)
        with open(metrics_path, encoding='utf-8') as fh:
            lines = fh.readlines()
        if len(lines) > 10000:
            with open(metrics_path, 'w', encoding='utf-8') as fh:
                fh.writelines(lines[-10000:])
    except OSError:
        pass
    incidents = detector.detect(snapshot, config)
    current_keys = {i['key'] for i in incidents}

    # восстановившиеся
    for key in [k for k in state['open'] if k not in current_keys]:
        opened = state['open'].pop(key)
        msg = f'✅ argus: восстановлено — {opened["title"]}'
        notify(config, msg)
        append_jsonl(incidents_path, {'ts': snapshot['ts'], 'event': 'resolved',
                                      'key': key, 'title': opened['title']})

    # новые
    for inc in incidents:
        if inc['key'] in state['open']:
            continue                      # уже оповещали, ждём закрытия
        verdict = llm.diagnose(inc, config)
        record = {'ts': snapshot['ts'], 'event': 'incident', **inc,
                  'verdict': verdict}
        action_result = None
        if verdict.get('action_id') and config.get('auto_remediate', False):
            action_result = remediation.try_execute(
                verdict['action_id'], config, state_path,
                dry_run=config.get('dry_run', False))
            record['action'] = {'id': verdict['action_id'], **action_result}
        append_jsonl(incidents_path, record)
        lines = [f'🚨 argus [{inc["severity"]}]: {inc["title"]}',
                 f'Диагноз: {verdict["diagnosis"]}',
                 f'Причина: {verdict["probable_cause"]}',
                 f'Рекомендация: {verdict["recommended_action"]} '
                 f'(уверенность {verdict["confidence"]:.0%},'
                 f' {"LLM" if verdict.get("llm") else "правило"})']
        if action_result is not None:
            lines.append(f'Действие {verdict["action_id"]}: '
                         f'{"выполнено" if action_result["executed"] else "НЕ выполнено"}'
                         f' ({action_result["reason"]})')
        notify(config, '\n'.join(lines))
        state['open'][inc['key']] = {'title': inc['title'], 'ts': snapshot['ts']}

    with open(state_path, 'w', encoding='utf-8') as fh:
        state.setdefault('last_run', time.time())
        state['last_run'] = time.time()
        json.dump(state, fh, ensure_ascii=False, indent=1)
    return {'incidents': len(incidents), 'open': len(state['open'])}


if __name__ == '__main__':
    cfg = sys.argv[1] if len(sys.argv) > 1 else 'local/config.json'
    print(run_once(cfg))
