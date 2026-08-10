# -*- coding: utf-8 -*-
"""Исполнитель ремедиаций с предохранителями.

Принципы:
- разрешены ТОЛЬКО действия из белого списка конфига (например,
  restart:relmet-web → docker restart relmet-web);
- никакая команда не строится из текста модели — action_id лишь выбирает
  заранее описанное действие;
- кулдаун на действие и суточный лимит; всё пишется в журнал;
- перезагрузка/выключение хоста не поддерживаются в принципе.
"""
import json
import subprocess
import time


def _load_state(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(path, state):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)


def try_execute(action_id, config, state_path, dry_run=False):
    """Выполнить действие, если предохранители позволяют.

    :return: {'executed': bool, 'reason': str, 'output': str}
    """
    actions = config.get('actions', {})
    if action_id not in actions:
        return {'executed': False, 'reason': 'действие не в белом списке', 'output': ''}
    spec = actions[action_id]
    now = time.time()
    state = _load_state(state_path)
    a_state = state.setdefault('actions', {}).setdefault(action_id, {})

    cooldown = config.get('action_cooldown_s', 1800)
    if now - a_state.get('last_ts', 0) < cooldown:
        return {'executed': False, 'reason': f'кулдаун {cooldown} с не истёк', 'output': ''}
    day = time.strftime('%Y-%m-%d')
    daily = a_state.get('daily', {})
    if daily.get(day, 0) >= config.get('action_daily_max', 3):
        return {'executed': False, 'reason': 'исчерпан суточный лимит', 'output': ''}

    cmd = spec['cmd']
    forbidden = ('shutdown', 'reboot', 'poweroff', 'halt', 'rm -rf /')
    if any(f in ' '.join(cmd) for f in forbidden):
        return {'executed': False, 'reason': 'запрещённая команда', 'output': ''}

    if dry_run:
        return {'executed': False, 'reason': 'dry-run', 'output': ' '.join(cmd)}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        ok = out.returncode == 0
    except Exception as exc:
        return {'executed': False, 'reason': f'ошибка запуска: {exc}', 'output': ''}
    a_state['last_ts'] = now
    daily[day] = daily.get(day, 0) + 1
    a_state['daily'] = {day: daily[day]}          # старые дни не копим
    _save_state(state_path, state)
    return {'executed': ok,
            'reason': 'выполнено' if ok else f'код возврата {out.returncode}',
            'output': (out.stdout + out.stderr)[-500:]}
