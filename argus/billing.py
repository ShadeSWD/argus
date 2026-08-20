# -*- coding: utf-8 -*-
"""Напоминание об оплате подписки Claude в Telegram + опц. предупреждение об
истечении авторизации Claude Code. Запускается ежедневно из cron.

Конфиг: local/subscription.json (renew_date, cycle, amount, remind_days,
warn_auth_days). Пока renew_date не задан — по оплате молчит.

Идемпотентность: факт отправки за текущий цикл фиксируется в state-файле,
чтобы не слать повторно (и чтобы напомнить, даже если точный день пропущен —
шлём, когда до даты остаётся ≤ remind_days и за этот цикл ещё не слали).
"""
import datetime
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(BASE, 'local', 'subscription.json')
STATE = '/var/lib/argus/billing_state.json'
NOTIFY = ['/root/AutoConnectorTEST/.venv/bin/python',
          os.path.join(BASE, 'local', 'notify_tg.py')]


def _load(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open(STATE, 'w', encoding='utf-8') as fh:
            json.dump(st, fh)
    except OSError:
        pass


def _notify(text):
    try:
        subprocess.run(NOTIFY + [text], timeout=60, capture_output=True)
        return True
    except Exception:
        return False


def _next_renewal(cfg, today):
    """Дата ближайшего списания ≥ сегодня из renew_date + цикла."""
    try:
        base = datetime.date.fromisoformat(cfg['renew_date'])
    except (KeyError, TypeError, ValueError):
        return None
    if cfg.get('cycle') == 'annual':
        d = base
        while d < today:
            try:
                d = d.replace(year=d.year + 1)
            except ValueError:            # 29 фев
                d = d.replace(year=d.year + 1, day=28)
        return d
    # monthly
    d = base
    guard = 0
    while d < today and guard < 600:
        y, m = d.year + (d.month // 12), (d.month % 12) + 1
        day = min(base.day, [31, 29 if y % 4 == 0 and (y % 100 or not y % 400)
                             else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1])
        d = datetime.date(y, m, day)
        guard += 1
    return d


def _auth_days():
    """Дней до истечения refresh-токена Claude Code (или None)."""
    creds = os.path.expanduser('~/.claude/.credentials.json')
    c = _load(creds, {}).get('claudeAiOauth', {})
    rt = c.get('refreshTokenExpiresAt')
    if not rt:
        return None
    import time
    return (rt / 1000 - time.time()) / 86400.0


def run():
    cfg = _load(CONFIG, {})
    state = _load(STATE, {})
    today = datetime.date.today()
    sent = []

    # --- оплата подписки ---
    renew = _next_renewal(cfg, today)
    if renew:
        days = (renew - today).days
        remind = int(cfg.get('remind_days', 3))
        already = state.get('last_notified_renewal') == renew.isoformat()
        if 0 <= days <= remind and not already:
            amount = cfg.get('amount')
            money = (' на сумму %s %s' % (amount, cfg.get('currency', ''))
                     if amount else '')
            when = ('сегодня' if days == 0 else
                    'завтра' if days == 1 else 'через %d дн' % days)
            msg = ('💳 Оплата подписки %s — %s (%s)%s.\n'
                   'Проверь, что карта активна и хватит средств.'
                   % (cfg.get('plan', 'Claude'), when,
                      renew.strftime('%d.%m.%Y'), money))
            if _notify(msg):
                state['last_notified_renewal'] = renew.isoformat()
                sent.append('payment(%d дн)' % days)

    # --- истечение авторизации Claude Code (опц.) ---
    warn_auth = float(cfg.get('warn_auth_days', 0) or 0)
    if warn_auth > 0:
        ad = _auth_days()
        if ad is not None and 0 <= ad <= warn_auth:
            tag = today.isoformat()
            if state.get('last_auth_warn') != tag:
                _notify('🔑 Авторизация Claude Code истекает через %.1f дн — '
                        'зайди в терминал и выполни `claude`, чтобы обновить '
                        'сессию (иначе агенты/крон остановятся).' % ad)
                state['last_auth_warn'] = tag
                sent.append('auth(%.1f дн)' % ad)

    _save_state(state)
    return sent


if __name__ == '__main__':
    result = run()
    print('отправлено:', result if result else 'нечего слать')
    sys.exit(0)
