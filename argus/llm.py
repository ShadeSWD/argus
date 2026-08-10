# -*- coding: utf-8 -*-
"""LLM-диагност: локальная модель через Ollama (селфхостед, без внешних API).

На вход — инцидент с фактами, на выход — структурированный вердикт:
{'diagnosis': str, 'probable_cause': str, 'recommended_action': str|None,
 'action_id': str|None, 'confidence': 0..1}

action_id — идентификатор из белого списка ремедиаций (см. remediation.py);
модель может только ПРЕДЛОЖИТЬ действие, применяет его исполнитель после
собственных проверок. При недоступности модели — честный rule-based фолбэк.
"""
import json
import re
import urllib.request

PROMPT = """Ты — дежурный инженер эксплуатации (AIOps). Проанализируй инцидент
и верни СТРОГО JSON без пояснений, по схеме:
{{"diagnosis": "что произошло, 1-2 предложения по-русски",
  "probable_cause": "наиболее вероятная причина",
  "recommended_action": "что сделать человеку, 1 предложение",
  "action_id": <одно из {actions} или null>,
  "confidence": <число 0..1>}}

action_id выбирай ТОЛЬКО если уверен, что автоматическое действие уместно
и безопасно; иначе null. Перезагрузку хоста не предлагай никогда.

ИНЦИДЕНТ: {title} (важность: {severity})
ФАКТЫ:
{evidence}
"""


def _fallback(incident, allowed_actions):
    """Rule-based вердикт без LLM (модель недоступна)."""
    action = None
    key = incident['key']
    if key.startswith('container-down:'):
        name = key.split(':', 1)[1]
        cand = f'restart:{name}'
        action = cand if cand in allowed_actions else None
    return {'diagnosis': incident['title'],
            'probable_cause': 'модель недоступна — диагноз по правилу',
            'recommended_action': 'проверить сервис вручную',
            'action_id': action, 'confidence': 0.3, 'llm': False}


def diagnose(incident, config):
    allowed = list(config.get('actions', {}))
    base = config.get('ollama_url', 'http://127.0.0.1:11434')
    model = config.get('ollama_model', 'qwen2.5:3b')
    prompt = PROMPT.format(
        actions=allowed or ['(нет разрешённых действий)'],
        title=incident['title'], severity=incident['severity'],
        evidence=json.dumps(incident['evidence'], ensure_ascii=False)[:3000])
    payload = json.dumps({
        'model': model, 'stream': False, 'format': 'json',
        'options': {'temperature': 0.2, 'num_predict': 400},
        'messages': [{'role': 'user', 'content': prompt}],
    }).encode()
    try:
        req = urllib.request.Request(base.rstrip('/') + '/api/chat', data=payload,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=config.get('llm_timeout', 180)) as resp:
            data = json.loads(resp.read())
        text = data['message']['content']
        m = re.search(r'\{.*\}', text, re.S)
        verdict = json.loads(m.group(0) if m else text)
        action = verdict.get('action_id')
        if action not in allowed:
            action = None
        return {'diagnosis': str(verdict.get('diagnosis', ''))[:500],
                'probable_cause': str(verdict.get('probable_cause', ''))[:500],
                'recommended_action': str(verdict.get('recommended_action', ''))[:300],
                'action_id': action,
                'confidence': max(0.0, min(1.0, float(verdict.get('confidence', 0) or 0))),
                'llm': True}
    except Exception:
        return _fallback(incident, allowed)
