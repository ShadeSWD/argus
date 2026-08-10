# -*- coding: utf-8 -*-
"""Тесты детектора, предохранителей ремедиации и фолбэка диагноста."""
import json
import os
import tempfile
import unittest

from sentinel import detector, llm, remediation

SNAP = {
    'ts': '2026-08-07T12:00:00',
    'containers': {'web': {'status': 'Up 2 days', 'running': True, 'image': 'x'},
                   'db': {'status': 'Exited (1)', 'running': False, 'image': 'y'}},
    'http': {'https://ok.example/': {'code': 200, 'ms': 300, 'ok': True, 'error': None},
             'https://bad.example/': {'code': None, 'ms': 15000, 'ok': False,
                                      'error': 'timed out'}},
    'resources': {'disk_used_pct': 95.0, 'mem_available_pct': 40.0,
                  'load1_per_core': 0.5},
    'logs': {'web': '\n'.join(['INFO ok'] * 3 + ['Traceback ...'] * 6)},
}
CFG = {'watch_containers': ['web', 'db', 'ghost'],
       'actions': {'restart:db': {'cmd': ['docker', 'restart', 'db']}}}


class TestDetector(unittest.TestCase):
    def test_rules(self):
        keys = {i['key'] for i in detector.detect(SNAP, CFG)}
        self.assertIn('container-down:db', keys)
        self.assertIn('container-missing:ghost', keys)
        self.assertIn('http-fail:https://bad.example/', keys)
        self.assertIn('disk-full', keys)
        self.assertIn('log-errors:web', keys)
        self.assertNotIn('http-fail:https://ok.example/', keys)

    def test_severity(self):
        sev = {i['key']: i['severity'] for i in detector.detect(SNAP, CFG)}
        self.assertEqual(sev['container-down:db'], 'critical')
        self.assertEqual(sev['log-errors:web'], 'warning')


class TestRemediationGuards(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.NamedTemporaryFile(suffix='.json', delete=False).name

    def tearDown(self):
        os.unlink(self.state)

    def test_whitelist_only(self):
        r = remediation.try_execute('rm-rf', CFG, self.state)
        self.assertFalse(r['executed'])
        self.assertIn('белом списке', r['reason'])

    def test_forbidden_command_blocked(self):
        cfg = {'actions': {'bad': {'cmd': ['reboot']}}}
        r = remediation.try_execute('bad', cfg, self.state)
        self.assertFalse(r['executed'])
        self.assertEqual(r['reason'], 'запрещённая команда')

    def test_dry_run_and_cooldown(self):
        cfg = {'actions': {'echo': {'cmd': ['echo', 'hi']}},
               'action_cooldown_s': 3600}
        r = remediation.try_execute('echo', cfg, self.state, dry_run=True)
        self.assertFalse(r['executed'])
        self.assertEqual(r['reason'], 'dry-run')
        r1 = remediation.try_execute('echo', cfg, self.state)
        self.assertTrue(r1['executed'])
        r2 = remediation.try_execute('echo', cfg, self.state)
        self.assertFalse(r2['executed'])
        self.assertIn('кулдаун', r2['reason'])

    def test_daily_limit(self):
        cfg = {'actions': {'echo': {'cmd': ['echo', 'hi']}},
               'action_cooldown_s': 0, 'action_daily_max': 2}
        for _ in range(2):
            self.assertTrue(remediation.try_execute('echo', cfg, self.state)['executed'])
        r = remediation.try_execute('echo', cfg, self.state)
        self.assertFalse(r['executed'])
        self.assertIn('суточный лимит', r['reason'])


class TestLlmFallback(unittest.TestCase):
    def test_fallback_suggests_whitelisted_restart(self):
        inc = {'key': 'container-down:db', 'severity': 'critical',
               'title': 'Контейнер db не запущен', 'evidence': {}}
        cfg = dict(CFG, ollama_url='http://127.0.0.1:1')   # заведомо недоступен
        v = llm.diagnose(inc, cfg)
        self.assertFalse(v['llm'])
        self.assertEqual(v['action_id'], 'restart:db')

    def test_fallback_no_action_outside_whitelist(self):
        inc = {'key': 'container-down:unknown', 'severity': 'critical',
               'title': 'x', 'evidence': {}}
        cfg = dict(CFG, ollama_url='http://127.0.0.1:1')
        v = llm.diagnose(inc, cfg)
        self.assertIsNone(v['action_id'])


if __name__ == '__main__':
    unittest.main()
