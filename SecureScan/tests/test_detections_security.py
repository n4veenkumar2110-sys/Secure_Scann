"""
Tests for the correlation/detection engine, the attack scenario loader and the
web-security hardening added to SecureScan.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import app  # noqa: E402
from database import init_db  # noqa: E402
from detections import run_detections  # noqa: E402
from parser_autopsy import classify_autopsy_artifact  # noqa: E402


def _ev(i, t, **kw):
    base = {'id': f'e{i}', 'event_time': t, 'source': 'Windows audit', 'category': 'System',
            'severity': 'Low', 'title': '', 'username': '', 'source_ip': '', 'destination_ip': '',
            'protocol': '', 'command': '', 'details': '', 'evidence_reference': f'REF-{i}', 'is_demo': 0}
    base.update(kw)
    return base


def _rules(result):
    return {d['rule_id'] for d in result['detections']}


class DetectionEngineUnitTests(unittest.TestCase):
    """Pure-function tests of detections.run_detections()."""

    def test_empty_evidence_has_no_risk(self):
        res = run_detections([])
        self.assertEqual(res['total'], 0)
        self.assertEqual(res['risk_score'], 0)
        self.assertEqual(res['risk_level'], 'None')
        self.assertEqual(len(res['kill_chain']), 8)

    def test_brute_force_without_success_is_high(self):
        evts = [_ev(i, f'2026-11-18T02:0{i}:00+00:00', category='Authentication', severity='High',
                    title="Event 4625: Failed login attempt for 'bob'", username='bob', source_ip='203.0.113.9')
                for i in range(6)]
        res = run_detections(evts)
        self.assertIn('SS-001', _rules(res))
        self.assertNotIn('SS-002', _rules(res))
        det = next(d for d in res['detections'] if d['rule_id'] == 'SS-001')
        self.assertEqual(det['severity'], 'High')
        self.assertEqual(det['mitre'][0]['id'], 'T1110')
        self.assertEqual(det['event_count'], 6)

    def test_brute_force_followed_by_success_is_critical(self):
        evts = [_ev(i, f'2026-11-18T02:0{i}:00+00:00', category='Authentication',
                    title="Event 4625: Failed login attempt for 'bob'", username='bob', source_ip='203.0.113.9')
                for i in range(5)]
        evts.append(_ev(99, '2026-11-18T02:07:00+00:00', category='Authentication',
                        title="Event 4624: Successful login for 'bob'", username='bob', source_ip='203.0.113.9'))
        res = run_detections(evts)
        self.assertIn('SS-002', _rules(res))
        self.assertEqual(res['detections'][0]['severity'], 'Critical')
        self.assertIn('e99', res['detections'][0]['event_ids'])

    def test_failures_below_threshold_or_spread_out_do_not_fire(self):
        few = [_ev(i, f'2026-11-18T02:0{i}:00+00:00', category='Authentication',
                   title='Failed authentication', username='bob', source_ip='1.2.3.4') for i in range(4)]
        spread = [_ev(i, f'2026-11-18T{10 + i}:00:00+00:00', category='Authentication',
                      title='Failed authentication', username='amy', source_ip='1.2.3.5') for i in range(8)]
        self.assertNotIn('SS-001', _rules(run_detections(few)))
        self.assertNotIn('SS-001', _rules(run_detections(spread)))

    def test_port_scan_ignores_reply_packets(self):
        evts = []
        for i, p in enumerate([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389]):
            evts.append(_ev(f's{i}', f'2026-11-18T02:00:{i:02d}+00:00', source='Wireshark', category='Network',
                            source_ip='203.0.113.5', destination_ip='10.0.0.2', command=f'{40000 + i} → {p}',
                            details='TCP Flags: [SYN]'))
            evts.append(_ev(f'r{i}', f'2026-11-18T02:00:{i:02d}+00:00', source='Wireshark', category='Network',
                            source_ip='10.0.0.2', destination_ip='203.0.113.5', command=f'{p} → {40000 + i}',
                            details='TCP Flags: [RST, ACK]'))
        scans = [d for d in run_detections(evts)['detections'] if d['rule_id'] == 'SS-008']
        self.assertEqual(len(scans), 1, 'only the scanner, not the victim replying, should be flagged')
        self.assertIn('203.0.113.5', scans[0]['summary'])

    def test_beaconing_and_cross_source_corroboration(self):
        evts = [_ev(f'h{i}', f'2026-11-18T02:1{i}:00+00:00', source='Sysmon', category='Network', severity='Medium',
                    title='Sysmon 3: Script interpreter network connection', username='WS\\amy',
                    destination_ip='198.51.100.7', command='C:\\Windows\\System32\\powershell.exe',
                    details='Destination: 198.51.100.7:4444') for i in range(3)]
        evts.append(_ev('w1', '2026-11-18T02:10:01+00:00', source='Wireshark', category='Network', severity='High',
                        source_ip='10.0.0.2', destination_ip='198.51.100.7', command='50000 → 4444',
                        details='TCP Flags: [SYN]'))
        res = run_detections(evts)
        self.assertIn('SS-009', _rules(res))
        self.assertIn('SS-011', _rules(res))
        beacon = next(d for d in res['detections'] if d['rule_id'] == 'SS-009')
        self.assertEqual(beacon['severity'], 'Critical')
        self.assertEqual(beacon['sources'], ['Sysmon', 'Wireshark'])
        self.assertIn('amy', beacon['entities']['users'], 'DOMAIN\\user should be normalised')

    def test_credential_dumping_and_dga_dns(self):
        evts = [
            _ev(1, '2026-11-18T02:00:00+00:00', category='Process', username='amy',
                command='m.exe "privilege::debug" "sekurlsa::logonpasswords"'),
            _ev(2, '2026-11-18T02:01:00+00:00', source='Sysmon', category='Network',
                title="Sysmon 22: DNS query: 'qx8v7zr2kp9m4wtl3n.info'", details='QueryName: qx8v7zr2kp9m4wtl3n.info'),
            _ev(3, '2026-11-18T02:02:00+00:00', source='Sysmon', category='Network',
                title="Sysmon 22: DNS query: 'www.microsoft.com'", details='QueryName: www.microsoft.com'),
        ]
        res = run_detections(evts)
        self.assertIn('SS-005', _rules(res))
        dns = [d for d in res['detections'] if d['rule_id'] == 'SS-010']
        self.assertEqual(len(dns), 1, 'only the random-looking domain should be flagged')
        self.assertIn('T1568.002', [m['id'] for m in dns[0]['mitre']])

    def test_detection_ids_are_stable(self):
        evts = [_ev(1, '2026-11-18T02:00:00+00:00', category='Process', username='amy',
                    command='vssadmin.exe delete shadows /all /quiet')]
        self.assertEqual(run_detections(evts)['detections'][0]['id'], run_detections(evts)['detections'][0]['id'])


class AutopsyClassifierRegressionTests(unittest.TestCase):
    def test_sam_substring_no_longer_false_positive(self):
        for name, path in [('sample.txt', 'C:/Users/x/sample.txt'), ('Samsung.jpg', 'D:/DCIM/Samsung.jpg')]:
            self.assertEqual(classify_autopsy_artifact(name, path, '', '')[1], 'Informational', name)

    def test_real_sam_hive_still_flagged(self):
        self.assertEqual(classify_autopsy_artifact('SAM', 'C:\\Windows\\System32\\config\\SAM', '', '')[1], 'High')


class ApiSecurityAndScenarioTests(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.upload_dir = tempfile.mkdtemp()
        app.config.update(TESTING=True, DATABASE=self.db_path, UPLOAD_FOLDER=self.upload_dir)
        self.client = app.test_client()
        with app.app_context():
            init_db(app)

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.unlink(self.db_path)
        except OSError:
            pass
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    # --- Hardening -------------------------------------------------------
    def test_project_files_are_not_served(self):
        for path in ('/instance/securescan.db', '/config.py', '/app.py', '/database.py',
                     '/detections.py', '/tests/test_securescan.py', '/sample_data/audit_sample.log'):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_ui_assets_still_served(self):
        for path in ('/', '/style.css', '/app.js'):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_security_headers_present(self):
        res = self.client.get('/')
        self.assertEqual(res.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(res.headers.get('X-Frame-Options'), 'DENY')
        self.assertIn("script-src 'self'", res.headers.get('Content-Security-Policy', ''))
        self.assertEqual(self.client.get('/api/stats').headers.get('Cache-Control'), 'no-store')

    def test_cross_origin_writes_are_blocked(self):
        evil = {'Origin': 'http://evil.example'}
        self.assertEqual(self.client.delete('/api/events/demo', headers=evil).status_code, 403)
        res = self.client.post('/api/import/wireshark', headers=evil, content_type='multipart/form-data',
                               data={'file': (io.BytesIO(b'No.,Time\n'), 'x.csv')})
        self.assertEqual(res.status_code, 403)
        self.assertEqual(self.client.post('/api/scenario', headers=evil).status_code, 403)

    def test_same_origin_and_non_browser_writes_allowed(self):
        self.assertEqual(self.client.post('/api/events/demo', headers={'Origin': 'http://localhost'}).status_code, 201)
        self.assertEqual(self.client.delete('/api/events/demo').status_code, 200)

    def test_unauthenticated_sync_endpoint_removed(self):
        res = self.client.post('/api/events/sync', json=[{'title': 'x'}])
        self.assertEqual(res.status_code, 404)

    # --- Detections API & scenario ---------------------------------------
    def test_detections_endpoint_empty_db(self):
        data = self.client.get('/api/detections').get_json()
        self.assertEqual(data['total'], 0)
        self.assertEqual(data['risk_level'], 'None')

    def test_scenario_triggers_full_attack_chain_and_is_clearable(self):
        res = self.client.post('/api/scenario')
        self.assertEqual(res.status_code, 201)
        self.assertEqual(len(res.get_json()['files']), 5)

        data = self.client.get('/api/detections').get_json()
        expected = {'SS-002', 'SS-003', 'SS-004', 'SS-005', 'SS-006', 'SS-007', 'SS-008',
                    'SS-009', 'SS-010', 'SS-011', 'SS-012', 'SS-013', 'SS-014'}
        self.assertTrue(expected.issubset(_rules(data)), expected - _rules(data))
        self.assertEqual(data['risk_level'], 'Critical')
        self.assertTrue(all(d['is_demo'] for d in data['detections']))
        hit_tactics = {k['tactic'] for k in data['kill_chain'] if k['count']}
        self.assertEqual(len(hit_tactics), 8)

        stats = self.client.get('/api/stats').get_json()
        self.assertEqual(stats['detections']['total'], data['total'])
        report = self.client.get('/api/reports/summary').get_json()
        self.assertEqual(report['risk_level'], 'Critical')
        self.assertTrue(report['detections'])

        # loading twice must not duplicate evidence
        self.client.post('/api/scenario')
        self.assertEqual(self.client.get('/api/stats').get_json()['total_events'], stats['total_events'])

        self.client.delete('/api/events/demo')
        self.assertEqual(self.client.get('/api/detections').get_json()['total'], 0)


if __name__ == '__main__':
    unittest.main()
