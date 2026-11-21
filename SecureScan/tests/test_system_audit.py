"""
Tests for the live system-audit integrations:
  * Windows host audit (collectors/host_audit.py)
  * Wireshark/TShark live capture (collectors/live_capture.py)
  * Autopsy case database import (collectors/autopsy_case.py)
External tools are mocked so the suite runs on any machine.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import app as app_module  # noqa: E402
from app import app  # noqa: E402
from database import init_db  # noqa: E402
from collectors import live_capture  # noqa: E402
from collectors.host_audit import audit_to_events  # noqa: E402
from collectors.autopsy_case import import_case_database, locate_case_db  # noqa: E402

AUDIT_JSON = {
    'host': {'computer': 'LAB-PC', 'user': 'LAB-PC\\student', 'is_admin': False, 'os': 'Windows 11',
             'build': '26100', 'audit_time': '2026-11-21T07:00:00.0000000Z'},
    'local_users': [
        {'name': 'Guest', 'enabled': True, 'password_required': False, 'password_expires': False},
        {'name': 'student', 'enabled': True, 'password_required': True, 'password_expires': True},
    ],
    'administrators': [{'name': 'LAB-PC\\student'}],
    'listening_ports': [{'address': '0.0.0.0', 'port': 3389, 'pid': 900, 'process': 'svchost'},
                        {'address': '0.0.0.0', 'port': 4444, 'pid': 1234, 'process': 'nc'}],
    'connections': [{'local': '10.0.0.5', 'local_port': 50000, 'remote': '198.51.100.7', 'remote_port': 4444,
                     'pid': 4321, 'process': 'powershell'}],
    'firewall': [{'profile': 'Domain', 'enabled': True}, {'profile': 'Public', 'enabled': False}],
    'defender': {'antivirus_enabled': True, 'realtime_protection': False, 'signature_age_days': 1},
    'uac': {'enable_lua': 1}, 'rdp': {'enabled': True}, 'smb1': {'server_smb1': False, 'client_driver_present': False},
    'autoruns': [{'location': 'HKCU:\\...\\Run', 'name': 'updater',
                  'command': 'C:\\Users\\student\\AppData\\Local\\Temp\\upd.exe'}],
    'scheduled_tasks': [],
    'hotfixes': {'count': 3, 'latest_id': 'KB1', 'latest_installed': '2026-01-01T00:00:00.0000000Z'},
    'risky_processes': [],
    'security_log': {'error': 'Attempted to perform an unauthorized operation.'},
}


class HostAuditTests(unittest.TestCase):
    def setUp(self):
        self.records, self.checks, self.meta = audit_to_events(AUDIT_JSON, raw_hash='abc')
        self.by_check = {c['check']: c for c in self.checks}

    def titles(self, severity):
        return [r['title'] for r in self.records if r['severity'] == severity]

    def test_misconfigurations_become_findings(self):
        high = ' '.join(self.titles('High'))
        self.assertIn('Guest account is ENABLED', high)
        self.assertIn('Windows Firewall disabled for: Public', high)
        self.assertIn('real-time protection OFF', high)
        self.assertIn('Last Windows update installed', high)          # > 90 days old
        self.assertIn('4444', ' '.join(self.titles('Critical')))       # backdoor listener
        self.assertIn('Remote Desktop ENABLED', ' '.join(self.titles('Medium')))
        self.assertIn('Autostart entry: updater', ' '.join(self.titles('Medium')))

    def test_check_statuses(self):
        self.assertEqual(self.by_check['Windows Firewall']['status'], 'fail')
        self.assertEqual(self.by_check['User Account Control']['status'], 'pass')
        self.assertEqual(self.by_check['Security event log']['status'], 'skipped')

    def test_connections_feed_correlation(self):
        conn = [r for r in self.records if r['destination_ip'] == '198.51.100.7'][0]
        self.assertEqual(conn['source'], 'System audit')
        self.assertEqual(conn['category'], 'Network')
        self.assertIn('Destination: 198.51.100.7:4444', conn['details'])
        self.assertEqual(conn['severity'], 'High')

    def test_ids_unique_and_meta(self):
        self.assertEqual(len({r['id'] for r in self.records}), len(self.records))
        self.assertEqual(self.meta['computer'], 'LAB-PC')


class LiveCaptureTests(unittest.TestCase):
    TSHARK_D = ("1. \\Device\\NPF_{AAA} (Wi-Fi)\n2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
                "3. etwdump (Event Tracing for Windows (ETW) reader)\n")

    def _run(self, *args, **kwargs):
        return mock.Mock(stdout=self.TSHARK_D, stderr='', returncode=0)

    def test_interface_listing_skips_pseudo_interfaces(self):
        with mock.patch.object(live_capture, 'find_tshark_path', return_value='tshark'), \
             mock.patch.object(live_capture.subprocess, 'run', side_effect=self._run):
            ifaces = live_capture.list_interfaces()
        self.assertEqual([i['name'] for i in ifaces], ['Wi-Fi', 'Adapter for loopback traffic capture'])

    def test_unknown_interface_and_bad_filter_rejected(self):
        with mock.patch.object(live_capture, 'find_tshark_path', return_value='tshark'), \
             mock.patch.object(live_capture.subprocess, 'run', side_effect=self._run):
            with self.assertRaises(ValueError):
                live_capture.capture_packets('99', 10, 100, 'x.pcapng')
            with self.assertRaises(ValueError):
                live_capture.capture_packets('1', 10, 100, 'x.pcapng', capture_filter='tcp; rm -rf /')

    def test_capture_command_is_bounded_and_shell_free(self):
        calls = []
        tmp = Path(tempfile.mkdtemp()) / 'c.pcapng'

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if '-D' in cmd:
                return mock.Mock(stdout=self.TSHARK_D, stderr='', returncode=0)
            tmp.write_bytes(b'\x0a\x0d\x0d\x0a')
            return mock.Mock(stdout='', stderr='Capturing on Wi-Fi\n42 packets captured', returncode=0)

        with mock.patch.object(live_capture, 'find_tshark_path', return_value='tshark'), \
             mock.patch.object(live_capture.subprocess, 'run', side_effect=fake_run):
            meta = live_capture.capture_packets('1', 9999, 10 ** 9, tmp)
        cmd = calls[-1]
        self.assertIsInstance(cmd, list)
        self.assertIn('duration:120', cmd)                    # clamped
        self.assertEqual(cmd[cmd.index('-c') + 1], '20000')   # clamped
        self.assertEqual(meta['packets_captured'], 42)
        shutil.rmtree(tmp.parent, ignore_errors=True)


def build_fake_case(case_dir):
    """Creates a minimal Sleuth Kit case database with the columns Autopsy uses."""
    case_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(case_dir / 'autopsy.db')
    con.executescript("""
        CREATE TABLE tsk_objects (obj_id INTEGER PRIMARY KEY, par_obj_id INTEGER, type INTEGER);
        CREATE TABLE tsk_image_names (obj_id INTEGER, name TEXT, sequence INTEGER);
        CREATE TABLE data_source_info (obj_id INTEGER PRIMARY KEY);
        CREATE TABLE tsk_files (obj_id INTEGER PRIMARY KEY, name TEXT, parent_path TEXT, size INTEGER,
            meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, crtime INTEGER, mtime INTEGER, atime INTEGER,
            md5 TEXT, sha256 TEXT, mime_type TEXT, extension TEXT, known INTEGER);
        CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT);
        CREATE TABLE blackboard_artifacts (artifact_id INTEGER PRIMARY KEY, obj_id INTEGER, artifact_type_id INTEGER);
        CREATE TABLE blackboard_attribute_types (attribute_type_id INTEGER PRIMARY KEY, type_name TEXT, display_name TEXT);
        CREATE TABLE blackboard_attributes (artifact_id INTEGER, attribute_type_id INTEGER, value_text TEXT,
            value_int32 INTEGER, value_int64 INTEGER, value_double REAL);
        INSERT INTO tsk_objects VALUES (1, NULL, 0);
        INSERT INTO tsk_image_names VALUES (1, 'C:\\evidence\\disk.E01', 0);
        INSERT INTO tsk_files VALUES
          (10,'holiday.jpg','/Users/bob/Downloads/',73802,1,1,5,0,1795000000,0,'aaa',NULL,'application/x-dosexec','jpg',0),
          (11,'svc.exe','/Users/bob/AppData/Local/Temp/',73802,1,1,5,0,1795000100,0,'aaa',NULL,'application/x-dosexec','exe',0),
          (12,'secret.docx','/Users/bob/Documents/',5000,1,2,4,0,1795000200,0,'bbb',NULL,'application/zip','docx',0),
          (13,'notes.txt','/Users/bob/Documents/',10,1,1,5,0,1795000300,0,'ccc',NULL,'text/plain','txt',0),
          (14,'bad.dll','/Windows/',10,1,1,5,0,1795000400,0,'ddd',NULL,'application/x-dosexec','dll',2),
          (15,'Documents','/Users/bob/',0,2,1,5,0,0,0,NULL,NULL,NULL,NULL,0);
        INSERT INTO blackboard_artifact_types VALUES (1,'TSK_DEVICE_ATTACHED','USB Device Attached');
        INSERT INTO blackboard_attribute_types VALUES (1,'TSK_DEVICE_MODEL','Device Model'), (2,'TSK_DATETIME','Date/Time');
        INSERT INTO blackboard_artifacts VALUES (100, 1, 1);
        INSERT INTO blackboard_attributes VALUES (100,1,'SanDisk Cruzer',NULL,NULL,NULL), (100,2,NULL,NULL,1795000500,NULL);
    """)
    con.commit()
    con.close()
    (case_dir / 'Case.aut').write_text('<AutopsyCase/>')


class AutopsyCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.case = self.tmp / 'Case_2026'
        build_fake_case(self.case)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_locate_case_db_accepts_folder_aut_and_db(self):
        for p in (self.case, self.case / 'Case.aut', self.case / 'autopsy.db'):
            self.assertEqual(locate_case_db(p).name, 'autopsy.db')
        with self.assertRaises(ValueError):
            locate_case_db(self.tmp)

    def test_case_import_flags_forensic_findings(self):
        before = (self.case / 'autopsy.db').read_bytes()
        records, summary = import_case_database(self.case)
        titles = {r['title']: r['severity'] for r in records}
        self.assertEqual(summary['files_total'], 5)            # directories excluded
        self.assertEqual(summary['files_deleted'], 1)
        self.assertEqual(titles["File extension mismatch: 'holiday.jpg' is really application/x-dosexec"], 'High')
        self.assertEqual(titles["Known-bad file (notable hash): 'bad.dll'"], 'Critical')
        self.assertIn('Same executable stored under 2 different names', titles)
        self.assertTrue(any(t.startswith('Deleted file entry') for t in titles))
        self.assertTrue(any('SanDisk Cruzer' in t for t in titles))
        self.assertEqual(summary['data_sources'][0], 'C:\\evidence\\disk.E01')
        self.assertEqual((self.case / 'autopsy.db').read_bytes(), before, 'case DB must not be modified')

    def test_reimport_is_idempotent(self):
        a, _ = import_case_database(self.case)
        b, _ = import_case_database(self.case)
        self.assertEqual([r['id'] for r in a], [r['id'] for r in b])


class SystemAuditApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        app.config.update(TESTING=True, DATABASE=self.db_path, UPLOAD_FOLDER=str(self.tmp / 'uploads'))
        (self.tmp / 'uploads').mkdir()
        self.client = app.test_client()
        with app.app_context():
            init_db(app)

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.unlink(self.db_path)
        except OSError:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    @unittest.skipUnless(os.name == 'nt', 'host audit route is Windows-only')
    def test_host_audit_route_stores_evidence_and_latest(self):
        with mock.patch.object(app_module, 'run_host_audit', return_value=AUDIT_JSON):
            res = self.client.post('/api/audit/host')
        self.assertEqual(res.status_code, 201, res.get_json())
        body = res.get_json()
        self.assertEqual(len(body['sha256_hash']), 64)
        self.assertTrue(any(f['severity'] == 'Critical' for f in body['findings']))
        latest = self.client.get('/api/audit/host/latest').get_json()
        self.assertTrue(latest['available'])
        self.assertEqual(latest['meta']['computer'], 'LAB-PC')
        stats = self.client.get('/api/stats').get_json()
        self.assertGreater(stats['sources']['system_audit'], 0)
        imports = self.client.get('/api/imports').get_json()
        self.assertEqual(imports[0]['source_type'], 'System audit')

    def test_capture_route_rejects_bad_input(self):
        with mock.patch.object(app_module, 'capture_packets', side_effect=ValueError('Unknown capture interface')):
            self.assertEqual(self.client.post('/api/capture/live', json={'interface': 'x'}).status_code, 400)
        self.assertEqual(self.client.post('/api/capture/live', json={'duration': 'abc'}).status_code, 400)

    def test_autopsy_case_import_route(self):
        case = self.tmp / 'Case_2026'
        build_fake_case(case)
        res = self.client.post('/api/autopsy/import-case', json={'path': str(case)})
        self.assertEqual(res.status_code, 201, res.get_json())
        self.assertGreater(res.get_json()['summary']['inserted'], 0)
        again = self.client.post('/api/autopsy/import-case', json={'path': str(case)}).get_json()
        self.assertEqual(again['summary']['inserted'], 0)          # duplicates prevented
        self.assertEqual(self.client.post('/api/autopsy/import-case', json={'path': str(self.tmp)}).status_code, 400)

    def test_autopsy_analyze_validates_path(self):
        res = self.client.post('/api/autopsy/analyze', json={'path': str(self.tmp / 'nope')})
        self.assertIn(res.status_code, (400,))

    def test_cross_origin_audit_actions_blocked(self):
        evil = {'Origin': 'http://evil.example'}
        for url in ('/api/audit/host', '/api/capture/live', '/api/autopsy/analyze', '/api/autopsy/import-case'):
            self.assertEqual(self.client.post(url, json={}, headers=evil).status_code, 403, url)


if __name__ == '__main__':
    unittest.main()
