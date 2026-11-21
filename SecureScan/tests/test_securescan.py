import unittest
import io
import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import app
from database import init_db

class SecureScanTestCase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.upload_dir = tempfile.mkdtemp()

        app.config['TESTING'] = True
        app.config['DATABASE'] = self.db_path
        app.config['UPLOAD_FOLDER'] = self.upload_dir

        self.client = app.test_client()

        with app.app_context():
            init_db(app)

    def tearDown(self):
        os.close(self.db_fd)
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_health_endpoints(self):
        """Test GET /health and /api/health."""
        with self.client.get('/health') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['database'], 'connected')

        with self.client.get('/api/health') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['status'], 'ok')

    def test_static_frontend_serving(self):
        """Test serving index.html, style.css, app.js, and README.txt."""
        with self.client.get('/') as res:
            self.assertEqual(res.status_code, 200)
            self.assertIn(b'SecureScan', res.data)
            self.assertIn(b'style.css', res.data)

        with self.client.get('/style.css') as res:
            self.assertEqual(res.status_code, 200)
            self.assertIn(b'--bg', res.data)

        with self.client.get('/app.js') as res:
            self.assertEqual(res.status_code, 200)
            self.assertIn(b'SecureScan', res.data)

    def test_stats_initial(self):
        """Test dashboard counts initial empty state."""
        with self.client.get('/api/stats') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['total_events'], 0)
            self.assertEqual(data['critical'], 0)
            self.assertEqual(data['demo_records'], 0)

    def test_demo_event_generation_and_deletion(self):
        """Test generating demo records and subsequently clearing them."""
        # 1. Generate demo events (includes Linux, Wireshark, Autopsy, Windows 11 and Sysmon)
        with self.client.post('/api/events/demo') as res:
            self.assertEqual(res.status_code, 201)
            data = json.loads(res.data)
            self.assertEqual(data['added_count'], 10)

        # 2. Check stats updated
        with self.client.get('/api/stats') as res:
            data = json.loads(res.data)
            self.assertEqual(data['total_events'], 10)
            self.assertEqual(data['demo_records'], 10)
            self.assertGreater(data['high'], 0)
            self.assertGreater(data['sources']['windows_audit'], 0)
            self.assertGreater(data['sources']['sysmon'], 0)

        # 3. Check /api/events returns them with is_demo = True
        with self.client.get('/api/events') as res:
            data = json.loads(res.data)
            self.assertEqual(len(data), 10)
            self.assertTrue(all(e['is_demo'] is True for e in data))

        # 4. Clear demo events
        with self.client.delete('/api/events/demo') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['deleted_count'], 10)

        # 5. Check stats are 0 again
        with self.client.get('/api/stats') as res:
            data = json.loads(res.data)
            self.assertEqual(data['total_events'], 0)
            self.assertEqual(data['demo_records'], 0)

    def test_windows_security_events_import(self):
        """Test importing Windows 11 Security log JSON and verifying detection rules."""
        win_sample = PROJECT_ROOT / 'sample_data' / 'windows_events_sample.json'
        self.assertTrue(win_sample.exists(), "windows_events_sample.json must exist")

        with open(win_sample, 'rb') as f:
            data = {'file': (f, 'windows_events_sample.json')}
            with self.client.post('/api/import/windows-audit', data=data, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)
                resp = json.loads(res.data)
                self.assertEqual(resp['successful_records'], 7)
                self.assertEqual(resp['duplicates_skipped'], 0)
                self.assertEqual(len(resp['sha256_hash']), 64)

        # Verify parsed records in SQLite
        with self.client.get('/api/events?source=Windows audit') as res:
            events = json.loads(res.data)
            self.assertEqual(len(events), 7)

            # 1. Event 4625 (Failed logon) must be High severity & Authentication
            failed_logon = next(e for e in events if '4625' in e['title'])
            self.assertEqual(failed_logon['severity'], 'High')
            self.assertEqual(failed_logon['category'], 'Authentication')
            self.assertEqual(failed_logon['source_ip'], '192.168.1.50')
            self.assertIn('brute-force', failed_logon['details'])

            # 2. Event 4720 (User created) must be Medium severity & Account
            user_created = next(e for e in events if '4720' in e['title'])
            self.assertEqual(user_created['severity'], 'Medium')
            self.assertEqual(user_created['category'], 'Account')

            # 3. Event 4726 (User deleted) must be High severity & Account
            user_deleted = next(e for e in events if '4726' in e['title'])
            self.assertEqual(user_deleted['severity'], 'High')
            self.assertEqual(user_deleted['category'], 'Account')

            # 4. Event 4672 (Admin privileges assigned)
            admin_priv = next(e for e in events if '4672' in e['title'])
            self.assertEqual(admin_priv['severity'], 'Medium')

            # 5. Event 4688 (Process creation whoami.exe)
            proc_created = next(e for e in events if '4688' in e['title'])
            self.assertEqual(proc_created['category'], 'Process')
            self.assertEqual(proc_created['severity'], 'Medium')

    def test_sysmon_events_import_via_windows_audit(self):
        """Test importing original Sysmon events (IDs 1, 3, 11) via windows-audit endpoint."""
        sysmon_sample = PROJECT_ROOT / 'sample_data' / 'sysmon_events_sample.json'
        self.assertTrue(sysmon_sample.exists(), "sysmon_events_sample.json must exist")

        with open(sysmon_sample, 'rb') as f:
            data = {'file': (f, 'sysmon_events_sample.json')}
            with self.client.post('/api/import/windows-audit', data=data, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)
                resp = json.loads(res.data)
                self.assertEqual(resp['successful_records'], 3)

        # Check Sysmon records in database
        with self.client.get('/api/events?source=Sysmon') as res:
            events = json.loads(res.data)
            self.assertEqual(len(events), 3)

            # Sysmon 1 -> Process category
            p_event = next(e for e in events if 'Sysmon 1:' in e['title'])
            self.assertEqual(p_event['category'], 'Process')

            # Sysmon 3 -> Network category with destination IP
            net_event = next(e for e in events if 'Sysmon 3:' in e['title'])
            self.assertEqual(net_event['category'], 'Network')
            self.assertEqual(net_event['destination_ip'], '142.250.72.14')

            # Sysmon 11 -> File creation / Forensic
            file_event = next(e for e in events if 'Sysmon 11:' in e['title'])
            self.assertEqual(file_event['category'], 'Forensic')
            self.assertIn('staged_payload.ps1', file_event['details'] + file_event['title'])

    def test_sysmon_dedicated_endpoint_extended(self):
        """Test the dedicated POST /api/import/sysmon endpoint with extended sample data (IDs 1, 3, 11, 22)."""
        sysmon_ext = PROJECT_ROOT / 'sample_data' / 'sysmon_events_extended.json'
        self.assertTrue(sysmon_ext.exists(), "sysmon_events_extended.json must exist")

        with open(sysmon_ext, 'rb') as f:
            data = {'file': (f, 'sysmon_events_extended.json')}
            with self.client.post('/api/import/sysmon', data=data, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)
                resp = json.loads(res.data)
                self.assertEqual(resp['successful_records'], 6)
                self.assertEqual(resp['duplicates_skipped'], 0)
                self.assertEqual(resp['failed_records'], 0)
                self.assertEqual(len(resp['sha256_hash']), 64)

        # Verify all 6 records in database
        with self.client.get('/api/events?source=Sysmon') as res:
            events = json.loads(res.data)
            self.assertEqual(len(events), 6)

            # Event 1: Process Create (whoami.exe -> recon process, Medium severity)
            proc_event = next(e for e in events if 'Sysmon 1:' in e['title'])
            self.assertEqual(proc_event['category'], 'Process')
            self.assertIn(proc_event['severity'], ('Medium', 'High'))
            self.assertIn('whoami', proc_event['command'])

            # Event 3: Network Connect (PowerShell -> Medium severity)
            net_event = next(e for e in events if 'Sysmon 3:' in e['title'])
            self.assertEqual(net_event['category'], 'Network')
            self.assertEqual(net_event['destination_ip'], '142.250.72.14')
            self.assertEqual(net_event['severity'], 'Medium')

            # Event 11: File Create in temp (Medium severity)
            file_events = [e for e in events if 'Sysmon 11:' in e['title']]
            self.assertEqual(len(file_events), 2)
            temp_file = next(e for e in file_events if 'staged_payload' in e['title'])
            self.assertEqual(temp_file['category'], 'Forensic')
            self.assertEqual(temp_file['severity'], 'Medium')

            # Event 22: DNS Query normal (Informational)
            dns_normal = next(e for e in events if 'google.com' in e['title'])
            self.assertEqual(dns_normal['category'], 'Network')
            self.assertEqual(dns_normal['severity'], 'Informational')

            # Event 22: DNS Query suspicious domain (Medium)
            dns_suspicious = next(e for e in events if 'pastebin.com' in e['title'])
            self.assertEqual(dns_suspicious['category'], 'Network')
            self.assertEqual(dns_suspicious['severity'], 'Medium')

    def test_sysmon_duplicate_prevention(self):
        """Test that importing the same Sysmon file twice does not create duplicates."""
        sysmon_ext = PROJECT_ROOT / 'sample_data' / 'sysmon_events_extended.json'

        # First import
        with open(sysmon_ext, 'rb') as f:
            res1 = self.client.post('/api/import/sysmon', data={'file': (f, 'sysmon_events_extended.json')}, content_type='multipart/form-data')
            self.assertEqual(res1.status_code, 201)
            resp1 = json.loads(res1.data)
            self.assertEqual(resp1['successful_records'], 6)
            self.assertEqual(resp1['duplicates_skipped'], 0)

        # Second import of exact same file
        with open(sysmon_ext, 'rb') as f:
            res2 = self.client.post('/api/import/sysmon', data={'file': (f, 'sysmon_events_extended.json')}, content_type='multipart/form-data')
            self.assertEqual(res2.status_code, 201)
            resp2 = json.loads(res2.data)
            self.assertEqual(resp2['successful_records'], 0)
            self.assertEqual(resp2['duplicates_skipped'], 6)

        # Verify database still only has 6 events total
        with self.client.get('/api/stats') as res:
            stats = json.loads(res.data)
            self.assertEqual(stats['total_events'], 6)
            self.assertEqual(stats['sources']['sysmon'], 6)

    def test_sysmon_parser_dns_query_classification(self):
        """Test that the Sysmon parser correctly classifies DNS Query events (ID 22)."""
        from collectors.sysmon_parser import normalize_sysmon_event

        # Normal DNS query
        normal_dns = {
            'event_id': 22,
            'event_time': '2026-11-20T11:00:00Z',
            'record_id': 9001,
            'source': 'Sysmon',
            'computer_name': 'TEST-PC',
            'image': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'query_name': 'www.example.com',
            'query_type': 'A',
            'query_status': '0',
            'query_results': '93.184.216.34',
            'username': 'testuser'
        }
        result = normalize_sysmon_event(normal_dns)
        self.assertEqual(result['category'], 'Network')
        self.assertEqual(result['severity'], 'Informational')
        self.assertIn('www.example.com', result['title'])
        self.assertEqual(result['source'], 'Sysmon')

        # Suspicious DNS query
        suspicious_dns = {
            'event_id': 22,
            'event_time': '2026-11-20T11:01:00Z',
            'record_id': 9002,
            'source': 'Sysmon',
            'computer_name': 'TEST-PC',
            'image': 'C:\\Windows\\System32\\powershell.exe',
            'query_name': 'evil.ngrok.io',
            'query_type': 'A',
            'query_status': '0',
            'query_results': '1.2.3.4',
            'username': 'testuser'
        }
        result2 = normalize_sysmon_event(suspicious_dns)
        self.assertEqual(result2['category'], 'Network')
        self.assertEqual(result2['severity'], 'Medium')
        self.assertIn('suspicious', result2['title'].lower())

    def test_sysmon_dashboard_stats_integration(self):
        """Test that Sysmon records appear correctly in dashboard statistics."""
        sysmon_ext = PROJECT_ROOT / 'sample_data' / 'sysmon_events_extended.json'

        with open(sysmon_ext, 'rb') as f:
            self.client.post('/api/import/sysmon', data={'file': (f, 'sysmon_events_extended.json')}, content_type='multipart/form-data')

        with self.client.get('/api/stats') as res:
            stats = json.loads(res.data)
            self.assertEqual(stats['sources']['sysmon'], 6)
            # Should have Process, Network, and Forensic categories
            self.assertGreater(stats['categories']['process'], 0)
            self.assertGreater(stats['categories']['network'], 0)
            self.assertGreater(stats['categories']['forensic'], 0)

        # Reports summary should also reflect Sysmon
        with self.client.get('/api/reports/summary') as res:
            report = json.loads(res.data)
            self.assertEqual(report['sources_summary']['Sysmon'], 6)
            self.assertGreater(report['total_events'], 0)

    def test_windows_duplicate_prevention(self):
        """Test that importing the same Windows event file twice does not create duplicates."""
        win_sample = PROJECT_ROOT / 'sample_data' / 'windows_events_sample.json'
        
        # First import
        with open(win_sample, 'rb') as f:
            res1 = self.client.post('/api/import/windows-audit', data={'file': (f, 'windows_events_sample.json')}, content_type='multipart/form-data')
            self.assertEqual(res1.status_code, 201)
            resp1 = json.loads(res1.data)
            self.assertEqual(resp1['successful_records'], 7)
            self.assertEqual(resp1['duplicates_skipped'], 0)

        # Second import of exact same file
        with open(win_sample, 'rb') as f:
            res2 = self.client.post('/api/import/windows-audit', data={'file': (f, 'windows_events_sample.json')}, content_type='multipart/form-data')
            self.assertEqual(res2.status_code, 201)
            resp2 = json.loads(res2.data)
            self.assertEqual(resp2['successful_records'], 0)
            self.assertEqual(resp2['duplicates_skipped'], 7)

        # Verify database still only has 7 events total
        with self.client.get('/api/stats') as res:
            stats = json.loads(res.data)
            self.assertEqual(stats['total_events'], 7)

    def test_sample_evidence_pack_imports(self):
        """Test importing the sample files from sample_data/ directory."""
        sample_dir = PROJECT_ROOT / 'sample_data'
        audit_file = sample_dir / 'audit_sample.log'
        pcap_file = sample_dir / 'wireshark_sample.csv'
        aut_file = sample_dir / 'autopsy_sample.csv'

        # 1. Import Linux Audit Log
        with open(audit_file, 'rb') as f:
            with self.client.post('/api/import/linux-audit', data={'file': (f, 'audit_sample.log')}, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)

        # 2. Import Wireshark CSV
        with open(pcap_file, 'rb') as f:
            with self.client.post('/api/import/wireshark', data={'file': (f, 'wireshark_sample.csv')}, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)

        # 3. Import Autopsy CSV
        with open(aut_file, 'rb') as f:
            with self.client.post('/api/import/autopsy', data={'file': (f, 'autopsy_sample.csv')}, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)

        # 4. Verify dashboard stats reflect tools
        with self.client.get('/api/stats') as res:
            stats = json.loads(res.data)
            self.assertGreaterEqual(stats['total_events'], 17)

    def test_invalid_file_handling(self):
        """Test rejection of invalid files and unsupported extensions."""
        data_bad_ext = {
            'file': (io.BytesIO(b'MZ...executable'), 'malicious.exe')
        }
        with self.client.post('/api/import/sysmon', data=data_bad_ext, content_type='multipart/form-data') as res:
            self.assertEqual(res.status_code, 400)
            data_err = json.loads(res.data)
            self.assertIn('Unsupported file format', data_err['error'])

        with self.client.post('/api/import/sysmon', data={}) as res:
            self.assertEqual(res.status_code, 400)

        # Also test windows-audit endpoint
        data_bad_ext2 = {
            'file': (io.BytesIO(b'MZ...executable'), 'malicious.exe')
        }
        with self.client.post('/api/import/windows-audit', data=data_bad_ext2, content_type='multipart/form-data') as res:
            self.assertEqual(res.status_code, 400)

    def test_wireshark_extended_csv_import(self):
        """Test importing Wireshark extended CSV containing IPv4, IPv6, DNS queries, and unusual ports."""
        csv_file = PROJECT_ROOT / 'sample_data' / 'wireshark_extended_sample.csv'
        self.assertTrue(csv_file.exists(), "wireshark_extended_sample.csv must exist")

        with open(csv_file, 'rb') as f:
            data = {'file': (f, 'wireshark_extended_sample.csv')}
            with self.client.post('/api/import/wireshark', data=data, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)
                resp = json.loads(res.data)
                self.assertEqual(resp['successful_records'], 9)
                self.assertEqual(resp['duplicates_skipped'], 0)
                self.assertEqual(len(resp['sha256_hash']), 64)

        # Verify parsed records in SQLite
        with self.client.get('/api/events?source=Wireshark') as res:
            events = json.loads(res.data)
            self.assertEqual(len(events), 9)

            # 1. Check IPv6 DNS query
            ipv6_event = next(e for e in events if '2001:db8::10' in e['source_ip'])
            self.assertEqual(ipv6_event['destination_ip'], '2001:db8::1')
            self.assertEqual(ipv6_event['protocol'], 'DNS')
            self.assertIn('internal-host.corp', ipv6_event['title'] + ipv6_event['details'])

            # 2. Check unusual port 4444 record
            port_4444_event = next(e for e in events if '4444' in e['title'] or '4444' in e['command'])
            self.assertEqual(port_4444_event['severity'], 'Medium')
            self.assertIn('4444', port_4444_event['details'])

            # 3. Check DNS query with ngrok
            ngrok_event = next(e for e in events if 'ngrok' in e['title'] or 'ngrok' in e['details'])
            self.assertEqual(ngrok_event['severity'], 'Medium')

    def test_wireshark_column_variations(self):
        """Test Wireshark CSV parser against alternative column header names."""
        from collectors.wireshark_parser import parse_wireshark_csv_text

        # Alternative headers: frame.time_epoch, ip.src, ipv6.dst, frame.protocols, frame.len, _ws.col.info
        custom_csv = (
            '"frame.time_epoch","ip.src","ipv6.dst","frame.protocols","frame.len","_ws.col.info"\n'
            '"1716042121.100","192.168.1.100","2001:db8::2","eth:ip:tcp:tls","1400","Application Data"\n'
            '"1716042122.200","10.0.0.5","1.1.1.1","eth:ip:udp:dns","85","Standard query 0x1234 A mysite.com"\n'
        )
        records, succ, fail = parse_wireshark_csv_text(custom_csv, filename="custom_export.csv")
        self.assertEqual(succ, 2)
        self.assertEqual(fail, 0)
        self.assertEqual(records[0]['source_ip'], '192.168.1.100')
        self.assertEqual(records[0]['destination_ip'], '2001:db8::2')
        self.assertEqual(records[0]['protocol'], 'TLS')
        self.assertEqual(records[1]['protocol'], 'DNS')
        self.assertIn('mysite.com', records[1]['title'] + records[1]['details'])

    def test_wireshark_duplicate_prevention(self):
        """Test that importing the same Wireshark file twice avoids duplicate rows."""
        csv_file = PROJECT_ROOT / 'sample_data' / 'wireshark_extended_sample.csv'

        # First import
        with open(csv_file, 'rb') as f:
            res1 = self.client.post('/api/import/wireshark', data={'file': (f, 'wireshark_extended_sample.csv')}, content_type='multipart/form-data')
            self.assertEqual(res1.status_code, 201)
            resp1 = json.loads(res1.data)
            self.assertEqual(resp1['successful_records'], 9)
            self.assertEqual(resp1['duplicates_skipped'], 0)

        # Second import of exact same file
        with open(csv_file, 'rb') as f:
            res2 = self.client.post('/api/import/wireshark', data={'file': (f, 'wireshark_extended_sample.csv')}, content_type='multipart/form-data')
            self.assertEqual(res2.status_code, 201)
            resp2 = json.loads(res2.data)
            self.assertEqual(resp2['successful_records'], 0)
            self.assertEqual(resp2['duplicates_skipped'], 9)

        # Database should still have only 9 Wireshark records
        with self.client.get('/api/events?source=Wireshark') as res:
            events = json.loads(res.data)
            self.assertEqual(len(events), 9)

    def test_tshark_detection_and_pcap_parsing(self):
        """Test TShark detection and parsing of sample_traffic.pcap directly."""
        from collectors.wireshark_parser import find_tshark_path, get_tshark_info, parse_pcap_file

        info = get_tshark_info()
        tshark_bin = find_tshark_path()

        if tshark_bin:
            self.assertTrue(info['available'])
            self.assertIsNotNone(info['path'])
            pcap_file = PROJECT_ROOT / 'sample_data' / 'sample_traffic.pcap'
            self.assertTrue(pcap_file.exists(), "sample_traffic.pcap must exist")

            records, succ, fail = parse_pcap_file(pcap_file)
            self.assertEqual(succ, 3)
            self.assertEqual(fail, 0)

            # Record 1: DNS query for example.com
            dns_rec = next(r for r in records if r['protocol'] == 'DNS')
            self.assertEqual(dns_rec['source_ip'], '192.168.1.100')
            self.assertEqual(dns_rec['destination_ip'], '8.8.8.8')
            self.assertIn('example.com', dns_rec['title'] + dns_rec['details'])

            # Record 2: TCP SYN to port 4444 (Unusual port rule)
            tcp_rec = next(r for r in records if r['protocol'] == 'TCP')
            self.assertEqual(tcp_rec['severity'], 'Medium')
            self.assertEqual(tcp_rec['destination_ip'], '198.51.100.25')

            # Record 3: IPv6 UDP
            ipv6_rec = next(r for r in records if r['protocol'] == 'UDP')
            self.assertEqual(ipv6_rec['source_ip'], '2001:db8::10')
            self.assertEqual(ipv6_rec['destination_ip'], '2001:db8::1')
        else:
            self.assertFalse(info['available'])
            self.assertIn("TShark was not found", info['install_guide'])

    def test_pcap_upload_endpoints(self):
        """Test uploading .pcap file to POST /api/import/pcap and /api/import/wireshark."""
        from collectors.wireshark_parser import find_tshark_path
        if not find_tshark_path():
            self.skipTest("TShark is not installed; skipping PCAP execution test")

        pcap_file = PROJECT_ROOT / 'sample_data' / 'sample_traffic.pcap'
        with open(pcap_file, 'rb') as f:
            data = {'file': (f, 'sample_traffic.pcap')}
            with self.client.post('/api/import/pcap', data=data, content_type='multipart/form-data') as res:
                self.assertEqual(res.status_code, 201)
                resp = json.loads(res.data)
                self.assertEqual(resp['successful_records'], 3)
                self.assertEqual(resp['duplicates_skipped'], 0)
                self.assertEqual(len(resp['sha256_hash']), 64)

        # Second upload to /api/import/wireshark should detect duplicate packets
        with open(pcap_file, 'rb') as f:
            data2 = {'file': (f, 'sample_traffic.pcap')}
            with self.client.post('/api/import/wireshark', data=data2, content_type='multipart/form-data') as res2:
                self.assertEqual(res2.status_code, 201)
                resp2 = json.loads(res2.data)
                self.assertEqual(resp2['successful_records'], 0)
                self.assertEqual(resp2['duplicates_skipped'], 3)

    def test_network_stats_endpoint(self):
        """Test GET /api/network/stats returns aggregated network metrics from SQLite."""
        csv_file = PROJECT_ROOT / 'sample_data' / 'wireshark_extended_sample.csv'
        with open(csv_file, 'rb') as f:
            self.client.post('/api/import/wireshark', data={'file': (f, 'wireshark_extended_sample.csv')}, content_type='multipart/form-data')

        with self.client.get('/api/network/stats') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertGreaterEqual(data['total_packets'], 9)
            self.assertIn('protocols', data)
            self.assertIn('DNS', data['protocols'])
            self.assertIn('TCP', data['protocols'])
            self.assertIn('traffic_split', data)
            self.assertGreater(data['traffic_split']['tcp'], 0)
            self.assertIn('tshark', data)
            self.assertIn('top_sources', data)
            self.assertIn('top_destinations', data)
            self.assertIn('dns_queries', data)

    def test_missing_csv_columns_and_invalid_files(self):
        """Test handling of CSV with missing columns, empty rows, and invalid uploads."""
        # 1. Empty CSV
        res = self.client.post('/api/import/wireshark', data={'file': (io.BytesIO(b''), 'empty.csv')}, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 201)
        data = json.loads(res.data)
        self.assertEqual(data['successful_records'], 0)

        # 2. Unsupported extension
        res_bad = self.client.post('/api/import/wireshark', data={'file': (io.BytesIO(b'hello'), 'bad.bin')}, content_type='multipart/form-data')
        self.assertEqual(res_bad.status_code, 400)

        # 3. CSV with missing columns and unparseable rows
        bad_csv = io.BytesIO(b'"colA","colB"\n"foo","bar"\n')
        res_unparseable = self.client.post('/api/import/wireshark', data={'file': (bad_csv, 'unknown.csv')}, content_type='multipart/form-data')
        self.assertEqual(res_unparseable.status_code, 201)
        data_unparseable = json.loads(res_unparseable.data)
        self.assertEqual(data_unparseable['successful_records'], 0)

    def test_relationship_graph_endpoint(self):
        """Test GET /api/graph endpoint with empty database and populated SQLite records."""
        # 1. Initial state (empty)
        with self.client.get('/api/graph') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['total_nodes'], 0)
            self.assertEqual(data['total_edges'], 0)
            self.assertEqual(data['nodes'], [])
            self.assertEqual(data['edges'], [])
            self.assertIn('disclaimer', data)

        # 2. Populate with demo records
        self.client.post('/api/events/demo')
        with self.client.get('/api/graph') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertGreater(data['total_nodes'], 0)
            self.assertGreater(data['total_edges'], 0)
            
            # Verify node schema
            first_node = data['nodes'][0]
            self.assertIn('id', first_node)
            self.assertIn('label', first_node)
            self.assertIn('type', first_node)
            self.assertIn('max_severity', first_node)
            
            # Verify edge schema and integrity reasons
            first_edge = data['edges'][0]
            self.assertIn('source', first_edge)
            self.assertIn('target', first_edge)
            self.assertIn('relation', first_edge)
            self.assertIn('reason', first_edge)
            self.assertTrue(len(first_edge['reason']) > 0)

        # 3. Clean up demo records
        self.client.delete('/api/events/demo')
        with self.client.get('/api/graph') as res:
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.data)
            self.assertEqual(data['total_nodes'], 0)

    def test_autopsy_all_formats_import(self):
        """Test Autopsy ingest supporting CSV, TSV, JSON, and SleuthKit Bodyfile formats."""
        # 1. Autopsy CSV Report
        csv_data = (
            '"File Name","File Path","Size","Modified Time","MD5 Hash","User","Comment"\n'
            '"evidence.doc","/home/analyst/evidence.doc","1024","2026-11-20 14:00:00","e99a18c428cb38d5f260853678922e03","analyst","Deleted document"\n'
        ).encode('utf-8')
        res_csv = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(csv_data), 'autopsy_report.csv')}, content_type='multipart/form-data')
        self.assertEqual(res_csv.status_code, 201)
        data_csv = json.loads(res_csv.data)
        self.assertEqual(data_csv['successful_records'], 1)
        self.assertEqual(data_csv['duplicate_records'], 0)

        # 2. Autopsy TSV Report
        tsv_data = (
            "File Name\tFile Path\tSize\tModified Time\tMD5 Hash\tUser\n"
            "id_rsa\t/home/analyst/.ssh/id_rsa\t2048\t2026-11-20 15:30:00\t5d41402abc4b2a76b9719d911017c592\tanalyst\n"
        ).encode('utf-8')
        res_tsv = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(tsv_data), 'autopsy_report.tsv')}, content_type='multipart/form-data')
        self.assertEqual(res_tsv.status_code, 201)
        data_tsv = json.loads(res_tsv.data)
        self.assertEqual(data_tsv['successful_records'], 1)

        # 3. Autopsy JSON Report
        json_obj = {
            "case_name": "CAINE-001",
            "artifacts": [
                {
                    "name": "places.sqlite",
                    "path": "/home/analyst/.mozilla/firefox/places.sqlite",
                    "size": 40960,
                    "modified": "2026-11-20 16:00:00",
                    "md5": "098f6bcd4621d373cade4e832627b4f6",
                    "comment": "Web history"
                }
            ]
        }
        json_data = json.dumps(json_obj).encode('utf-8')
        res_json = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(json_data), 'autopsy_export.json')}, content_type='multipart/form-data')
        self.assertEqual(res_json.status_code, 201)
        data_json = json.loads(res_json.data)
        self.assertEqual(data_json['successful_records'], 1)

        # 4. SleuthKit / Autopsy Bodyfile format (11 columns pipe delimited)
        bodyfile_data = (
            "0|/home/analyst/payload.sh (deleted)|1423|r/rrwxrwxrwx|1000|1000|512|1732100000|1732100000|1732100000|1732100000\n"
        ).encode('utf-8')
        res_body = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(bodyfile_data), 'autopsy_timeline.txt')}, content_type='multipart/form-data')
        self.assertEqual(res_body.status_code, 201)
        data_body = json.loads(res_body.data)
        self.assertEqual(data_body['successful_records'], 1)

        # Verify total in stats
        res_stats = self.client.get('/api/stats')
        stats = json.loads(res_stats.data)
        self.assertEqual(stats['sources']['autopsy'], 4)

    def test_autopsy_duplicate_prevention(self):
        """Test that importing the exact same Autopsy file twice prevents duplicates."""
        csv_data = (
            '"File Name","File Path","Size","Modified Time","MD5 Hash","User","Comment"\n'
            '"unique_file.bin","/tmp/unique_file.bin","4096","2026-11-20 18:00:00","d41d8cd98f00b204e9800998ecf8427e","root","Staging executable"\n'
        ).encode('utf-8')

        # First import
        res1 = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(csv_data), 'unique.csv')}, content_type='multipart/form-data')
        self.assertEqual(res1.status_code, 201)
        data1 = json.loads(res1.data)
        self.assertEqual(data1['successful_records'], 1)
        self.assertEqual(data1['duplicate_records'], 0)

        # Second import (exact duplicate)
        res2 = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(csv_data), 'unique.csv')}, content_type='multipart/form-data')
        self.assertEqual(res2.status_code, 201)
        data2 = json.loads(res2.data)
        self.assertEqual(data2['successful_records'], 0)
        self.assertEqual(data2['duplicate_records'], 1)

        # Confirm total events remained 1
        res_stats = self.client.get('/api/stats')
        stats = json.loads(res_stats.data)
        self.assertEqual(stats['sources']['autopsy'], 1)

    def test_autopsy_error_handling(self):
        """Test rejection of invalid formats, empty files, and malformed Autopsy content."""
        # 1. Empty file
        res_empty = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(b''), 'empty.csv')}, content_type='multipart/form-data')
        self.assertEqual(res_empty.status_code, 201)
        data_empty = json.loads(res_empty.data)
        self.assertEqual(data_empty['successful_records'], 0)

        # 2. Unsupported extension
        res_bad = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(b'dummy content'), 'bad.bin')}, content_type='multipart/form-data')
        self.assertEqual(res_bad.status_code, 400)

        # 3. CSV with empty unparseable rows
        unparseable_csv = io.BytesIO(b'"colA","colB"\n"",""\n')
        res_unparseable = self.client.post('/api/import/autopsy', data={'file': (unparseable_csv, 'unknown.csv')}, content_type='multipart/form-data')
        self.assertEqual(res_unparseable.status_code, 201)
        data_unparseable = json.loads(res_unparseable.data)
        self.assertEqual(data_unparseable['successful_records'], 0)

    def test_autopsy_timeline_and_graph_integration(self):
        """Test Autopsy records appearing in /api/timeline and /api/graph correctly."""
        csv_data = (
            '"File Name","File Path","Size","Modified Time","MD5 Hash","User","Comment"\n'
            '"passwords.kdbx","/Users/analyst/Documents/passwords.kdbx","8192","2026-11-20 12:00:00","1234567890abcdef1234567890abcdef","analyst","Credential vault"\n'
        ).encode('utf-8')
        res_import = self.client.post('/api/import/autopsy', data={'file': (io.BytesIO(csv_data), 'vault.csv')}, content_type='multipart/form-data')
        self.assertEqual(res_import.status_code, 201)

        # Verify /api/timeline?source=Autopsy
        res_timeline = self.client.get('/api/timeline?source=Autopsy')
        self.assertEqual(res_timeline.status_code, 200)
        timeline_events = json.loads(res_timeline.data)
        self.assertEqual(len(timeline_events), 1)
        self.assertEqual(timeline_events[0]['source'], 'Autopsy')
        self.assertIn('passwords.kdbx', timeline_events[0]['title'])

        # Verify /api/graph generates nodes and edges
        res_graph = self.client.get('/api/graph')
        self.assertEqual(res_graph.status_code, 200)
        graph_data = json.loads(res_graph.data)
        node_ids = [n['id'] for n in graph_data['nodes']]
        self.assertIn('user:analyst', node_ids)
        self.assertIn('file:passwords.kdbx', node_ids)
        self.assertGreater(graph_data['total_edges'], 0)

if __name__ == '__main__':
    unittest.main()
