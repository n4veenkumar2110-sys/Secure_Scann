import os
import sys
import re
import hashlib
import datetime
import uuid
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, g, Response
from werkzeug.utils import secure_filename

from config import Config
from database import get_db, close_db, init_db, query_db, modify_db
from parser_linux import parse_linux_audit_text
from collectors.wireshark_parser import (
    parse_wireshark_csv_text,
    parse_pcap_file,
    find_tshark_path,
    get_tshark_info
)
from parser_autopsy import parse_autopsy_csv_text, parse_autopsy_content
from collectors.windows_audit import parse_windows_audit_content
from collectors.sysmon_parser import parse_sysmon_json
from detections import run_detections
from urllib.parse import urlparse
import json
from collectors.live_capture import list_interfaces, capture_packets
from collectors.host_audit import run_collector as run_host_audit, audit_to_events
from collectors.autopsy_case import autopsy_info, find_autopsy, run_autopsy_ingest, import_case_database
import threading

# SECURITY: static_folder=None disables Flask's automatic static route.
# Previously static_folder='.' exposed EVERY file in the project over HTTP
# (the SQLite evidence database, uploaded evidence, source code, .venv).
# Only the three UI assets below are now served, via explicit routes.
app = Flask(__name__, static_folder=None)
app.config.from_object(Config)

BASE_DIR = Path(__file__).resolve().parent
SCENARIO_DIR = BASE_DIR / 'sample_data' / 'scenario'


@app.before_request
def enforce_same_origin():
    """CSRF defence: reject state-changing requests sent from another website.

    Browsers attach an Origin (or Referer) header to cross-site POST/DELETE
    requests. A malicious page could otherwise silently upload fake evidence or
    purge records from an analyst's local SecureScan instance.
    Non-browser clients (curl, scripts) send no Origin and are allowed.
    """
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    origin = request.headers.get('Origin') or request.headers.get('Referer')
    if not origin:
        return None
    if urlparse(origin).netloc != request.host:
        return jsonify({'error': 'Cross-origin request blocked (CSRF protection).'}), 403
    return None


@app.after_request
def apply_security_headers(response):
    """Defence-in-depth HTTP security headers."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    if request.path.startswith('/api/'):
        response.headers.setdefault('Cache-Control', 'no-store')
    return response

# Register teardown
app.teardown_appcontext(close_db)

# Ensure upload and instance directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
Path(app.config['INSTANCE_DIR']).mkdir(parents=True, exist_ok=True)

# Initialise database on startup
with app.app_context():
    init_db(app)

def allowed_file(filename):
    """Checks whether the uploaded file has a permissible extension."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']

def compute_sha256(content_bytes):
    """Computes SHA-256 checksum of file bytes for forensic integrity."""
    return hashlib.sha256(content_bytes).hexdigest()

def insert_events_batch(events_list, track_duplicates=False):
    """Inserts a batch of event dictionaries into SQLite using parameterised queries."""
    if not events_list:
        return (0, 0) if track_duplicates else 0
    db = get_db()
    sql = """
    INSERT INTO events (
        id, event_time, source, category, severity, title,
        username, source_ip, destination_ip, protocol, command,
        details, evidence_reference, is_demo, imported_at, raw_payload
    ) VALUES (
        :id, :event_time, :source, :category, :severity, :title,
        :username, :source_ip, :destination_ip, :protocol, :command,
        :details, :evidence_reference, :is_demo, :imported_at, :raw_payload
    )
    """
    inserted = 0
    duplicates = 0
    for e in events_list:
        try:
            db.execute(sql, e)
            inserted += 1
        except Exception as ex:
            if 'UNIQUE constraint failed' in str(ex):
                duplicates += 1
            else:
                raise ex
    db.commit()
    if track_duplicates:
        return inserted, duplicates
    return inserted

# =====================================================================
# STATIC ASSETS & FRONTEND SERVING
# =====================================================================

@app.route('/')
def serve_index():
    """Serves the primary SecureScan single-page UI."""
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/style.css')
def serve_css():
    """Serves the application CSS stylesheet."""
    return send_from_directory(BASE_DIR, 'style.css')

@app.route('/app.js')
def serve_js():
    """Serves the frontend controller JavaScript."""
    return send_from_directory(BASE_DIR, 'app.js')

@app.route('/README.txt')
def serve_readme():
    """Serves the project README file."""
    return send_from_directory(BASE_DIR, 'README.txt')

@app.route('/schema.sql')
def serve_schema():
    """Serves the SQLite schema file."""
    return send_from_directory(BASE_DIR, 'schema.sql')

# =====================================================================
# API: HEALTH & SYSTEM DIAGNOSTICS
# =====================================================================

@app.route('/health')
@app.route('/api/health')
def health():
    """Returns application health status and database connectivity."""
    try:
        row = query_db("SELECT COUNT(*) AS count FROM events", one=True)
        count = row['count'] if row else 0
        return jsonify({
            'status': 'ok',
            'database': 'connected',
            'database_path': app.config['DATABASE'],
            'total_events': count,
            'version': '1.0.0',
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'database': 'disconnected',
            'error': str(e)
        }), 500

# =====================================================================
# API: STATS & DASHBOARD AGGREGATION
# =====================================================================

@app.route('/api/stats')
def stats():
    """Returns real dashboard counts calculated directly from SQLite."""
    try:
        total_row = query_db("SELECT COUNT(*) AS total FROM events", one=True)
        total = total_row['total'] if total_row else 0

        # Severity distribution
        sev_rows = query_db("""
            SELECT severity, COUNT(*) as cnt
            FROM events
            GROUP BY severity
        """)
        sev_map = {r['severity']: r['cnt'] for r in sev_rows}

        # Source distribution
        src_rows = query_db("""
            SELECT source, COUNT(*) as cnt
            FROM events
            GROUP BY source
        """)
        src_map = {r['source']: r['cnt'] for r in src_rows}

        # Category distribution
        cat_rows = query_db("""
            SELECT category, COUNT(*) as cnt
            FROM events
            GROUP BY category
        """)
        cat_map = {r['category']: r['cnt'] for r in cat_rows}

        # Demo vs Real imported counts
        demo_row = query_db("SELECT COUNT(*) as cnt FROM events WHERE is_demo = 1", one=True)
        demo_cnt = demo_row['cnt'] if demo_row else 0
        imported_cnt = total - demo_cnt
        det = run_detections(_load_events_for_detection())

        return jsonify({
            'total_events': total,
            'critical': sev_map.get('Critical', 0),
            'high': sev_map.get('High', 0),
            'medium': sev_map.get('Medium', 0),
            'low': sev_map.get('Low', 0),
            'informational': sev_map.get('Informational', 0),
            'sources_count': len(src_map),
            'sources': {
                'windows_audit': src_map.get('Windows audit', 0),
                'sysmon': src_map.get('Sysmon', 0),
                'linux_audit': src_map.get('Linux audit', 0),
                'wireshark': src_map.get('Wireshark', 0),
                'autopsy': src_map.get('Autopsy', 0),
                'system_audit': src_map.get('System audit', 0)
            },
            'categories': {
                'authentication': cat_map.get('Authentication', 0),
                'process': cat_map.get('Process', 0),
                'network': cat_map.get('Network', 0),
                'forensic': cat_map.get('Forensic', 0),
                'account': cat_map.get('Account', 0),
                'system': cat_map.get('System', 0)
            },
            'demo_records': demo_cnt,
            'imported_records': imported_cnt,
            'detections': {'total': det['total'], 'risk_score': det['risk_score'],
                           'risk_level': det['risk_level'], 'severity_counts': det['severity_counts']}
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================================
# API: EVENTS (SEARCH, FILTER, TIMELINE)
# =====================================================================

@app.route('/api/events')
def get_events():
    """Returns events with optional search, source, category, and severity filtering."""
    try:
        source = request.args.get('source')
        category = request.args.get('category')
        severity = request.args.get('severity')
        search = request.args.get('search')
        limit = request.args.get('limit', default=1000, type=int)
        offset = request.args.get('offset', default=0, type=int)

        conditions = []
        params = []

        if source:
            if ',' in source:
                src_list = [s.strip() for s in source.split(',') if s.strip()]
                placeholders = ', '.join('?' for _ in src_list)
                conditions.append(f"source IN ({placeholders})")
                params.extend(src_list)
            else:
                conditions.append("source = ?")
                params.append(source)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if severity and severity.lower() != 'all':
            conditions.append("severity = ?")
            params.append(severity)
        if search:
            s_term = f"%{search.strip()}%"
            conditions.append("""
                (title LIKE ? OR username LIKE ? OR source_ip LIKE ? OR
                 destination_ip LIKE ? OR protocol LIKE ? OR command LIKE ? OR
                 details LIKE ? OR evidence_reference LIKE ? OR category LIKE ? OR source LIKE ?)
            """)
            params.extend([s_term] * 10)

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        query = f"""
            SELECT id, event_time, source, category, severity, title,
                   username, source_ip, destination_ip, protocol, command,
                   details, evidence_reference, is_demo, imported_at
            FROM events
            {where_clause}
            ORDER BY event_time DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        rows = query_db(query, params)
        events_list = [dict(r) for r in rows]
        # Ensure is_demo is boolean
        for e in events_list:
            e['is_demo'] = bool(e['is_demo'])

        return jsonify(events_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/timeline')
def get_timeline():
    """Returns chronological timeline events across all evidence sources."""
    try:
        search = request.args.get('search')
        severity = request.args.get('severity')
        source = request.args.get('source')
        limit = request.args.get('limit', default=500, type=int)

        conditions = []
        params = []

        if source and source.lower() != 'all':
            if ',' in source:
                src_list = [s.strip() for s in source.split(',') if s.strip()]
                placeholders = ', '.join('?' for _ in src_list)
                conditions.append(f"source IN ({placeholders})")
                params.extend(src_list)
            else:
                conditions.append("source = ?")
                params.append(source)

        if severity and severity.lower() != 'all':
            conditions.append("severity = ?")
            params.append(severity)
        if search:
            s_term = f"%{search.strip()}%"
            conditions.append("""
                (title LIKE ? OR details LIKE ? OR evidence_reference LIKE ? OR
                 username LIKE ? OR source LIKE ? OR category LIKE ?)
            """)
            params.extend([s_term] * 6)

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        query = f"""
            SELECT id, event_time, source, category, severity, title,
                   username, source_ip, destination_ip, protocol, command,
                   details, evidence_reference, is_demo, imported_at
            FROM events
            {where_clause}
            ORDER BY event_time DESC
            LIMIT ?
        """
        params.append(limit)
        rows = query_db(query, params)
        result = [dict(r) for r in rows]
        for e in result:
            e['is_demo'] = bool(e['is_demo'])
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/graph')
def get_relationship_graph():
    """Generates an entity-relationship graph (nodes & edges) from actual imported SQLite events."""
    try:
        events = query_db("""
            SELECT id, event_time, source, category, severity, title,
                   username, source_ip, destination_ip, protocol, command,
                   details, evidence_reference, is_demo
            FROM events
            ORDER BY event_time DESC
            LIMIT 500
        """)

        nodes_dict = {}
        edges_map = {}

        def get_or_create_node(node_id, label, ntype, severity='Low', metadata=None):
            if node_id not in nodes_dict:
                nodes_dict[node_id] = {
                    'id': node_id,
                    'label': label,
                    'type': ntype,
                    'count': 0,
                    'max_severity': severity,
                    'metadata': metadata or {}
                }
            nodes_dict[node_id]['count'] += 1
            sev_weights = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1}
            cur_weight = sev_weights.get(nodes_dict[node_id]['max_severity'], 1)
            new_weight = sev_weights.get(severity, 1)
            if new_weight > cur_weight:
                nodes_dict[node_id]['max_severity'] = severity
            return node_id

        def add_edge(src_id, tgt_id, relation, details, event_id, severity):
            if not src_id or not tgt_id or src_id == tgt_id:
                return
            key = f"{src_id}->{tgt_id}:{relation}"
            if key not in edges_map:
                edges_map[key] = {
                    'id': key,
                    'source': src_id,
                    'target': tgt_id,
                    'relation': relation,
                    'reason': details,
                    'count': 0,
                    'events': [],
                    'severity': severity
                }
            edges_map[key]['count'] += 1
            if len(edges_map[key]['events']) < 6:
                edges_map[key]['events'].append({
                    'event_id': event_id,
                    'details': details,
                    'severity': severity
                })

        for ev in events:
            ev_id = ev['id']
            user = (ev['username'] or '').strip()
            src_ip = (ev['source_ip'] or '').strip()
            dst_ip = (ev['destination_ip'] or '').strip()
            cmd = (ev['command'] or '').strip()
            details = (ev['details'] or '').strip()
            title = (ev['title'] or '').strip()
            source = ev['source']
            sev = ev['severity'] or 'Low'

            user_node_id = None
            if user and user not in ('—', 'None', 'SYSTEM', 'LOCAL SYSTEM', 'ANONYMOUS LOGON'):
                user_node_id = get_or_create_node(f"user:{user}", user, 'user', sev, {'source': source})
            elif user in ('SYSTEM', 'LOCAL SYSTEM'):
                user_node_id = get_or_create_node("user:SYSTEM", "SYSTEM", 'user', 'Informational', {'source': source})

            if source == 'Autopsy' and not user_node_id:
                m_u = re.search(r'(?:[/\\]Users[/\\]|[/\\]home[/\\])([^/\\]+)', details, re.I)
                if m_u:
                    prof_user = m_u.group(1).strip()
                    if prof_user and prof_user not in ('—', 'None', 'SYSTEM', 'Public', 'Default'):
                        user_node_id = get_or_create_node(f"user:{prof_user}", prof_user, 'user', sev, {'source': 'Autopsy'})

            # Process extraction
            proc_name = None
            if cmd:
                tokens = cmd.replace('\\', '/').split()
                if tokens:
                    first = tokens[0].rstrip(';,"\'').split('/')[-1]
                    if '.' in first and len(first) <= 40:
                        proc_name = first.lower()
            if not proc_name and 'Process' in (ev['category'] or ''):
                m = re.search(r'([a-zA-Z0-9_\-\.]+\.exe)', details, re.I)
                if m:
                    proc_name = m.group(1).lower()

            proc_node_id = None
            if proc_name:
                proc_node_id = get_or_create_node(f"proc:{proc_name}", proc_name, 'process', sev, {'cmd': cmd[:100]})

            if user_node_id and proc_node_id:
                add_edge(user_node_id, proc_node_id, 'executed', f"{user} executed {proc_name}", ev_id, sev)

            # Network / IP extraction
            target_ip = dst_ip if (dst_ip and dst_ip != '—') else (src_ip if (src_ip and src_ip not in ('—', '127.0.0.1', '::1', 'Local / System')) else None)
            net_node_id = None
            if target_ip and target_ip not in ('—', 'Local / System', 'System'):
                net_node_id = get_or_create_node(f"ip:{target_ip}", target_ip, 'network', sev, {'protocol': ev['protocol']})
                if proc_node_id:
                    add_edge(proc_node_id, net_node_id, 'network_connect', f"{proc_name} communicated with {target_ip}", ev_id, sev)
                elif user_node_id:
                    add_edge(user_node_id, net_node_id, 'logged_in_from', f"{user} logged in from {target_ip}", ev_id, sev)

            # DNS Query extraction
            m_dns = re.search(r'(?:DNS query|QueryName)[:\s]+([a-zA-Z0-9\-\._]+\.[a-zA-Z]{2,})', details, re.I)
            if m_dns:
                dns_query = m_dns.group(1).lower()
                dns_node_id = get_or_create_node(f"dns:{dns_query}", dns_query, 'dns', sev, {})
                if proc_node_id:
                    add_edge(proc_node_id, dns_node_id, 'dns_lookup', f"{proc_name} queried {dns_query}", ev_id, sev)
                elif net_node_id:
                    add_edge(net_node_id, dns_node_id, 'resolves_to', f"{target_ip} resolved {dns_query}", ev_id, sev)

            # File / Artifact extraction (Windows, Sysmon, and Autopsy forensic findings)
            fname = None
            if source == 'Autopsy':
                m_title = re.search(r"'(.*?)'", title)
                if m_title:
                    fname = m_title.group(1).split('\\')[-1].split('/')[-1]
                if not fname:
                    m_path = re.search(r'Path:\s*([^\s|]+)', details)
                    if m_path:
                        fname = m_path.group(1).split('\\')[-1].split('/')[-1]
            if not fname:
                m_file = re.search(r'(?:TargetFilename|Target File|File created|Deleted file|File|Path)[:\s]+([a-zA-Z0-9_\-\.\\]+)', details, re.I)
                if m_file:
                    first_part = m_file.group(1).strip()
                    if '.' in first_part or len(first_part) > 2:
                        fname = first_part.split('\\')[-1].split('/')[-1]

            if fname and fname not in ('—', 'None', '', 'file'):
                fhash_m = re.search(r'Hash:\s*([a-fA-F0-9]{32,64})|MD5:\s*([a-fA-F0-9]{32})', details)
                file_meta = {'hash': fhash_m.group(1) or fhash_m.group(2)} if fhash_m else {}
                file_node_id = get_or_create_node(f"file:{fname.lower()}", fname, 'file', sev, file_meta)
                if proc_node_id:
                    add_edge(proc_node_id, file_node_id, 'created_file', f"{proc_name} created/accessed {fname}", ev_id, sev)
                elif user_node_id:
                    rel = 'recovered_file' if 'deleted' in title.lower() else 'accessed_file'
                    add_edge(user_node_id, file_node_id, rel, f"{user} associated with {fname} (Autopsy finding)", ev_id, sev)

            # USB / External Device extraction from Autopsy
            if 'device' in title.lower() or 'usb' in details.lower():
                m_dev = re.search(r"'(.*?)'", title)
                dev_name = m_dev.group(1) if m_dev else None
                if not dev_name:
                    m_dev_details = re.search(r"Device:\s*([^\s|]+)", details)
                    if m_dev_details:
                        dev_name = m_dev_details.group(1)
                if dev_name:
                    dev_node_id = get_or_create_node(f"dev:{dev_name.lower()}", dev_name, 'network', sev, {'category': 'USB Device'})
                    if user_node_id:
                        add_edge(user_node_id, dev_node_id, 'attached_device', f"{user} connected device {dev_name} (Autopsy)", ev_id, sev)

        return jsonify({
            'nodes': list(nodes_dict.values()),
            'edges': list(edges_map.values()),
            'total_nodes': len(nodes_dict),
            'total_edges': len(edges_map),
            'disclaimer': 'Topological correlations represent observed system and network telemetry. Correlation does not imply or constitute definitive proof of malicious activity.'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# API: CORRELATION & DETECTION ENGINE (MITRE ATT&CK)
# =====================================================================

def _load_events_for_detection(limit=20000):
    return query_db("""
        SELECT id, event_time, source, category, severity, title, username,
               source_ip, destination_ip, protocol, command, details,
               evidence_reference, is_demo
        FROM events ORDER BY event_time ASC LIMIT ?
    """, (limit,))


@app.route('/api/detections')
def get_detections():
    """Runs correlation rules over all stored evidence and returns detections."""
    try:
        return jsonify(run_detections(_load_events_for_detection())), 200
    except Exception as e:
        app.logger.exception('Detection engine failure')
        return jsonify({'error': f'Detection engine failed: {e}'}), 500


# =====================================================================
# API: ATTACK SCENARIO (multi-source demo routed through the REAL parsers)
# =====================================================================

@app.route('/api/scenario', methods=['POST'])
def load_attack_scenario():
    """Loads the bundled 'Operation Night Owl' incident dataset.

    Unlike /api/events/demo (hand-written rows), each scenario file is passed
    through the same parser a real upload would use, so the scenario exercises
    the full ingest pipeline. Records are flagged is_demo=1 and are removed by
    'Clear demo'.
    """
    plan = [
        ('windows_security.json', lambda t: parse_windows_audit_content(t)),
        ('sysmon.json',           lambda t: parse_sysmon_json(t)),
        ('linux_audit.log',       lambda t: parse_linux_audit_text(t, import_ref_prefix='SCN-AUDIT')),
        ('network_capture.csv',   lambda t: parse_wireshark_csv_text(t, import_ref_prefix='SCN-PCAP',
                                                                     filename='network_capture.csv')),
        ('autopsy_findings.csv',  lambda t: parse_autopsy_content(t, filename='autopsy_findings.csv',
                                                                  import_ref_prefix='SCN-AUT')),
    ]
    if not SCENARIO_DIR.is_dir():
        return jsonify({'error': 'Scenario dataset not found (sample_data/scenario).'}), 404

    loaded, per_file = 0, {}
    for fname, parser in plan:
        path = SCENARIO_DIR / fname
        if not path.is_file():
            continue
        records, ok, _failed = parser(path.read_text(encoding='utf-8'))
        for r in records:
            r['is_demo'] = 1
            r['id'] = 'scn-' + r['id']           # keep scenario IDs separate from real imports
            r['details'] = 'SCENARIO: ' + (r.get('details') or '')
        inserted, _dups = insert_events_batch(records, track_duplicates=True)
        per_file[fname] = inserted
        loaded += inserted

    return jsonify({
        'status': 'ok',
        'message': f'Attack scenario loaded: {loaded} events across {len(per_file)} evidence sources '
                   f'(marked DEMO). Open Threat Detections to see the correlated incident.',
        'added_count': loaded,
        'files': per_file,
    }), 201


# =====================================================================
# API: LIVE SYSTEM AUDIT (Wireshark/TShark capture + Windows host audit)
# =====================================================================

def _record_import(import_id, original_fn, stored_fn, source_label, sha256, total, inserted, failed):
    modify_db("""
        INSERT INTO imports (id, original_filename, stored_filename, source_type,
                             sha256_hash, total_records, successful_records, failed_records, imported_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (import_id, original_fn, stored_fn, source_label, sha256, total, inserted, failed,
          datetime.datetime.now(datetime.timezone.utc).isoformat()))


def _stamp():
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]


@app.route('/api/capture/interfaces')
def capture_interfaces():
    """Lists the network interfaces TShark can capture on."""
    info = get_tshark_info()
    return jsonify({'tshark': info, 'interfaces': list_interfaces() if info['available'] else []}), 200


@app.route('/api/capture/live', methods=['POST'])
def capture_live():
    """Captures live traffic with TShark, stores the .pcapng as evidence and imports it."""
    body = request.get_json(silent=True) or {}
    try:
        duration = int(body.get('duration', 20))
        max_packets = int(body.get('max_packets', 2000))
    except (TypeError, ValueError):
        return jsonify({'error': 'duration and max_packets must be integers.'}), 400

    stored_fn = f"{_stamp()}_live_capture.pcapng"
    target = Path(app.config['UPLOAD_FOLDER']) / stored_fn
    try:
        meta = capture_packets(body.get('interface'), duration, max_packets, target,
                               capture_filter=(body.get('filter') or '').strip())
        sha256 = compute_sha256(target.read_bytes())
        records, ok, failed = parse_pcap_file(target, import_ref_prefix='LIVE', capture_hash=sha256,
                                              timeout=120)
        inserted, dups = insert_events_batch(records, track_duplicates=True) if ok else (0, 0)
        import_id = f"imp-live-{uuid.uuid4().hex[:10]}"
        _record_import(import_id, f"live capture on {meta['interface']}", stored_fn,
                       'Wireshark live capture', sha256, ok + failed, inserted, failed)
        return jsonify({
            'status': 'ok',
            'message': f"Captured {meta.get('packets_captured') or ok} packets on {meta['interface']} "
                       f"in {meta['duration_seconds']} s; {inserted} packet records imported.",
            'capture': meta, 'sha256_hash': sha256, 'stored_file': stored_fn,
            'successful_records': inserted, 'failed_records': failed, 'import_id': import_id,
        }), 201
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except (RuntimeError, TimeoutError, FileNotFoundError) as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/audit/host', methods=['POST'])
def audit_host():
    """Runs the read-only Windows host audit and stores its findings as evidence."""
    if os.name != 'nt':
        return jsonify({'error': 'The host audit collector runs on Windows only.'}), 400
    try:
        data = run_host_audit()
    except Exception as e:
        return jsonify({'error': f'Host audit failed: {e}'}), 500

    raw = json.dumps(data, indent=2).encode('utf-8')
    sha256 = compute_sha256(raw)
    stored_fn = f"{_stamp()}_host_audit.json"
    (Path(app.config['UPLOAD_FOLDER']) / stored_fn).write_bytes(raw)

    records, checks, meta = audit_to_events(data, raw_hash=sha256)
    inserted, _ = insert_events_batch(records, track_duplicates=True)
    import_id = f"imp-host-{uuid.uuid4().hex[:10]}"
    _record_import(import_id, f"host audit of {meta['computer']}", stored_fn, 'System audit',
                   sha256, len(records), inserted, 0)
    return jsonify({
        'status': 'ok',
        'message': f"System audit of {meta['computer']} complete: {len(checks)} checks, {inserted} records stored.",
        'meta': meta, 'checks': checks, 'sha256_hash': sha256, 'import_id': import_id,
        'findings': [{'severity': r['severity'], 'title': r['title']} for r in records
                     if r['severity'] not in ('Informational',)],
    }), 201


AUTOPSY_JOBS = {}
AUTOPSY_LOCK = threading.Lock()


def _store_autopsy_case(case_path, label):
    """Imports an Autopsy case DB into SQLite (must run inside an app context)."""
    records, summary = import_case_database(case_path)
    inserted, dups = insert_events_batch(records, track_duplicates=True)
    import_id = f"imp-autcase-{uuid.uuid4().hex[:10]}"
    _record_import(import_id, label, summary['case_db'], 'Autopsy case', summary['case_db_sha256'],
                   len(records), inserted, 0)
    summary.update({'inserted': inserted, 'duplicates_skipped': dups, 'import_id': import_id})
    return summary


@app.route('/api/autopsy/status')
def autopsy_status():
    info = autopsy_info()
    info['case_base_dir'] = str(Path(app.config['INSTANCE_DIR']) / 'autopsy_cases')
    with AUTOPSY_LOCK:
        info['jobs'] = sorted(AUTOPSY_JOBS.values(), key=lambda j: j['started'], reverse=True)[:10]
    return jsonify(info), 200


@app.route('/api/autopsy/import-case', methods=['POST'])
def autopsy_import_case():
    """Imports an existing Autopsy case (folder, .aut file or autopsy.db) read-only."""
    path = ((request.get_json(silent=True) or {}).get('path') or '').strip().strip('"')
    if not path:
        return jsonify({'error': 'Provide the path of an Autopsy case folder, .aut file or autopsy.db.'}), 400
    try:
        summary = _store_autopsy_case(path, f'Autopsy case {Path(path).name}')
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to read Autopsy case: {e}'}), 500
    return jsonify({'status': 'ok', 'summary': summary,
                    'message': f"Imported Autopsy case {summary['case_name']}: {summary['files_total']} files, "
                               f"{summary['files_flagged']} flagged, {summary['inserted']} records stored."}), 201


@app.route('/api/autopsy/analyze', methods=['POST'])
def autopsy_analyze():
    """Starts Autopsy command-line ingest on a folder or disk image (background job)."""
    if not find_autopsy():
        return jsonify({'error': 'Autopsy is not installed on this workstation.'}), 400
    path = ((request.get_json(silent=True) or {}).get('path') or '').strip().strip('"')
    if not path or not Path(path).exists():
        return jsonify({'error': f'Data source not found: {path or "(empty)"}'}), 400
    with AUTOPSY_LOCK:
        if any(j['status'] == 'running' for j in AUTOPSY_JOBS.values()):
            return jsonify({'error': 'An Autopsy analysis is already running.'}), 409
        job_id = f"aut-{uuid.uuid4().hex[:8]}"
        AUTOPSY_JOBS[job_id] = {'id': job_id, 'source': path, 'status': 'running', 'message': 'Starting Autopsy...',
                                'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'summary': None}
    case_base = Path(app.config['INSTANCE_DIR']) / 'autopsy_cases'

    def worker():
        def progress(msg):
            with AUTOPSY_LOCK:
                AUTOPSY_JOBS[job_id]['message'] = msg
        try:
            case_dir = run_autopsy_ingest(path, case_base, case_name='SecureScanAudit', progress=progress)
            progress('Autopsy finished - importing case database...')
            with app.app_context():
                summary = _store_autopsy_case(case_dir, f'Autopsy analysis of {Path(path).name}')
            with AUTOPSY_LOCK:
                AUTOPSY_JOBS[job_id].update(status='done', summary=summary,
                                            message=f"Done: {summary['files_total']} files analysed, "
                                                    f"{summary['files_flagged']} flagged.")
        except Exception as e:
            with AUTOPSY_LOCK:
                AUTOPSY_JOBS[job_id].update(status='error', message=str(e))

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'status': 'started', 'job_id': job_id,
                    'message': 'Autopsy analysis started. This usually takes 1-5 minutes.'}), 202


@app.route('/api/autopsy/jobs/<job_id>')
def autopsy_job(job_id):
    with AUTOPSY_LOCK:
        job = AUTOPSY_JOBS.get(job_id)
    return (jsonify(job), 200) if job else (jsonify({'error': 'Unknown job'}), 404)


@app.route('/api/audit/host/latest')
def audit_host_latest():
    """Returns the check results of the most recent host audit (re-derived from its stored JSON)."""
    row = query_db("SELECT * FROM imports WHERE source_type = 'System audit' ORDER BY imported_at DESC LIMIT 1",
                   one=True)
    if not row:
        return jsonify({'available': False}), 200
    path = Path(app.config['UPLOAD_FOLDER']) / row['stored_filename']
    if not path.is_file():
        return jsonify({'available': False}), 200
    _records, checks, meta = audit_to_events(json.loads(path.read_text(encoding='utf-8')), raw_hash=row['sha256_hash'])
    return jsonify({'available': True, 'meta': meta, 'checks': checks, 'sha256_hash': row['sha256_hash'],
                    'imported_at': row['imported_at']}), 200

# =====================================================================
# API: DEMONSTRATION RECORDS (CREATE & PURGE)
# =====================================================================

@app.route('/api/events/demo', methods=['POST'])
def generate_demo_events():
    """Generates clearly marked demonstration events for demonstration."""
    now = datetime.datetime.now(datetime.timezone.utc)
    base_ts = now.timestamp()
    iso_now = now.isoformat()

    samples = [
        {
            'mins': 3,
            'source': 'Linux audit',
            'category': 'Authentication',
            'severity': 'High',
            'title': 'Multiple failed login attempts',
            'username': 'analyst',
            'source_ip': '192.168.1.24',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': 'DEMO: Several authentication failures recorded for analyst. Rule: High failure rate indicates potential unauthorized access attempt.',
            'evidence_reference': 'DEMO-AUD-001'
        },
        {
            'mins': 11,
            'source': 'Linux audit',
            'category': 'Account',
            'severity': 'Medium',
            'title': 'New local account created',
            'username': 'labuser',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': 'useradd labuser',
            'details': 'DEMO: Account creation event observed in imported audit record. Rule: Provisioning of new local user account.',
            'evidence_reference': 'DEMO-AUD-002'
        },
        {
            'mins': 19,
            'source': 'Linux audit',
            'category': 'Process',
            'severity': 'Low',
            'title': 'Shell command executed',
            'username': 'analyst',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '/usr/bin/id',
            'details': 'DEMO: Command execution record collected. Rule: Standard privilege check process execution.',
            'evidence_reference': 'DEMO-AUD-003'
        },
        {
            'mins': 27,
            'source': 'Wireshark',
            'category': 'Network',
            'severity': 'Informational',
            'title': 'DNS query observed',
            'username': '',
            'source_ip': '192.168.1.10',
            'destination_ip': '1.1.1.1',
            'protocol': 'DNS',
            'command': '',
            'details': 'DEMO: DNS name resolution request captured by Wireshark. Payload: Standard A query for lab-service.internal.',
            'evidence_reference': 'DEMO-PCAP-001'
        },
        {
            'mins': 35,
            'source': 'Wireshark',
            'category': 'Network',
            'severity': 'Low',
            'title': 'HTTPS connection observed',
            'username': '',
            'source_ip': '192.168.1.10',
            'destination_ip': '142.250.72.14',
            'protocol': 'TLS',
            'command': '',
            'details': 'DEMO: Encrypted TLS transport session observed. Payload contents are encrypted and not inferred.',
            'evidence_reference': 'DEMO-PCAP-002'
        },
        {
            'mins': 43,
            'source': 'Autopsy',
            'category': 'Forensic',
            'severity': 'Medium',
            'title': 'Recently deleted file entry',
            'username': '',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': 'DEMO: Deleted file entry recorded from Autopsy filesystem examination: /home/labuser/Documents/notes.txt (Size: 104 bytes).',
            'evidence_reference': 'DEMO-AUT-001'
        },
        {
            'mins': 51,
            'source': 'Autopsy',
            'category': 'Forensic',
            'severity': 'Informational',
            'title': 'Browser history artefact found',
            'username': '',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': 'DEMO: Browser history SQLite artefact extracted from disk image: /home/labuser/.config/browser/history.',
            'evidence_reference': 'DEMO-AUT-002'
        },
        {
            'mins': 5,
            'source': 'Windows audit',
            'category': 'Authentication',
            'severity': 'High',
            'title': 'Event 4625: Multiple failed logon attempts for analyst',
            'username': 'analyst',
            'source_ip': '192.168.1.50',
            'destination_ip': '',
            'protocol': 'NTLM',
            'command': '',
            'details': 'DEMO: Windows 11 Security Log Event 4625. Multiple logon failures recorded from 192.168.1.50. Rule: High failure rate indicates brute-force attempt.',
            'evidence_reference': 'DEMO-WIN-4625'
        },
        {
            'mins': 15,
            'source': 'Windows audit',
            'category': 'Process',
            'severity': 'Medium',
            'title': 'Event 4688: Recon process executed: whoami.exe /priv',
            'username': 'analyst',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': 'C:\\Windows\\System32\\whoami.exe /priv',
            'details': 'DEMO: Windows 11 Security Event 4688. Command-line reconnaissance binary executed to query user privileges.',
            'evidence_reference': 'DEMO-WIN-4688'
        },
        {
            'mins': 22,
            'source': 'Sysmon',
            'category': 'Network',
            'severity': 'Medium',
            'title': 'Sysmon 3: Outbound connection from powershell.exe to 142.250.72.14:443',
            'username': 'analyst',
            'source_ip': '192.168.1.10',
            'destination_ip': '142.250.72.14',
            'protocol': 'TCP',
            'command': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'details': 'DEMO: Microsoft Sysmon Event ID 3. Script interpreter initiated an outbound connection to remote destination 142.250.72.14:443.',
            'evidence_reference': 'DEMO-SYS-003'
        }
    ]

    records = []
    for i, s in enumerate(samples):
        event_time = datetime.datetime.fromtimestamp(base_ts - s['mins'] * 60, tz=datetime.timezone.utc).isoformat()
        records.append({
            'id': f"demo-{int(base_ts)}-{i+1}",
            'event_time': event_time,
            'source': s['source'],
            'category': s['category'],
            'severity': s['severity'],
            'title': s['title'],
            'username': s['username'],
            'source_ip': s['source_ip'],
            'destination_ip': s['destination_ip'],
            'protocol': s['protocol'],
            'command': s['command'],
            'details': s['details'],
            'evidence_reference': s['evidence_reference'],
            'is_demo': 1,
            'imported_at': iso_now,
            'raw_payload': 'DEMO_SYNTHETIC_EVENT'
        })

    insert_events_batch(records)
    return jsonify({
        'status': 'ok',
        'message': f'{len(records)} demo events generated successfully. Marked is_demo = true.',
        'added_count': len(records)
    }), 201

@app.route('/api/events/demo', methods=['DELETE'])
def clear_demo_events():
    """Deletes only demo records from the SQLite database."""
    try:
        db = get_db()
        cur = db.execute("DELETE FROM events WHERE is_demo = 1")
        deleted_count = cur.rowcount
        db.commit()
        cur.close()
        return jsonify({
            'status': 'ok',
            'message': f'{deleted_count} demo records deleted. Real evidence preserved.',
            'deleted_count': deleted_count
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================================
# API: EVIDENCE IMPORTS (LINUX AUDIT, WIRESHARK, AUTOPSY)
# =====================================================================

def save_and_log_upload(file_obj, source_type):
    """Safely saves an uploaded evidence file and calculates its SHA-256 hash."""
    if not file_obj or file_obj.filename == '':
        raise ValueError("No file provided.")
    if not allowed_file(file_obj.filename):
        raise ValueError(f"Unsupported file format. Permitted extensions: {', '.join(app.config['ALLOWED_EXTENSIONS'])}")

    original_filename = secure_filename(file_obj.filename)
    unique_prefix = datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + "_" + uuid.uuid4().hex[:6]
    stored_filename = f"{unique_prefix}_{original_filename}"
    target_path = Path(app.config['UPLOAD_FOLDER']) / stored_filename

    # Read bytes to verify size and compute SHA-256
    content_bytes = file_obj.read()
    if len(content_bytes) > app.config['MAX_CONTENT_LENGTH']:
        raise ValueError("File exceeds maximum permissible size of 10 MB.")

    sha256_hash = compute_sha256(content_bytes)

    # Save original file safely
    with open(target_path, 'wb') as f:
        f.write(content_bytes)

    return target_path, original_filename, stored_filename, sha256_hash, content_bytes

@app.route('/api/import/linux-audit', methods=['POST'])
def import_linux_audit():
    """Imports Linux auditd log files (.log, .txt) into SQLite."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400
    
    file_obj = request.files['file']
    try:
        target_path, original_fn, stored_fn, sha256, content_bytes = save_and_log_upload(file_obj, 'audit_log')
        text_content = content_bytes.decode('utf-8', errors='replace')
        
        import_id = f"imp-audit-{uuid.uuid4().hex[:10]}"
        records, successful, failed = parse_linux_audit_text(text_content, import_ref_prefix="AUDIT")

        inserted, duplicates = 0, 0
        if successful > 0:
            inserted, duplicates = insert_events_batch(records, track_duplicates=True)

        # Log into imports table
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        modify_db("""
            INSERT INTO imports (
                id, original_filename, stored_filename, source_type,
                sha256_hash, total_records, successful_records, failed_records, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (import_id, original_fn, stored_fn, 'Linux audit', sha256, successful + failed, inserted, failed, now_iso))

        dup_msg = f", {duplicates} duplicate records skipped" if duplicates else ""
        return jsonify({
            'status': 'ok',
            'message': f'Successfully imported {inserted} Linux audit records ({failed} unparseable lines skipped{dup_msg}).',
            'import_id': import_id,
            'sha256_hash': sha256,
            'total_records': successful + failed,
            'successful_records': inserted,
            'duplicates_skipped': duplicates,
            'failed_records': failed
        }), 201

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to process audit log: {str(e)}'}), 500

@app.route('/api/import/wireshark', methods=['POST'])
@app.route('/api/import/pcap', methods=['POST'])
def import_wireshark():
    """Imports Wireshark packet dissection CSV export files or raw PCAP/PCAPNG captures into SQLite."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file_obj = request.files['file']
    if not file_obj or file_obj.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename_lower = file_obj.filename.lower()
    is_pcap = filename_lower.endswith('.pcap') or filename_lower.endswith('.pcapng')

    try:
        source_type_tag = 'wireshark_pcap' if is_pcap else 'wireshark_csv'
        target_path, original_fn, stored_fn, sha256, content_bytes = save_and_log_upload(file_obj, source_type_tag)

        import_id = f"imp-pcap-{uuid.uuid4().hex[:10]}"
        records = []
        successful = 0
        failed = 0

        if is_pcap:
            tshark_info = get_tshark_info()
            if not tshark_info['available']:
                return jsonify({
                    'error': (
                        "TShark is required to process .pcap and .pcapng files directly. "
                        "Please install Wireshark with TShark from https://www.wireshark.org "
                        "or export packet dissections as CSV from Wireshark (File > Export Packet Dissections > As CSV...)."
                    ),
                    'tshark_status': tshark_info
                }), 400

            records, successful, failed = parse_pcap_file(target_path, import_ref_prefix="PCAP", capture_hash=sha256)
        else:
            text_content = content_bytes.decode('utf-8', errors='replace')
            records, successful, failed = parse_wireshark_csv_text(
                text_content, import_ref_prefix="WIRESHARK", filename=original_fn, capture_hash=sha256
            )

        inserted = 0
        duplicates = 0
        if successful > 0:
            inserted, duplicates = insert_events_batch(records, track_duplicates=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_label = 'Wireshark PCAP' if is_pcap else 'Wireshark'
        modify_db("""
            INSERT INTO imports (
                id, original_filename, stored_filename, source_type,
                sha256_hash, total_records, successful_records, failed_records, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (import_id, original_fn, stored_fn, source_label, sha256, successful + failed, inserted, failed, now_iso))

        dup_msg = f" ({duplicates} duplicate packets skipped)" if duplicates else ""
        file_kind = "PCAP/PCAPNG capture" if is_pcap else "Wireshark CSV"
        return jsonify({
            'status': 'ok',
            'message': f'Successfully imported {inserted} {file_kind} packet records{dup_msg}.',
            'import_id': import_id,
            'sha256_hash': sha256,
            'total_records': successful + failed,
            'successful_records': inserted,
            'duplicates_skipped': duplicates,
            'failed_records': failed
        }), 201

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except TimeoutError as te:
        return jsonify({'error': f'PCAP processing timed out: {str(te)}'}), 504
    except Exception as e:
        return jsonify({'error': f'Failed to process network capture: {str(e)}'}), 500

@app.route('/api/network/stats')
def network_stats():
    """Returns dedicated network analysis aggregates directly from SQLite."""
    try:
        # Total network events
        total_row = query_db("""
            SELECT COUNT(*) AS total
            FROM events
            WHERE category = 'Network' OR source = 'Wireshark'
        """, one=True)
        total_packets = total_row['total'] if total_row else 0

        # Protocols distribution
        proto_rows = query_db("""
            SELECT protocol, COUNT(*) as cnt
            FROM events
            WHERE (category = 'Network' OR source = 'Wireshark') AND protocol IS NOT NULL AND protocol != ''
            GROUP BY protocol
            ORDER BY cnt DESC
        """)
        protocols = {r['protocol']: r['cnt'] for r in proto_rows}

        # Top Source IPs
        src_rows = query_db("""
            SELECT source_ip, COUNT(*) as cnt
            FROM events
            WHERE (category = 'Network' OR source = 'Wireshark') AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 8
        """)
        top_sources = [{'ip': r['source_ip'], 'count': r['cnt']} for r in src_rows]

        # Top Destination IPs
        dst_rows = query_db("""
            SELECT destination_ip, COUNT(*) as cnt
            FROM events
            WHERE (category = 'Network' OR source = 'Wireshark') AND destination_ip IS NOT NULL AND destination_ip != ''
            GROUP BY destination_ip
            ORDER BY cnt DESC
            LIMIT 8
        """)
        top_destinations = [{'ip': r['destination_ip'], 'count': r['cnt']} for r in dst_rows]

        # DNS queries extracted from details / title
        dns_rows = query_db("""
            SELECT title, details, command, is_demo
            FROM events
            WHERE (category = 'Network' OR source = 'Wireshark')
              AND (protocol = 'DNS' OR title LIKE '%DNS%' OR details LIKE '%DNS Query%')
            ORDER BY event_time DESC
            LIMIT 50
        """)
        dns_queries = []
        seen_queries = set()
        for r in dns_rows:
            q_match = re.search(r"DNS Query:\s*([a-zA-Z0-9_\-\.]+)|query:\s*'([^']+)'|query\s+(?:0x[0-9a-fA-F]+\s+)?(?:response\s+)?(?:0x[0-9a-fA-F]+\s+)?[A-Z0-9]*\s*([a-zA-Z0-9_\-\.]+)", (r['details'] or '') + ' ' + (r['title'] or ''))
            if q_match:
                q_name = q_match.group(1) or q_match.group(2) or q_match.group(3)
                if q_name and '.' in q_name and not q_name.startswith('0x') and q_name not in seen_queries:
                    seen_queries.add(q_name)
                    dns_queries.append({'query': q_name, 'is_demo': bool(r['is_demo'])})

        # TCP vs UDP vs Others
        tcp_cnt = sum(cnt for p, cnt in protocols.items() if 'TCP' in p or p in ('TLS', 'HTTP', 'HTTPS', 'SSH', 'SMB', 'SMB2'))
        udp_cnt = sum(cnt for p, cnt in protocols.items() if 'UDP' in p or p in ('DNS', 'DHCP', 'NTP'))
        other_cnt = max(0, total_packets - (tcp_cnt + udp_cnt))

        # TShark availability
        tshark_status = get_tshark_info()

        # Demo vs Real imported counts
        demo_row = query_db("SELECT COUNT(*) as cnt FROM events WHERE (category = 'Network' OR source = 'Wireshark') AND is_demo = 1", one=True)
        demo_cnt = demo_row['cnt'] if demo_row else 0

        return jsonify({
            'total_packets': total_packets,
            'protocols': protocols,
            'top_sources': top_sources,
            'top_destinations': top_destinations,
            'dns_queries': dns_queries[:15],
            'traffic_split': {
                'tcp': tcp_cnt,
                'udp': udp_cnt,
                'other': other_cnt
            },
            'tshark': tshark_status,
            'demo_records': demo_cnt,
            'imported_records': total_packets - demo_cnt
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/import/autopsy', methods=['POST'])
def import_autopsy():
    """Imports Autopsy findings (CSV, TSV, JSON, Bodyfile) into SQLite."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file_obj = request.files['file']
    try:
        target_path, original_fn, stored_fn, sha256, content_bytes = save_and_log_upload(file_obj, 'autopsy')
        text_content = content_bytes.decode('utf-8', errors='replace')

        import_id = f"imp-aut-{uuid.uuid4().hex[:10]}"
        records, parsed_count, failed = parse_autopsy_content(text_content, filename=original_fn, import_ref_prefix="AUTOPSY")

        inserted = 0
        duplicates = 0
        if parsed_count > 0:
            inserted, duplicates = insert_events_batch(records, track_duplicates=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        modify_db("""
            INSERT INTO imports (
                id, original_filename, stored_filename, source_type,
                sha256_hash, total_records, successful_records, failed_records, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (import_id, original_fn, stored_fn, 'Autopsy', sha256, parsed_count + failed, inserted, failed, now_iso))

        msg = f'Successfully imported {inserted} Autopsy findings'
        if duplicates > 0:
            msg += f' ({duplicates} duplicate findings skipped)'
        if failed > 0:
            msg += f' ({failed} invalid records skipped)'
        msg += '.'

        return jsonify({
            'status': 'ok',
            'message': msg,
            'import_id': import_id,
            'sha256_hash': sha256,
            'total_records': parsed_count + failed,
            'successful_records': inserted,
            'duplicate_records': duplicates,
            'failed_records': failed
        }), 201

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to process Autopsy findings: {str(e)}'}), 500

@app.route('/api/import/windows-audit', methods=['POST'])
def import_windows_audit():
    """Imports Windows Event Logs and Sysmon exports (JSON or CSV) into SQLite."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file_obj = request.files['file']
    try:
        target_path, original_fn, stored_fn, sha256, content_bytes = save_and_log_upload(file_obj, 'windows_audit')
        text_content = content_bytes.decode('utf-8', errors='replace')

        import_id = f"imp-win-{uuid.uuid4().hex[:10]}"
        records, parsed_count, failed = parse_windows_audit_content(text_content)

        inserted = 0
        duplicates = 0
        if parsed_count > 0:
            inserted, duplicates = insert_events_batch(records, track_duplicates=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        modify_db("""
            INSERT INTO imports (
                id, original_filename, stored_filename, source_type,
                sha256_hash, total_records, successful_records, failed_records, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (import_id, original_fn, stored_fn, 'Windows audit', sha256, parsed_count + failed, inserted, failed, now_iso))

        dup_msg = f" ({duplicates} duplicate records skipped)" if duplicates else ""
        return jsonify({
            'status': 'ok',
            'message': f'Successfully imported {inserted} Windows/Sysmon records{dup_msg}.',
            'import_id': import_id,
            'sha256_hash': sha256,
            'total_records': parsed_count + failed,
            'successful_records': inserted,
            'duplicates_skipped': duplicates,
            'failed_records': failed
        }), 201

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to process Windows audit file: {str(e)}'}), 500

@app.route('/api/import/sysmon', methods=['POST'])
def import_sysmon():
    """Imports Microsoft Sysmon event JSON exports into SQLite."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file_obj = request.files['file']
    try:
        target_path, original_fn, stored_fn, sha256, content_bytes = save_and_log_upload(file_obj, 'sysmon')
        text_content = content_bytes.decode('utf-8', errors='replace')

        import_id = f"imp-sysmon-{uuid.uuid4().hex[:10]}"
        records, parsed_count, failed = parse_sysmon_json(text_content)

        inserted = 0
        duplicates = 0
        if parsed_count > 0:
            inserted, duplicates = insert_events_batch(records, track_duplicates=True)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        modify_db("""
            INSERT INTO imports (
                id, original_filename, stored_filename, source_type,
                sha256_hash, total_records, successful_records, failed_records, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (import_id, original_fn, stored_fn, 'Sysmon', sha256, parsed_count + failed, inserted, failed, now_iso))

        dup_msg = f" ({duplicates} duplicate records skipped)" if duplicates else ""
        return jsonify({
            'status': 'ok',
            'message': f'Successfully imported {inserted} Sysmon records{dup_msg}.',
            'import_id': import_id,
            'sha256_hash': sha256,
            'total_records': parsed_count + failed,
            'successful_records': inserted,
            'duplicates_skipped': duplicates,
            'failed_records': failed
        }), 201

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to process Sysmon file: {str(e)}'}), 500

@app.route('/api/imports')
def get_imports():
    """Returns the evidence import audit trail."""
    try:
        rows = query_db("SELECT * FROM imports ORDER BY imported_at DESC")
        return jsonify([dict(r) for r in rows]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =====================================================================
# API: REPORTS & INVESTIGATION SUMMARY
# =====================================================================

@app.route('/api/reports/summary')
def reports_summary():
    """Returns investigation statistics and key findings for forensic reporting."""
    try:
        total_row = query_db("SELECT COUNT(*) AS total FROM events", one=True)
        total = total_row['total'] if total_row else 0

        demo_row = query_db("SELECT COUNT(*) AS cnt FROM events WHERE is_demo = 1", one=True)
        demo_cnt = demo_row['cnt'] if demo_row else 0
        imported_cnt = total - demo_cnt

        # Severity breakdown
        sev_rows = query_db("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity")
        sev_map = {r['severity']: r['cnt'] for r in sev_rows}

        # Source breakdown
        src_rows = query_db("SELECT source, COUNT(*) as cnt FROM events GROUP BY source")
        src_map = {r['source']: r['cnt'] for r in src_rows}

        # Top critical and high findings
        priority_rows = query_db("""
            SELECT id, event_time, source, category, severity, title, details, evidence_reference, is_demo
            FROM events
            WHERE severity IN ('Critical', 'High')
            ORDER BY event_time DESC
            LIMIT 15
        """)
        priority_events = [dict(r) for r in priority_rows]
        for e in priority_events:
            e['is_demo'] = bool(e['is_demo'])

        det = run_detections(_load_events_for_detection())

        return jsonify({
            'detections': det['detections'][:20],
            'risk_score': det['risk_score'],
            'risk_level': det['risk_level'],
            'kill_chain': det['kill_chain'],
            'report_title': 'SecureScan Investigation Summary Report',
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'total_events': total,
            'imported_records': imported_cnt,
            'demo_records': demo_cnt,
            'severity_summary': {
                'Critical': sev_map.get('Critical', 0),
                'High': sev_map.get('High', 0),
                'Medium': sev_map.get('Medium', 0),
                'Low': sev_map.get('Low', 0),
                'Informational': sev_map.get('Informational', 0)
            },
            'sources_summary': {
                'Windows audit': src_map.get('Windows audit', 0),
                'Sysmon': src_map.get('Sysmon', 0),
                'Linux audit': src_map.get('Linux audit', 0),
                'Wireshark': src_map.get('Wireshark', 0),
                'Autopsy': src_map.get('Autopsy', 0),
                'System audit': src_map.get('System audit', 0)
            },
            'priority_findings': priority_events,
            'investigation_notes': [
                "1. Prioritise high and critical observations; cross-reference timestamps across system, network, and disk records.",
                "2. Rule alerts represent investigative leads requiring validation; they do not automatically establish malicious intent.",
                "3. Preserve chain of custody and original evidence hashes before drawing formal forensic conclusions.",
                "4. Autopsy disk images and Wireshark pcap streams must remain in write-blocked, pristine states."
            ],
            'recommendations': [
                "Review repeated failed authentications for brute-force or credential stuffing patterns.",
                "Verify whether newly created local user accounts follow authorized change management.",
                "Correlate outbound network sessions with observed executable staging paths."
            ]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/export.csv')
def export_csv():
    """Generates and streams a full CSV export of all database events."""
    try:
        rows = query_db("SELECT * FROM events ORDER BY event_time DESC")
        cols = ['event_time', 'source', 'category', 'severity', 'title', 'username',
                'source_ip', 'destination_ip', 'protocol', 'command', 'details',
                'evidence_reference', 'is_demo', 'imported_at']

        def generate():
            yield ",".join(cols) + "\r\n"
            for r in rows:
                line = []
                for c in cols:
                    val = str(r[c] if r[c] is not None else '')
                    # Escape quotes
                    escaped = '"' + val.replace('"', '""') + '"'
                    line.append(escaped)
                yield ",".join(line) + "\r\n"

        return Response(
            generate(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=securescan-evidence-export.csv'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error Handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Uploaded file exceeds the maximum 10 MB limit.'}), 413

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print(f"[*] Starting SecureScan backend on http://{Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
