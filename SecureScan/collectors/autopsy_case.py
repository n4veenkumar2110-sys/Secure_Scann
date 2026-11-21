"""
SecureScan <-> Autopsy integration
==================================

Two ways SecureScan uses the real Autopsy forensic suite installed on the workstation:

1. run_autopsy_ingest()  - drives Autopsy's command-line ingest mode
       autopsy64.exe --createCase --addDataSource --runIngest --generateReports
   to create a case, add a folder / disk image as a data source and run Autopsy's
   ingest modules (hashing, file-type ID, extension-mismatch, encryption detection,
   interesting files, recent activity, EXIF, keyword search ...).

2. import_case_database() - reads the resulting Sleuth Kit case database
   (<case>/autopsy.db, SQLite) READ-ONLY and converts its files and "blackboard"
   artifacts into SecureScan events. This also works for any case an analyst built
   by hand in the Autopsy GUI - just point SecureScan at the case folder or .aut file.

The case database is opened with SQLite's `mode=ro&immutable=1` so the evidence
database is never modified (forensic soundness).
"""

import datetime
import glob
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from parser_autopsy import classify_autopsy_artifact

# Artifact types (TSK blackboard) -> (category, severity, label, explanation)
ARTIFACT_RULES = {
    'TSK_HASHSET_HIT': ('Forensic', 'Critical', 'Known-bad hash set hit',
                        'File hash matches a notable (known-bad) hash set.'),
    'TSK_INTERESTING_FILE_HIT': ('Forensic', 'Medium', 'Interesting file',
                                 'File matched an Autopsy "interesting files" rule.'),
    'TSK_INTERESTING_ITEM': ('Forensic', 'Medium', 'Interesting item',
                             'Item matched an Autopsy "interesting items" rule.'),
    'TSK_EXT_MISMATCH_DETECTED': ('Forensic', 'High', 'File extension mismatch',
                                  'File content does not match its extension (e.g. an executable renamed .jpg) - '
                                  'a common way to hide malware or exfiltrated data (MITRE T1036.008).'),
    'TSK_ENCRYPTION_SUSPECTED': ('Forensic', 'Medium', 'Encrypted / high-entropy file',
                                 'File has high entropy and may be encrypted (ransomware output or hidden container).'),
    'TSK_ENCRYPTION_DETECTED': ('Forensic', 'Medium', 'Encrypted file detected',
                                'Password-protected or encrypted file found.'),
    'TSK_USER_CONTENT_SUSPECTED': ('Forensic', 'Low', 'Suspected user content', 'Autopsy flagged user-created content.'),
    'TSK_KEYWORD_HIT': ('Forensic', 'Medium', 'Keyword search hit', 'File content matched a keyword list.'),
    'TSK_WEB_HISTORY': ('Forensic', 'Informational', 'Web history entry', 'Browser history record.'),
    'TSK_WEB_DOWNLOAD': ('Forensic', 'Low', 'Web download', 'File downloaded through a browser.'),
    'TSK_WEB_SEARCH_QUERY': ('Forensic', 'Informational', 'Web search query', 'Search term typed in a browser.'),
    'TSK_WEB_COOKIE': ('Forensic', 'Informational', 'Web cookie', 'Browser cookie.'),
    'TSK_DEVICE_ATTACHED': ('Forensic', 'Low', 'USB / external device attached',
                            'Removable device connection recorded - possible data-exfiltration path.'),
    'TSK_RECENT_OBJECT': ('Forensic', 'Informational', 'Recently opened item', 'Recent document / jump list entry.'),
    'TSK_PROG_RUN': ('Process', 'Low', 'Program execution record', 'Prefetch / execution artefact.'),
    'TSK_INSTALLED_PROG': ('System', 'Informational', 'Installed program', 'Installed software entry.'),
    'TSK_OS_ACCOUNT': ('Account', 'Informational', 'OS user account', 'Operating system account found on the image.'),
    'TSK_METADATA_EXIF': ('Forensic', 'Informational', 'EXIF metadata', 'Photo metadata (camera, GPS, time).'),
    'TSK_GPS_TRACKPOINT': ('Forensic', 'Informational', 'GPS location', 'Geolocation artefact.'),
    'TSK_DELETED_PROG': ('Forensic', 'Medium', 'Deleted program', 'Program that was uninstalled/deleted.'),
}
NOISY_INFO_TYPES = {'TSK_WEB_COOKIE', 'TSK_METADATA_EXIF', 'TSK_INSTALLED_PROG', 'TSK_GPS_TRACKPOINT'}

# Extension -> acceptable MIME prefixes. Used with Autopsy's File Type Identification
# result to catch disguised files even when the Extension Mismatch module was not run.
EXPECTED_MIME = {
    'jpg': ('image/',), 'jpeg': ('image/',), 'png': ('image/',), 'gif': ('image/',), 'bmp': ('image/',),
    'pdf': ('application/pdf',), 'txt': ('text/', 'application/octet-stream'), 'csv': ('text/',),
    'mp3': ('audio/',), 'mp4': ('video/',), 'docx': ('application/vnd.openxmlformats', 'application/zip', 'application/x-tika-ooxml'),
    'xlsx': ('application/vnd.openxmlformats', 'application/zip', 'application/x-tika-ooxml'),
    'doc': ('application/msword', 'application/x-tika-msoffice'), 'zip': ('application/zip',),
}
EXECUTABLE_MIME = ('application/x-dosexec', 'application/x-msdownload', 'application/x-executable',
                   'application/x-sharedlib', 'application/x-mach-binary', 'application/x-elf')
MAX_INVENTORY_FILES = 1500


# ---------------------------------------------------------------------------
# 1. Running Autopsy
# ---------------------------------------------------------------------------
def find_autopsy():
    """Returns the path of autopsy64.exe (newest installed version) or None."""
    roots = [os.environ.get('ProgramFiles', r'C:\Program Files'), os.environ.get('ProgramFiles(x86)', '')]
    hits = []
    for r in roots:
        if r:
            hits += glob.glob(os.path.join(r, 'Autopsy*', 'bin', 'autopsy64.exe'))
    return sorted(hits)[-1] if hits else None


def autopsy_info():
    path = find_autopsy()
    return {'available': bool(path), 'path': path,
            'version': Path(path).parent.parent.name.replace('Autopsy-', '') if path else None}


def _dismiss_startup_dialogs(pid):
    """Autopsy (Java/Swing) may open modal message boxes at start-up (first-run notice,
    optional Python module errors). They block command-line mode, so press their
    default button. Windows-only, best effort, touches only this Autopsy process."""
    ps = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    script = r'''
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type 'using System; using System.Runtime.InteropServices; public class W { [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h); }'
$root = [Windows.Automation.AutomationElement]::RootElement
$c = New-Object Windows.Automation.AndCondition((New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, __PID__)), (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Window)))
$n = 0
foreach ($i in 1..5) {
  $d = @($root.FindAll([Windows.Automation.TreeScope]::Descendants, $c) | Where-Object { $_.Current.Name -in 'Error','Information','Warning' })
  if (-not $d) { break }
  [W]::SetForegroundWindow([IntPtr]$d[0].Current.NativeWindowHandle) | Out-Null; Start-Sleep -Milliseconds 300
  [System.Windows.Forms.SendKeys]::SendWait('{ENTER}'); Start-Sleep -Milliseconds 800; $n++
}
$n'''
    try:
        out = subprocess.run([str(ps), '-NoProfile', '-NonInteractive', '-Command',
                              script.replace('__PID__', str(int(pid)))],
                             capture_output=True, text=True, timeout=60, check=False)
        return int((out.stdout or '0').strip().splitlines()[-1] or 0)
    except Exception:
        return 0


def run_autopsy_ingest(source_path, case_base_dir, case_name='SecureScanAudit', timeout=1800, progress=None):
    """Runs Autopsy command-line ingest on a folder or disk image. Returns the case folder."""
    exe = find_autopsy()
    if not exe:
        raise RuntimeError('Autopsy is not installed (autopsy64.exe not found under Program Files).')
    src = Path(source_path)
    if not src.exists():
        raise ValueError(f'Data source not found: {source_path}')
    base = Path(case_base_dir)
    base.mkdir(parents=True, exist_ok=True)
    before = set(base.glob(f'{case_name}_*'))

    args = [exe, '--nosplash', '--createCase', f'--caseName={case_name}', f'--caseBaseDir={base}',
            '--addDataSource', f'--dataSourcePath={src}', '--runIngest']
    # (--generateReports is omitted: it needs a report profile configured inside Autopsy;
    #  SecureScan produces its own report from the case database.)
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = time.time()
    next_dialog_check = started + 20
    while proc.poll() is None:
        if time.time() - started > timeout:
            proc.kill()
            raise TimeoutError(f'Autopsy ingest exceeded {timeout} s.')
        if os.name == 'nt' and time.time() >= next_dialog_check:
            _dismiss_startup_dialogs(proc.pid)
            next_dialog_check = time.time() + 20
        if progress:
            progress(f'Autopsy running ({int(time.time() - started)} s)...')
        time.sleep(3)

    created = sorted(set(base.glob(f'{case_name}_*')) - before, key=lambda p: p.stat().st_mtime)
    if not created or not (created[-1] / 'autopsy.db').is_file():
        raise RuntimeError('Autopsy finished but no case database was produced (see Autopsy logs).')
    return created[-1]


# ---------------------------------------------------------------------------
# 2. Reading an Autopsy case database
# ---------------------------------------------------------------------------
def locate_case_db(path):
    """Accepts a case folder, a .aut file or autopsy.db itself."""
    p = Path(path)
    if p.is_file() and p.name.lower() == 'autopsy.db':
        return p
    if p.is_file() and p.suffix.lower() == '.aut':
        p = p.parent
    if p.is_dir() and (p / 'autopsy.db').is_file():
        return p / 'autopsy.db'
    raise ValueError(f'No Autopsy case database (autopsy.db) found at: {path}')


def _ts(epoch):
    try:
        e = int(epoch or 0)
        return datetime.datetime.fromtimestamp(e, tz=datetime.timezone.utc).isoformat() if e > 0 else None
    except (TypeError, ValueError, OSError):
        return None


def _sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def import_case_database(path, demo=False):
    """
    Converts an Autopsy case into SecureScan events.
    Returns (records, summary_dict).
    """
    db_path = locate_case_db(path)
    db_hash = _sha256_file(db_path)
    uri = 'file:' + db_path.resolve().as_posix() + '?mode=ro&immutable=1'
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    case_dir = db_path.parent
    case_name = case_dir.name

    def cols(table):
        return {r[1] for r in con.execute(f'PRAGMA table_info({table})')}

    records, seen = [], set()

    def add(key, event_time, category, severity, title, details, username='', command='', ref=''):
        rid = 'autopsy-' + hashlib.sha256(f'{db_hash[:16]}|{key}'.encode('utf-8', 'replace')).hexdigest()[:16]
        if rid in seen:
            return
        seen.add(rid)
        records.append({
            'id': rid, 'event_time': event_time or now, 'source': 'Autopsy', 'category': category,
            'severity': severity, 'title': title[:300], 'username': username, 'source_ip': '', 'destination_ip': '',
            'protocol': '', 'command': command[:500],
            'details': (details + f' | Case: {case_name} | Autopsy case DB SHA-256: {db_hash[:16]}…')[:1400],
            'evidence_reference': ref or f'AUT-CASE-{len(records) + 1:05d}', 'is_demo': 1 if demo else 0,
            'imported_at': now, 'raw_payload': json.dumps({'case_db': str(db_path), 'key': key})[:1000],
        })

    # ---- Data sources ---------------------------------------------------
    sources = []
    try:
        for r in con.execute('SELECT o.obj_id, n.name FROM tsk_objects o LEFT JOIN tsk_image_names n ON n.obj_id = o.obj_id '
                             'WHERE o.par_obj_id IS NULL'):
            sources.append(r['name'] or f'object {r["obj_id"]}')
    except sqlite3.Error:
        pass
    try:
        for r in con.execute("SELECT name FROM tsk_files WHERE obj_id IN (SELECT obj_id FROM data_source_info)"):
            if r['name'] and r['name'] not in sources:
                sources.append(r['name'])
    except sqlite3.Error:
        pass

    # ---- Files ------------------------------------------------------------
    fcols = cols('tsk_files')
    sel = ['obj_id', 'name', 'parent_path', 'size', 'meta_type', 'dir_flags', 'meta_flags', 'crtime', 'mtime', 'atime']
    sel += [c for c in ('md5', 'sha256', 'mime_type', 'extension', 'known') if c in fcols]
    files_total = deleted = flagged_files = inventory = 0
    hash_names = {}
    for f in con.execute(f"SELECT {', '.join(sel)} FROM tsk_files WHERE meta_type = 1 AND name NOT IN ('.', '..') "
                         f"ORDER BY obj_id"):
        files_total += 1
        name, parent = f['name'] or '', f['parent_path'] or '/'
        full = parent + name
        is_deleted = (f['dir_flags'] == 2) or ((f['meta_flags'] or 0) & 2 == 2 and (f['meta_flags'] or 0) & 1 == 0)
        mime = f['mime_type'] if 'mime_type' in f.keys() else ''
        md5 = f['md5'] if 'md5' in f.keys() else ''
        known = f['known'] if 'known' in f.keys() else 0
        comment = '(deleted) unallocated' if is_deleted else ''
        # Case paths use '/', Windows-style rules use '\' - give the classifier both forms.
        category, severity, title, reason = classify_autopsy_artifact(
            name, f"{full} {full.replace('/', chr(92))}", comment, mime or '')
        ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
        if mime and ext in EXPECTED_MIME and not mime.startswith(EXPECTED_MIME[ext]):
            is_exe = mime.startswith(EXECUTABLE_MIME)
            severity = 'High' if is_exe else 'Medium'
            title = f"File extension mismatch: '{name}' is really {mime}"
            reason = ('Observation: Autopsy file-type identification shows the content does not match the .'
                      f'{ext} extension' + (' - an executable disguised as a harmless file, a common malware '
                      'delivery and hiding technique (MITRE T1036.008).' if is_exe else '.'))
        elif mime.startswith(EXECUTABLE_MIME) and any(m in full.lower() for m in ('/temp/', '/tmp/', '/downloads/')) \
                and severity == 'Informational':
            severity, title = 'Medium', f"Executable in Temp/Downloads: '{name}'"
            reason = 'Observation: Program file stored in a temporary or download folder (common malware staging location).'
        if known == 2:
            severity, title, reason = 'Critical', f"Known-bad file (notable hash): '{name}'", 'Observation: Hash is in a notable hash set.'
        if md5:
            hash_names.setdefault(md5, []).append((full, mime))
        deleted += is_deleted
        interesting = severity != 'Informational' or is_deleted
        flagged_files += interesting
        if not interesting:
            if inventory >= MAX_INVENTORY_FILES:
                continue
            inventory += 1
            title = f"File: '{name}'"
            reason = 'Observation: File inventoried by Autopsy (no rule matched).'
        when = _ts(f['mtime']) or _ts(f['crtime']) or _ts(f['atime'])
        details = ' | '.join(x for x in [
            reason, f'Path: {full}', f"Size: {f['size']} bytes", f'MIME: {mime}' if mime else '',
            f'MD5: {md5}' if md5 else '', f"Created: {_ts(f['crtime'])}" if f['crtime'] else '',
            f"Accessed: {_ts(f['atime'])}" if f['atime'] else '', 'Deleted: yes' if is_deleted else ''] if x)
        add(f"file|{f['obj_id']}", when, 'Forensic', severity, title, details, ref=f"AUT-OBJ-{f['obj_id']}")

    # ---- Same executable stored under different names (MD5 from Autopsy hash lookup) ----
    for md5, items in hash_names.items():
        names = {p.rsplit('/', 1)[-1].lower() for p, _ in items}
        if len(names) > 1 and any((m or '').startswith(EXECUTABLE_MIME) for _, m in items):
            add(f'dup|{md5}', None, 'Forensic', 'Medium',
                f"Same executable stored under {len(names)} different names",
                'Observation: Identical MD5 across differently named files - a dropped payload copied or renamed '
                f'to blend in. MD5: {md5} | Copies: ' + ', '.join(p for p, _ in items[:8]))

    # ---- Blackboard artifacts (results of Autopsy's ingest modules) ----------
    artifact_counts = {}
    try:
        rows = con.execute("""
            SELECT a.artifact_id, a.obj_id, t.type_name, t.display_name
            FROM blackboard_artifacts a JOIN blackboard_artifact_types t ON t.artifact_type_id = a.artifact_type_id
        """).fetchall()
    except sqlite3.Error:
        rows = []
    attr_sql = """
        SELECT t.type_name, t.display_name, b.value_text, b.value_int32, b.value_int64, b.value_double
        FROM blackboard_attributes b JOIN blackboard_attribute_types t ON t.attribute_type_id = b.attribute_type_id
        WHERE b.artifact_id = ?
    """
    for a in rows:
        tname = a['type_name']
        artifact_counts[a['display_name'] or tname] = artifact_counts.get(a['display_name'] or tname, 0) + 1
        if tname in NOISY_INFO_TYPES and artifact_counts[a['display_name'] or tname] > 200:
            continue
        attrs = {}
        for b in con.execute(attr_sql, (a['artifact_id'],)):
            v = b['value_text'] if b['value_text'] is not None else (
                b['value_int64'] if b['value_int64'] is not None else (b['value_int32'] if b['value_int32'] is not None else b['value_double']))
            attrs.setdefault(b['type_name'], v)
        src = con.execute('SELECT name, parent_path FROM tsk_files WHERE obj_id = ?', (a['obj_id'],)).fetchone()
        src_path = ((src['parent_path'] or '') + (src['name'] or '')) if src else ''
        category, severity, label, why = ARTIFACT_RULES.get(
            tname, ('Forensic', 'Low', a['display_name'] or tname, 'Autopsy ingest module result.'))
        subject = (attrs.get('TSK_URL') or attrs.get('TSK_PROG_NAME') or attrs.get('TSK_DEVICE_MODEL')
                   or attrs.get('TSK_SET_NAME') or attrs.get('TSK_NAME') or attrs.get('TSK_PATH')
                   or (src['name'] if src else '') or '')
        when = None
        for k in ('TSK_DATETIME_ACCESSED', 'TSK_DATETIME', 'TSK_DATETIME_CREATED', 'TSK_DATETIME_START'):
            if attrs.get(k):
                when = _ts(attrs[k])
                break
        if tname == 'TSK_EXT_MISMATCH_DETECTED' and src:
            mime_row = con.execute('SELECT mime_type FROM tsk_files WHERE obj_id = ?', (a['obj_id'],)).fetchone() \
                if 'mime_type' in fcols else None
            if mime_row and mime_row[0]:
                why += f' Real type: {mime_row[0]}.'
        attr_txt = ' | '.join(f'{k.replace("TSK_", "").title()}: {v}' for k, v in list(attrs.items())[:8]
                              if v not in (None, '') and not str(k).startswith('TSK_DATETIME'))
        add(f"art|{a['artifact_id']}", when, category, severity, f"{label}: '{str(subject)[:120]}'",
            f'Observation: {why} | Autopsy artifact: {a["display_name"]} | Source file: {src_path} | {attr_txt}',
            username=str(attrs.get('TSK_USER_NAME') or ''), ref=f"AUT-ART-{a['artifact_id']}")

    con.close()
    summary = {
        'case_name': case_name, 'case_dir': str(case_dir), 'case_db': str(db_path), 'case_db_sha256': db_hash,
        'data_sources': sources, 'files_total': files_total, 'files_deleted': deleted,
        'files_flagged': flagged_files, 'files_inventoried': inventory,
        'artifacts': artifact_counts, 'records': len(records),
        'reports': [str(p) for p in (case_dir / 'Reports').glob('**/*') if p.is_file()][:20],
    }
    return records, summary
