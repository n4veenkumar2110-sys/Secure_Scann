"""
SecureScan Autopsy Digital Forensics Ingest Parser
=================================================
Parses digital forensic findings exported from Autopsy (on CAINE Linux / Windows)
into the SecureScan SQLite events and evidence framework.

Supported Formats:
  1. Autopsy CSV Report exports (File listings, Artifacts, Web history, Deleted files)
  2. Autopsy TSV Report exports (Tab-delimited table exports)
  3. Autopsy JSON Reports (Structured JSON case & artifact exports)
  4. The Sleuth Kit (TSK) / Autopsy Bodyfile exports (11-field pipe-separated timeline format)

Features:
  - Robust format detection (CSV, TSV, JSON, Bodyfile)
  - Deterministic duplicate prevention via SHA-256 fingerprinting
  - Metadata preservation: MD5, SHA-256, path, size, timestamps, case ID, examiner notes
  - Zero speculative accusations: classifies findings as objective forensic observations
  - Safe handling of malformed records, missing columns, and empty files
"""

import csv
import io
import json
import datetime
import hashlib
import re
from pathlib import Path


def normalize_col(name):
    """Normalises column headers by lowercasing and stripping non-alphanumeric characters."""
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


def pick_value(row_dict, candidate_names):
    """Picks the first non-empty value matching any normalized candidate name."""
    norm_map = {normalize_col(k): v for k, v in row_dict.items()}
    for candidate in candidate_names:
        val = norm_map.get(normalize_col(candidate))
        if val is not None and str(val).strip() != '':
            return str(val).strip()
    return ''


def parse_autopsy_time(time_str):
    """Parses Autopsy date/time strings or epoch timestamps into ISO 8601 UTC."""
    if not time_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    clean_str = str(time_str).strip()

    # Numeric UNIX epoch timestamp check
    if re.match(r'^\d{9,12}(?:\.\d+)?$', clean_str):
        try:
            ts = float(clean_str)
            if ts > 0:
                return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
        except Exception:
            pass

    for fmt in (
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S %Z',
        '%m/%d/%Y %I:%M:%S %p',
        '%m/%d/%Y %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ'
    ):
        try:
            dt = datetime.datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except Exception:
            continue
    try:
        return datetime.datetime.fromisoformat(clean_str).isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


def generate_autopsy_record_id(source, filepath, filename, event_time, file_hash, size, ref_id):
    """Generates a deterministic SHA-256 based ID to prevent duplicate evidence ingestion."""
    key = f"{source}|{filepath}|{filename}|{event_time}|{file_hash}|{size}|{ref_id}"
    digest = hashlib.sha256(key.encode('utf-8', errors='replace')).hexdigest()[:16]
    return f"autopsy-{digest}"


def classify_autopsy_artifact(filename, filepath, comment, file_type):
    """
    Classifies an Autopsy finding into an objective forensic category and severity level
    without making speculative accusations.
    """
    category = 'Forensic'
    severity = 'Informational'
    title = filename or filepath or 'Autopsy forensic artefact'
    rule_reason = ""

    combined = f"{filepath} {filename} {comment} {file_type}".lower()

    if any(del_kw in combined for del_kw in ['deleted', '$recycle.bin', 'unallocated', 'trash', '(deleted)']):
        severity = 'Medium'
        title = f"Deleted file entry: '{filename or filepath}'"
        rule_reason = "Observation: File marked as deleted or located in deleted/unallocated storage in forensic image."

    elif any(cred_kw in combined for cred_kw in [
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'etc/shadow', 'password',
        'kdbx', 'credentials', 'ntds.dit', 'security.dat', 'wallet.dat'
    ]) or re.search(r'(^|[\\/\s])(sam|system|security)(\.hiv|\.save)?(\s|$)', combined) and 'config' in combined:
        # NOTE: the Windows SAM hive is matched as a whole path component under ...\config\
        # (a bare substring 'sam' wrongly flagged files such as 'sample.txt' or 'Samsung').
        severity = 'High'
        title = f"Sensitive credential file observed: '{filename}'"
        rule_reason = "Observation: File name or path matches sensitive credential storage artefact."

    elif any(stage_kw in combined for stage_kw in ['/tmp/', '\\temp\\', 'appdata\\local\\temp', '/dev/shm']):
        severity = 'Medium'
        title = f"Executable or artefact in temporary staging path: '{filename}'"
        rule_reason = "Observation: Artefact located in temporary directory commonly used for file staging."

    elif any(browser_kw in combined for browser_kw in ['history', 'cookies', 'places.sqlite', 'web data', 'download', 'tsk_web_history']):
        severity = 'Informational'
        title = f"Browser artefact found: '{filename or 'web history'}'"
        rule_reason = "Observation: Web browsing or download history artefact extracted from disk image."

    elif any(usb_kw in combined for usb_kw in ['tsk_device_attached', 'usb', 'device attached', 'cruzer', 'datatraveler']):
        severity = 'Low'
        title = f"External device observation: '{filename}'"
        rule_reason = "Observation: USB mass storage or peripheral device connection record identified."

    return category, severity, title, rule_reason


def parse_autopsy_content(content_text, filename="autopsy_report.csv", import_ref_prefix="AUT"):
    """
    Comprehensive parser for digital forensic findings exported from Autopsy.
    Detects JSON, SleuthKit Bodyfile, and Delimited CSV/TSV formats.
    Returns (records, successful_count, failed_count).
    """
    if not content_text or not content_text.strip():
        return [], 0, 0

    clean_text = content_text.lstrip('\ufeff').strip()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Check for JSON format
    if clean_text.startswith('{') or clean_text.startswith('['):
        try:
            return parse_autopsy_json_text(clean_text, import_ref_prefix, now_iso)
        except Exception:
            pass  # Fall through to tabular parser if JSON fails

    # 2. Check for SleuthKit / Autopsy Bodyfile format (pipe-delimited 11 columns)
    lines = clean_text.splitlines()
    if lines and len(lines[0].split('|')) == 11 and not lines[0].lower().startswith('file name'):
        return parse_autopsy_bodyfile_text(clean_text, import_ref_prefix, now_iso)

    # 3. Delimited Text Parser (CSV / TSV)
    return parse_autopsy_delimited_text(clean_text, import_ref_prefix, now_iso)


def parse_autopsy_json_text(json_text, import_ref_prefix="AUT", now_iso=None):
    """Parses Autopsy JSON report export."""
    now_iso = now_iso or datetime.datetime.now(datetime.timezone.utc).isoformat()
    data = json.loads(json_text)
    
    case_name = ""
    artifacts = []
    
    if isinstance(data, dict):
        case_name = data.get('case_name') or data.get('case') or data.get('case_number') or ""
        artifacts = data.get('artifacts') or data.get('findings') or data.get('results') or []
        if not artifacts and 'files' in data:
            artifacts = data['files']
    elif isinstance(data, list):
        artifacts = data

    records = []
    successful = 0
    failed = 0

    for idx, item in enumerate(artifacts):
        if not isinstance(item, dict):
            failed += 1
            continue

        fname = item.get('name') or item.get('filename') or item.get('title') or item.get('artifact_name') or ''
        fpath = item.get('path') or item.get('source_path') or item.get('filepath') or ''
        ftype = item.get('type') or item.get('artifact_type') or item.get('mime_type') or ''
        fsize = str(item.get('size') or item.get('bytes') or '')
        fhash = item.get('md5') or item.get('sha256') or item.get('hash') or ''
        comment = item.get('comment') or item.get('details') or item.get('description') or ''
        user = item.get('user') or item.get('username') or item.get('owner') or ''
        ref = item.get('ref') or item.get('id') or item.get('evidence_reference') or f"{import_ref_prefix}-{idx+1:04d}"
        time_raw = item.get('date_time') or item.get('time') or item.get('timestamp') or item.get('modified')

        if not fname and not fpath and not comment:
            failed += 1
            continue

        event_time = parse_autopsy_time(time_raw)
        category, severity, title, rule_reason = classify_autopsy_artifact(fname, fpath, comment, ftype)

        details_parts = []
        if case_name:
            details_parts.append(f"Case: {case_name}")
        if rule_reason:
            details_parts.append(rule_reason)
        if fpath:
            details_parts.append(f"Path: {fpath}")
        if ftype:
            details_parts.append(f"Type: {ftype}")
        if fsize:
            details_parts.append(f"Size: {fsize} bytes")
        if fhash:
            details_parts.append(f"Hash: {fhash}")
        if comment:
            details_parts.append(f"Notes: {comment}")
        details_parts.append("Forensic finding organized from Autopsy examination.")
        details_text = " | ".join(details_parts)

        rec_id = generate_autopsy_record_id('Autopsy', fpath, fname, event_time, fhash, fsize, ref)

        records.append({
            'id': rec_id,
            'event_time': event_time,
            'source': 'Autopsy',
            'category': category,
            'severity': severity,
            'title': title,
            'username': user,
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': details_text[:1400],
            'evidence_reference': ref,
            'is_demo': 0,
            'imported_at': now_iso,
            'raw_payload': json.dumps(item)[:1000]
        })
        successful += 1

    return records, successful, failed


def parse_autopsy_bodyfile_text(bodyfile_text, import_ref_prefix="AUT", now_iso=None):
    """
    Parses The Sleuth Kit (TSK) / Autopsy 11-field pipe-separated Bodyfile format:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    """
    now_iso = now_iso or datetime.datetime.now(datetime.timezone.utc).isoformat()
    records = []
    successful = 0
    failed = 0

    for idx, line in enumerate(bodyfile_text.splitlines()):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) != 11:
            failed += 1
            continue

        md5, path_str, inode, mode, uid, gid, size_str, atime_s, mtime_s, ctime_s, crtime_s = parts

        fname = path_str.split('/')[-1].split('\\')[-1]
        time_to_use = mtime_s if mtime_s and mtime_s != '0' else (crtime_s if crtime_s and crtime_s != '0' else atime_s)
        event_time = parse_autopsy_time(time_to_use)

        category, severity, title, rule_reason = classify_autopsy_artifact(fname, path_str, "", "")

        details_parts = [
            rule_reason or "Observation: Forensic filesystem metadata entry from SleuthKit/Autopsy bodyfile.",
            f"Path: {path_str}",
            f"Inode: {inode}",
            f"Mode: {mode}",
            f"UID/GID: {uid}/{gid}",
            f"Size: {size_str} bytes"
        ]
        if md5 and md5 != '0':
            details_parts.append(f"MD5: {md5}")
        details_text = " | ".join(details_parts)

        ref = f"{import_ref_prefix}-BODY-{idx+1:04d}"
        rec_id = generate_autopsy_record_id('Autopsy', path_str, fname, event_time, md5, size_str, ref)

        records.append({
            'id': rec_id,
            'event_time': event_time,
            'source': 'Autopsy',
            'category': category,
            'severity': severity,
            'title': title,
            'username': str(uid) if uid not in ('0', '') else 'root/system',
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': details_text[:1400],
            'evidence_reference': ref,
            'is_demo': 0,
            'imported_at': now_iso,
            'raw_payload': json.dumps({'bodyfile_line': line})
        })
        successful += 1

    return records, successful, failed


def parse_autopsy_delimited_text(delimited_text, import_ref_prefix="AUT", now_iso=None):
    """
    Parses Autopsy CSV or TSV table reports with flexible delimiter detection.
    """
    now_iso = now_iso or datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Detect delimiter: check tabs, commas, semicolons
    first_line = delimited_text.splitlines()[0] if delimited_text.splitlines() else ''
    delimiter = '\t' if '\t' in first_line and first_line.count('\t') > first_line.count(',') else ','
    if delimiter == ',' and ';' in first_line and first_line.count(';') > first_line.count(','):
        delimiter = ';'

    reader = csv.DictReader(io.StringIO(delimited_text), delimiter=delimiter)
    if not reader.fieldnames:
        return [], 0, 0

    records = []
    successful = 0
    failed = 0

    for idx, row in enumerate(reader):
        filename = pick_value(row, ['File Name', 'Name', 'Filename', 'title', 'Artifact', 'Document Name', 'Program Name'])
        filepath = pick_value(row, ['File Path', 'Path', 'Full Path', 'Source File', 'Directory', 'Location', 'URL'])
        file_type = pick_value(row, ['File Type', 'MIME Type', 'Type', 'Extension', 'Artifact Type'])
        size = pick_value(row, ['Size', 'File Size', 'Bytes', 'Length'])
        mtime = pick_value(row, ['Modified Time', 'Modified', 'Date Modified', 'Timestamp', 'Date', 'Date/Time', 'Last Run Time'])
        ctime = pick_value(row, ['Created Time', 'Created', 'Date Created'])
        atime = pick_value(row, ['Accessed Time', 'Accessed', 'Date Accessed'])
        file_hash = pick_value(row, ['MD5 Hash', 'MD5', 'SHA-256 Hash', 'SHA256', 'Hash'])
        comment = pick_value(row, ['Comment', 'Description', 'Tag', 'Known', 'Notes', 'details', 'Snippet'])
        user = pick_value(row, ['User', 'Owner', 'Username', 'User Name', 'acct'])
        evidence_ref = pick_value(row, ['Evidence Reference', 'Reference', 'ID', 'Artifact ID', 'Device ID'])
        case_name = pick_value(row, ['Case Name', 'Case', 'Case Number'])

        if not filename and not filepath and not comment:
            failed += 1
            continue

        event_time = parse_autopsy_time(mtime or ctime or atime)
        category, severity, title, rule_reason = classify_autopsy_artifact(filename, filepath, comment, file_type)

        details_parts = []
        if case_name:
            details_parts.append(f"Case: {case_name}")
        if rule_reason:
            details_parts.append(rule_reason)
        if filepath:
            details_parts.append(f"Path: {filepath}")
        if file_type:
            details_parts.append(f"Type: {file_type}")
        if size:
            details_parts.append(f"Size: {size} bytes")
        if file_hash:
            details_parts.append(f"Hash: {file_hash}")
        if comment:
            details_parts.append(f"Notes: {comment}")
        details_parts.append("Forensic finding organized from Autopsy examination.")
        details_text = " | ".join(details_parts)

        ref_id = evidence_ref or f"{import_ref_prefix}-{idx+1:04d}"
        rec_id = generate_autopsy_record_id('Autopsy', filepath, filename, event_time, file_hash, size, ref_id)

        records.append({
            'id': rec_id,
            'event_time': event_time,
            'source': 'Autopsy',
            'category': category,
            'severity': severity,
            'title': title,
            'username': user,
            'source_ip': '',
            'destination_ip': '',
            'protocol': '',
            'command': '',
            'details': details_text[:1400],
            'evidence_reference': ref_id,
            'is_demo': 0,
            'imported_at': now_iso,
            'raw_payload': json.dumps(dict(row))[:1000]
        })
        successful += 1

    return records, successful, failed


def parse_autopsy_csv_text(csv_text, import_ref_prefix="AUT"):
    """
    Backward-compatible wrapper for legacy callers.
    Parses Autopsy CSV text and returns (records, successful_count, failed_count).
    """
    return parse_autopsy_content(csv_text, import_ref_prefix=import_ref_prefix)
