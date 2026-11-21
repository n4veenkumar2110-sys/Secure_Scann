import json
import csv
import io
import datetime
import hashlib
import re

def parse_iso_time(time_str):
    """Normalises time string to ISO 8601 UTC."""
    if not time_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    clean_str = str(time_str).strip()

    # Try standard formats
    for fmt in (
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%m/%d/%Y %I:%M:%S %p',
        '%m/%d/%Y %H:%M:%S'
    ):
        try:
            dt = datetime.datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except Exception:
            continue

    try:
        return datetime.datetime.fromisoformat(clean_str.replace('Z', '+00:00')).isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

def generate_event_id(source, event_id, event_time, user, process, cmd, src_ip, rec_id):
    """Generates a deterministic hash-based ID to prevent duplicate record insertion."""
    unique_key = f"{source}|{event_id}|{event_time}|{user}|{process}|{cmd}|{src_ip}|{rec_id}"
    digest = hashlib.sha256(unique_key.encode('utf-8', errors='replace')).hexdigest()[:16]
    prefix = 'sysmon' if 'sysmon' in str(source).lower() else 'win'
    return f"{prefix}-{digest}"

def normalize_windows_event(item, index=0):
    """
    Normalises a single Windows Event or Sysmon event dictionary into SecureScan's schema.
    Applies transparent security rules and explains why events are flagged.
    """
    raw_eid = str(item.get('event_id') or item.get('Id') or item.get('EventID') or item.get('id') or '')
    # Extract numerical event id if mixed with string
    eid_match = re.search(r'\b(4624|4625|4688|4720|4726|4672|1|3|11)\b', raw_eid)
    event_id = int(eid_match.group(1)) if eid_match else None

    # Handle Sysmon vs Windows Security source
    src_input = str(item.get('source') or item.get('LogName') or item.get('log_name') or '')
    if 'sysmon' in src_input.lower() or event_id in (1, 3, 11):
        source = 'Sysmon'
    else:
        source = 'Windows audit'

    raw_time = item.get('event_time') or item.get('TimeCreated') or item.get('timestamp') or item.get('Time')
    event_time = parse_iso_time(raw_time)

    user = str(item.get('username') or item.get('User') or item.get('TargetUserName') or item.get('SubjectUserName') or '').strip()
    if user in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE') and item.get('SubjectUserName'):
        user = str(item.get('SubjectUserName')).strip()

    computer = str(item.get('computer_name') or item.get('MachineName') or '').strip()
    source_ip = str(item.get('source_ip') or item.get('IpAddress') or item.get('SourceIp') or '').strip()
    if source_ip in ('-', '127.0.0.1', '::1', 'unknown'):
        source_ip = ''

    destination_ip = str(item.get('destination_ip') or item.get('DestinationIp') or '').strip()
    dst_port = str(item.get('destination_port') or item.get('DestinationPort') or '').strip()
    protocol = str(item.get('protocol') or item.get('Protocol') or '').strip().upper()

    process_name = str(item.get('process_name') or item.get('NewProcessName') or item.get('Image') or item.get('ProcessName') or '').strip()
    cmd_line = str(item.get('command_line') or item.get('CommandLine') or '').strip()
    command = cmd_line or process_name

    target_file = str(item.get('target_filename') or item.get('TargetFilename') or '').strip()
    privileges = str(item.get('privileges') or item.get('PrivilegeList') or '').strip()
    rec_id = str(item.get('record_id') or item.get('RecordId') or index)

    # -----------------------------------------------------------------
    # Transparent Detection Rules & Classification
    # -----------------------------------------------------------------
    category = 'System'
    severity = 'Informational'
    title = f"{source} Event {event_id or 'Observed'}"
    rule_reason = ""
    evidence_ref = f"WIN-{event_id or 'EVT'}-{rec_id}"

    # RECON / PRIVILEGED PROCESS LIST
    suspicious_procs = ['powershell', 'cmd.exe', 'whoami', 'net.exe', 'vssadmin', 'certutil', 'mimikatz', 'reg.exe', 'nltest', 'rundll32', 'mshta', 'schtasks']

    if event_id == 4624:
        category = 'Authentication'
        severity = 'Informational'
        title = f"Event 4624: Successful login for '{user or 'User'}'"
        logon_type = item.get('logon_type') or item.get('LogonType') or ''
        rule_reason = f"Observation: Standard Windows logon event. LogonType: {logon_type or 'Interactive/Network'}."

    elif event_id == 4625:
        category = 'Authentication'
        severity = 'High'
        title = f"Event 4625: Failed login attempt for '{user or 'unknown'}'"
        rule_reason = "Observation: Authentication failure recorded in Windows Security Log. Repeated occurrences indicate potential brute-force or unauthorized logon attempts."

    elif event_id == 4720:
        category = 'Account'
        severity = 'Medium'
        title = f"Event 4720: User account created: '{user}'"
        rule_reason = "Observation: Local user account provisioning event observed in Windows Security Log."

    elif event_id == 4726:
        category = 'Account'
        severity = 'High'
        title = f"Event 4726: User account deleted: '{user}'"
        rule_reason = "Observation: Local user account removal observed in Windows Security Log. High-impact administrative change requiring validation."

    elif event_id == 4672:
        category = 'Authentication'
        severity = 'Medium'
        title = f"Event 4672: Special privileges assigned to '{user}'"
        rule_reason = f"Observation: Account logged on with administrative rights (e.g. SeDebugPrivilege). {('Privileges: ' + privileges) if privileges else ''}"

    elif event_id == 4688:
        category = 'Process'
        lower_cmd = command.lower()
        if any(sp in lower_cmd for sp in suspicious_procs):
            severity = 'Medium'
            title = f"Event 4688: Administrative / Recon process: '{process_name.split(chr(92))[-1]}'"
            rule_reason = f"Observation: Execution of administrative or reconnaissance binary commonly leveraged during post-exploitation activity: {command}."
        else:
            severity = 'Low'
            title = f"Event 4688: Process created: '{process_name.split(chr(92))[-1]}'"
            rule_reason = "Observation: Windows process creation event recorded."

    elif event_id == 1 and source == 'Sysmon':
        category = 'Process'
        lower_cmd = command.lower()
        if any(sp in lower_cmd for sp in suspicious_procs):
            severity = 'High' if 'mimikatz' in lower_cmd or 'vssadmin' in lower_cmd else 'Medium'
            title = f"Sysmon 1: Elevated / Recon process execution: '{process_name.split(chr(92))[-1]}'"
            rule_reason = f"Observation: Sysmon process creation rule matched suspicious command line: {command}."
        else:
            severity = 'Low'
            title = f"Sysmon 1: Process created: '{process_name.split(chr(92))[-1]}'"
            rule_reason = "Observation: Process creation monitored by Microsoft Sysmon."

    elif event_id == 3 and source == 'Sysmon':
        category = 'Network'
        lower_proc = process_name.lower()
        if any(sp in lower_proc for sp in ['powershell', 'cmd.exe', 'rundll32', 'mshta', 'certutil']):
            severity = 'Medium'
            title = f"Sysmon 3: Outbound network connection from script interpreter: '{process_name.split(chr(92))[-1]}'"
            rule_reason = f"Observation: Command interpreter initiated a network socket to {destination_ip}:{dst_port}."
        else:
            severity = 'Low'
            title = f"Sysmon 3: Network connection: {source_ip or 'Local'} → {destination_ip}:{dst_port}"
            rule_reason = f"Observation: Monitored network connection via protocol {protocol}."

    elif event_id == 11 and source == 'Sysmon':
        category = 'Forensic'
        lower_file = (target_file or command).lower()
        if any(st in lower_file for st in ['\\temp\\', '\\tmp\\', 'appdata\\local\\temp', '\\startup\\']):
            severity = 'Medium'
            title = f"Sysmon 11: File created in staging path: '{target_file.split(chr(92))[-1]}'"
            rule_reason = f"Observation: File creation in temporary or startup directory: {target_file}."
        else:
            severity = 'Informational'
            title = f"Sysmon 11: File created: '{target_file.split(chr(92))[-1]}'"
            rule_reason = "Observation: File system creation event recorded by Sysmon."

    else:
        # Fallback for generic Windows events
        rule_reason = item.get('description') or item.get('Message') or 'Windows event record observed.'

    # Structured details field
    details_parts = []
    if rule_reason:
        details_parts.append(rule_reason)
    if computer:
        details_parts.append(f"Computer: {computer}")
    if event_id:
        details_parts.append(f"EventID: {event_id}")
    if process_name:
        details_parts.append(f"Process: {process_name}")
    if target_file:
        details_parts.append(f"TargetFile: {target_file}")
    if source_ip:
        details_parts.append(f"Source IP: {source_ip}")
    if destination_ip:
        details_parts.append(f"Destination: {destination_ip}:{dst_port}" if dst_port else f"Destination: {destination_ip}")
    if item.get('hashes'):
        details_parts.append(f"Hashes: {item.get('hashes')}")

    details_text = " | ".join(details_parts) if details_parts else "Windows event details."
    deterministic_id = generate_event_id(source, event_id, event_time, user, process_name, command, source_ip, rec_id)

    return {
        'id': deterministic_id,
        'event_time': event_time,
        'source': source,
        'category': category,
        'severity': severity,
        'title': title,
        'username': user,
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'protocol': protocol,
        'command': command,
        'details': details_text[:1400],
        'evidence_reference': evidence_ref,
        'is_demo': 0,
        'imported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'raw_payload': json.dumps(item)[:1000]
    }

def parse_windows_audit_content(content_text):
    """
    Parses Windows audit content from JSON or CSV text and returns:
    (records, successful_count, failed_count)
    """
    clean_text = content_text.lstrip('\ufeff').strip()
    records = []
    successful = 0
    failed = 0

    if not clean_text:
        return [], 0, 0

    # 1. Try parsing as JSON
    if clean_text.startswith('[') or clean_text.startswith('{'):
        try:
            parsed = json.loads(clean_text)
            items = parsed if isinstance(parsed, list) else [parsed]
            for i, item in enumerate(items):
                if isinstance(item, dict):
                    rec = normalize_windows_event(item, i)
                    records.append(rec)
                    successful += 1
                else:
                    failed += 1
            return records, successful, failed
        except json.JSONDecodeError:
            pass

    # 2. Try parsing as CSV
    try:
        reader = csv.DictReader(io.StringIO(clean_text))
        if reader.fieldnames:
            for i, row in enumerate(reader):
                if any(row.values()):
                    rec = normalize_windows_event(dict(row), i)
                    records.append(rec)
                    successful += 1
                else:
                    failed += 1
            return records, successful, failed
    except Exception:
        pass

    return [], 0, 1
