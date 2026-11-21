"""
SecureScan Sysmon Parser
========================
Parses Sysmon event JSON exported by collectors/sysmon_collector.ps1
and normalises records into the SecureScan events schema.

Supports:
  - Event ID 1:  Process Create
  - Event ID 3:  Network Connect
  - Event ID 11: File Create
  - Event ID 22: DNS Query

Duplicate prevention uses deterministic SHA-256 IDs derived from
(source, event_id, event_time, record_id, image, command_line).
"""

import json
import datetime
import hashlib
import re


def _parse_iso_time(time_str):
    """Normalises time string to ISO 8601 UTC."""
    if not time_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    clean = str(time_str).strip()
    for fmt in (
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
    ):
        try:
            dt = datetime.datetime.strptime(clean, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except Exception:
            continue
    try:
        return datetime.datetime.fromisoformat(
            clean.replace('Z', '+00:00')
        ).isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _generate_sysmon_id(event_id, event_time, record_id, image, cmd_line):
    """Deterministic ID to prevent duplicate Sysmon records."""
    key = f"Sysmon|{event_id}|{event_time}|{record_id}|{image}|{cmd_line}"
    digest = hashlib.sha256(key.encode('utf-8', errors='replace')).hexdigest()[:16]
    return f"sysmon-{digest}"


# Processes commonly used in post-exploitation / reconnaissance
_SUSPICIOUS_PROCS = [
    'powershell', 'cmd.exe', 'whoami', 'net.exe', 'net1.exe',
    'vssadmin', 'certutil', 'mimikatz', 'reg.exe', 'nltest',
    'rundll32', 'mshta', 'schtasks', 'wmic', 'bitsadmin',
    'cscript', 'wscript', 'psexec',
]

# Domains commonly associated with C2 / exfiltration tests
_SUSPICIOUS_DOMAINS = [
    'pastebin.com', 'ngrok.io', 'ngrok-free.app',
    'raw.githubusercontent.com', 'transfer.sh',
]


def normalize_sysmon_event(item, index=0):
    """
    Normalises a single Sysmon event dictionary into the SecureScan schema.
    Applies transparent detection rules with explanations.
    """
    raw_eid = item.get('event_id') or item.get('EventID') or item.get('Id') or ''
    eid_match = re.search(r'\b(1|3|11|22)\b', str(raw_eid))
    event_id = int(eid_match.group(1)) if eid_match else None

    raw_time = (
        item.get('event_time') or item.get('UtcTime') or
        item.get('TimeCreated') or item.get('timestamp')
    )
    event_time = _parse_iso_time(raw_time)

    rec_id = str(item.get('record_id') or item.get('RecordId') or index)
    computer = str(item.get('computer_name') or item.get('Computer') or '').strip()

    # Process fields
    image = str(
        item.get('image') or item.get('Image') or
        item.get('process_name') or ''
    ).strip()
    cmd_line = str(
        item.get('command_line') or item.get('CommandLine') or ''
    ).strip()
    command = cmd_line or image

    user = str(item.get('username') or item.get('User') or '').strip()
    process_guid = str(item.get('process_guid') or item.get('ProcessGuid') or '').strip()
    process_id = str(item.get('process_id') or item.get('ProcessId') or '').strip()
    hashes = str(item.get('hashes') or item.get('Hashes') or '').strip()
    rule_name = str(item.get('rule_name') or item.get('RuleName') or '').strip()

    # Network fields
    src_ip = str(item.get('source_ip') or item.get('SourceIp') or '').strip()
    dst_ip = str(item.get('destination_ip') or item.get('DestinationIp') or '').strip()
    dst_port = str(item.get('destination_port') or item.get('DestinationPort') or '').strip()
    src_port = str(item.get('source_port') or item.get('SourcePort') or '').strip()
    protocol = str(item.get('protocol') or item.get('Protocol') or '').strip().upper()

    # File fields
    target_file = str(
        item.get('target_filename') or item.get('TargetFilename') or ''
    ).strip()

    # DNS fields
    query_name = str(item.get('query_name') or item.get('QueryName') or '').strip()
    query_type = str(item.get('query_type') or item.get('QueryType') or '').strip()
    query_status = str(item.get('query_status') or item.get('QueryStatus') or '').strip()
    query_results = str(item.get('query_results') or item.get('QueryResults') or '').strip()

    # Parent process fields
    parent_image = str(
        item.get('parent_image') or item.get('ParentImage') or
        item.get('parent_process') or ''
    ).strip()
    parent_cmd = str(item.get('parent_cmd') or item.get('ParentCommandLine') or '').strip()

    # -----------------------------------------------------------------
    # Classification and Detection Rules
    # -----------------------------------------------------------------
    category = 'System'
    severity = 'Informational'
    title = f"Sysmon Event {event_id or 'Unknown'}"
    rule_reason = ""
    evidence_ref = f"SYSMON-{event_id or 'EVT'}-{rec_id}"

    image_basename = image.split('\\')[-1] if image else ''
    lower_cmd = command.lower()
    lower_image = image.lower()

    if event_id == 1:
        # Process Create
        category = 'Process'
        if any(sp in lower_cmd for sp in _SUSPICIOUS_PROCS):
            if 'mimikatz' in lower_cmd or 'vssadmin' in lower_cmd:
                severity = 'High'
                title = f"Sysmon 1: High-risk process execution: '{image_basename}'"
                rule_reason = (
                    f"Observation: Sysmon process creation matched a high-risk "
                    f"binary commonly used in credential theft or shadow copy "
                    f"manipulation: {command}."
                )
            else:
                severity = 'Medium'
                title = f"Sysmon 1: Recon / administrative process: '{image_basename}'"
                rule_reason = (
                    f"Observation: Sysmon process creation matched a reconnaissance "
                    f"or administrative binary: {command}."
                )
        else:
            severity = 'Low'
            title = f"Sysmon 1: Process created: '{image_basename}'"
            rule_reason = "Observation: Process creation monitored by Microsoft Sysmon."

    elif event_id == 3:
        # Network Connect
        category = 'Network'
        if any(sp in lower_image for sp in ['powershell', 'cmd.exe', 'rundll32', 'mshta', 'certutil', 'wscript', 'cscript']):
            severity = 'Medium'
            title = f"Sysmon 3: Script interpreter network connection: '{image_basename}'"
            rule_reason = (
                f"Observation: Command interpreter initiated a network socket "
                f"to {dst_ip}:{dst_port}. Investigate the process context."
            )
        else:
            severity = 'Low'
            title = f"Sysmon 3: Network connection: {src_ip or 'Local'} → {dst_ip}:{dst_port}"
            rule_reason = f"Observation: Monitored network connection via protocol {protocol}."

    elif event_id == 11:
        # File Create
        category = 'Forensic'
        lower_file = (target_file or command).lower()
        if any(st in lower_file for st in ['\\temp\\', '\\tmp\\', 'appdata\\local\\temp', '\\startup\\']):
            severity = 'Medium'
            target_basename = target_file.split('\\')[-1] if target_file else 'unknown'
            title = f"Sysmon 11: File created in staging path: '{target_basename}'"
            rule_reason = (
                f"Observation: File creation in temporary or startup directory: "
                f"{target_file}."
            )
        else:
            target_basename = target_file.split('\\')[-1] if target_file else 'unknown'
            severity = 'Informational'
            title = f"Sysmon 11: File created: '{target_basename}'"
            rule_reason = "Observation: File system creation event recorded by Sysmon."

    elif event_id == 22:
        # DNS Query
        category = 'Network'
        if any(sd in query_name.lower() for sd in _SUSPICIOUS_DOMAINS):
            severity = 'Medium'
            title = f"Sysmon 22: DNS query to suspicious domain: '{query_name}'"
            rule_reason = (
                f"Observation: DNS resolution request for domain '{query_name}' "
                f"which matches a known file-sharing, tunnelling, or code-hosting "
                f"service. Verify this is expected."
            )
        elif query_name:
            severity = 'Informational'
            title = f"Sysmon 22: DNS query: '{query_name}'"
            rule_reason = (
                f"Observation: DNS name resolution query for '{query_name}' "
                f"recorded by Sysmon."
            )
        else:
            severity = 'Informational'
            title = "Sysmon 22: DNS query event"
            rule_reason = "Observation: DNS query event recorded by Sysmon."

    # -----------------------------------------------------------------
    # Assemble details
    # -----------------------------------------------------------------
    details_parts = []
    if rule_reason:
        details_parts.append(rule_reason)
    if rule_name:
        details_parts.append(f"Rule: {rule_name}")
    if computer:
        details_parts.append(f"Computer: {computer}")
    if event_id:
        details_parts.append(f"EventID: {event_id}")
    if process_guid:
        details_parts.append(f"ProcessGuid: {process_guid}")
    if process_id:
        details_parts.append(f"PID: {process_id}")
    if image:
        details_parts.append(f"Image: {image}")
    if cmd_line and cmd_line != image:
        details_parts.append(f"CommandLine: {cmd_line}")
    if parent_image:
        details_parts.append(f"ParentImage: {parent_image}")
    if parent_cmd:
        details_parts.append(f"ParentCmd: {parent_cmd}")
    if target_file:
        details_parts.append(f"TargetFile: {target_file}")
    if query_name:
        details_parts.append(f"QueryName: {query_name}")
    if query_results:
        details_parts.append(f"QueryResults: {query_results}")
    if src_ip:
        details_parts.append(f"SourceIP: {src_ip}")
    if dst_ip:
        dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        details_parts.append(f"Destination: {dst_str}")
    if hashes:
        details_parts.append(f"Hashes: {hashes}")

    details_text = " | ".join(details_parts) if details_parts else "Sysmon event details."

    deterministic_id = _generate_sysmon_id(
        event_id, event_time, rec_id, image, cmd_line
    )

    return {
        'id': deterministic_id,
        'event_time': event_time,
        'source': 'Sysmon',
        'category': category,
        'severity': severity,
        'title': title,
        'username': user,
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'protocol': protocol,
        'command': command,
        'details': details_text[:1400],
        'evidence_reference': evidence_ref,
        'is_demo': 0,
        'imported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'raw_payload': json.dumps(item)[:1000],
    }


def parse_sysmon_json(content_text):
    """
    Parses Sysmon JSON export text and returns:
      (records, successful_count, failed_count)
    """
    clean = content_text.lstrip('\ufeff').strip()
    records = []
    successful = 0
    failed = 0

    if not clean:
        return [], 0, 0

    if not (clean.startswith('[') or clean.startswith('{')):
        return [], 0, 1

    try:
        parsed = json.loads(clean)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return [], 0, 1

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            failed += 1
            continue
        try:
            rec = normalize_sysmon_event(item, i)
            records.append(rec)
            successful += 1
        except Exception:
            failed += 1

    return records, successful, failed
