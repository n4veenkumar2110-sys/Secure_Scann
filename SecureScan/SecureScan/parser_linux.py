import re
import datetime
import uuid
import hashlib


def _deterministic_id(raw_line):
    """Content-derived ID: re-importing the same audit log no longer duplicates events
    (auditd lines embed a unique timestamp:serial, so identical lines are the same record)."""
    return "audit-" + hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()[:16]

def parse_audit_timestamp(epoch_str):
    """Converts a Linux audit epoch string (e.g., 1700000000.123) into an ISO 8601 string."""
    try:
        sec = float(epoch_str)
        dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

def extract_field(line, pattern, default=''):
    """Extracts a regex match or returns default."""
    m = re.search(pattern, line)
    return m.group(1).strip('"') if m else default

def parse_linux_audit_text(content_text, import_ref_prefix="AUDIT"):
    """
    Parses Linux audit log text and returns (records, successful_count, failed_count).
    Supports common auditd record types: USER_AUTH, USER_LOGIN, USER_START,
    ADD_USER, DEL_USER, USER_MGMT, EXECVE, SYSCALL, PATH, etc.
    """
    lines = content_text.splitlines()
    records = []
    successful_count = 0
    failed_count = 0

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for idx, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Look for standard auditd signature: msg=audit(1699999999.123:456):
        time_match = re.search(r'msg=audit\(([\d\.]+):(\d+)\):', line)
        type_match = re.search(r'type=([A-Z_]+)', line)

        if not time_match and not type_match:
            # Check if this might be a generic syslog auth line (e.g. Nov 20 12:00:00 sshd...)
            if 'sshd' in line or 'login' in line or 'sudo' in line:
                record_id = _deterministic_id(line)
                records.append({
                    'id': record_id,
                    'event_time': now_iso,
                    'source': 'Linux audit',
                    'category': 'Authentication' if 'login' in line or 'sshd' in line else 'Process',
                    'severity': 'Medium' if 'fail' in line.lower() else 'Informational',
                    'title': 'System log event',
                    'username': extract_field(line, r'for (\w+)', ''),
                    'source_ip': extract_field(line, r'from ([\d\.]+)', ''),
                    'destination_ip': '',
                    'protocol': 'SSH' if 'sshd' in line else '',
                    'command': '',
                    'details': line[:1400],
                    'evidence_reference': f"{import_ref_prefix}-{idx+1:04d}",
                    'is_demo': 0,
                    'imported_at': now_iso,
                    'raw_payload': line
                })
                successful_count += 1
                continue
            else:
                failed_count += 1
                continue

        raw_time = time_match.group(1) if time_match else ''
        event_time = parse_audit_timestamp(raw_time) if raw_time else now_iso
        record_type = type_match.group(1) if type_match else 'AUDIT_RECORD'

        # Extract standard audit fields
        acct = extract_field(line, r'acct="?([^" \n]+)"?')
        uid = extract_field(line, r'\buid=(\d+)')
        auid = extract_field(line, r'\bauid=(\d+)')
        exe = extract_field(line, r'exe="?([^" \n]+)"?')
        comm = extract_field(line, r'comm="?([^" \n]+)"?')
        addr = extract_field(line, r'addr="?([^" \n]+)"?')
        hostname = extract_field(line, r'hostname="?([^" \n]+)"?')
        res = extract_field(line, r'\bres=([a-zA-Z0-9]+)')
        terminal = extract_field(line, r'terminal="?([^" \n]+)"?')

        user = acct or (f"uid:{uid}" if uid and uid != '4294967295' else '')
        command = exe or comm
        source_ip = addr if addr and addr != '?' else hostname

        # Extract EXECVE arguments if present (a0=... a1=... a2=...)
        args = re.findall(r'\ba\d+="?([^" \n]+)"?', line)
        if args and not command:
            command = " ".join(args)

        # Classification and Detection Rules
        category = 'System'
        severity = 'Informational'
        title = f"{record_type} event"
        rule_reason = ""

        is_failed = res.lower() in ('failed', '0', 'no') or 'fail' in line.lower() or 'denied' in line.lower()

        if record_type in ('USER_AUTH', 'USER_LOGIN'):
            category = 'Authentication'
            if is_failed:
                severity = 'High'
                title = f"Failed authentication for '{user or 'unknown'}'"
                rule_reason = "Authentication failure observed. Review account and source IP for brute-force or unauthorized attempts."
            else:
                severity = 'Low'
                title = f"Successful user login for '{user or 'system'}'"
                rule_reason = "Standard user login recorded."

        elif record_type in ('ADD_USER',):
            category = 'Account'
            severity = 'Medium'
            title = f"New user account created: '{user}'"
            rule_reason = "Local account creation event observed in system audit."

        elif record_type in ('DEL_USER',):
            category = 'Account'
            severity = 'High'
            title = f"User account deleted: '{user}'"
            rule_reason = "Account removal event observed. Validate authorization for account deprovisioning."

        elif record_type in ('USER_MGMT',):
            category = 'Account'
            severity = 'Medium'
            title = f"User management action for '{user}'"
            rule_reason = "Account modification observed in auditd records."

        elif record_type in ('EXECVE', 'SYSCALL') or any(kw in (exe or '').lower() for kw in ['sudo', 'su', 'useradd', 'userdel']):
            category = 'Process'
            if any(priv in (command or '').lower() for priv in ['sudo', '/bin/su', 'useradd', 'userdel', 'passwd', 'chmod', 'chown']):
                severity = 'Medium'
                title = f"Privileged command executed: '{command}'"
                rule_reason = "Execution of elevated command observed. Verify analyst authorization."
            else:
                severity = 'Low'
                title = f"Process execution: '{command or record_type}'"
                rule_reason = "Process execution event recorded in audit logs."

        elif record_type == 'PATH':
            category = 'System'
            severity = 'Low'
            item_name = extract_field(line, r'name="?([^" \n]+)"?')
            title = f"File access path: '{item_name}'" if item_name else "File system access"
            rule_reason = "File system path recorded in audit event."

        elif is_failed:
            severity = 'Medium'
            title = f"{record_type} failure event"
            rule_reason = f"Failure result ({res}) noted in audit log record."

        details_parts = []
        if rule_reason:
            details_parts.append(f"Observation: {rule_reason}")
        if record_type:
            details_parts.append(f"Type: {record_type}")
        if terminal and terminal != '?':
            details_parts.append(f"Terminal: {terminal}")
        if res:
            details_parts.append(f"Result: {res}")
        if command:
            details_parts.append(f"Command: {command}")
        details_text = " | ".join(details_parts) if details_parts else line[:400]

        record_id = _deterministic_id(line)
        records.append({
            'id': record_id,
            'event_time': event_time,
            'source': 'Linux audit',
            'category': category,
            'severity': severity,
            'title': title,
            'username': user,
            'source_ip': source_ip,
            'destination_ip': '',
            'protocol': '',
            'command': command,
            'details': details_text[:1400],
            'evidence_reference': f"{import_ref_prefix}-{idx+1:04d}",
            'is_demo': 0,
            'imported_at': now_iso,
            'raw_payload': line
        })
        successful_count += 1

    return records, successful_count, failed_count
