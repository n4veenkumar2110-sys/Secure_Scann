"""
SecureScan Windows host security audit
======================================

Runs collectors/host_audit.ps1 (read-only PowerShell) and converts its JSON into
SecureScan events (source = 'System audit'). Each check produces either a finding
(a misconfiguration or risky state, with severity and explanation) or an
informational inventory record, so the audit itself becomes searchable evidence
that is correlated with Wireshark and Autopsy data.

Checks (CIS-benchmark style, no Administrator rights required):
  accounts      - Guest enabled, accounts without password, passwords that never expire, admin group size
  network       - listening ports (risky services exposed), established connections per process
  hardening     - firewall profiles, Microsoft Defender, UAC, RDP, SMBv1
  persistence   - Run/RunOnce keys, Startup folders, non-Microsoft scheduled tasks
  patching      - days since last installed update
  processes     - executables running from Temp/Downloads/Public
  security log  - failed logons / account changes in the last 24 h (only if readable)
"""

import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / 'host_audit.ps1'

RISKY_LISTEN_PORTS = {
    21: ('FTP', 'High', 'clear-text file transfer'), 23: ('Telnet', 'High', 'clear-text remote shell'),
    445: ('SMB', 'Medium', 'file sharing; wormable vulnerabilities such as EternalBlue target it'),
    139: ('NetBIOS', 'Medium', 'legacy file sharing'), 3389: ('RDP', 'Medium', 'remote desktop, a top brute-force target'),
    5900: ('VNC', 'High', 'remote desktop often without strong auth'), 5985: ('WinRM HTTP', 'Medium', 'remote management'),
    1433: ('MS SQL', 'Medium', 'database exposed on the network'), 3306: ('MySQL', 'Medium', 'database exposed on the network'),
    4444: ('4444', 'Critical', 'Metasploit default listener'), 1337: ('1337', 'High', 'common backdoor port'),
    31337: ('31337', 'Critical', 'Back Orifice backdoor port'),
}
SUSPICIOUS_PATH_MARKERS = ('\\temp\\', '\\downloads\\', '\\users\\public\\', '\\appdata\\local\\temp\\')
SCRIPT_MARKERS = ('powershell', '-enc', 'mshta', 'wscript', 'cscript', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin')


def run_collector(timeout=180):
    """Executes the PowerShell collector and returns its parsed JSON."""
    # Absolute path: never resolve powershell.exe through PATH (prevents PATH hijacking).
    ps = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    cmd = [str(ps), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(SCRIPT)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                          encoding='utf-8', errors='replace')
    out = proc.stdout.strip()
    if not out:
        raise RuntimeError(f'Host audit collector produced no output: {proc.stderr.strip()[:400]}')
    return json.loads(out[out.index('{'):])


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, dict):
        return [] if 'error' in v else [v]
    return [x for x in v if isinstance(x, dict)]


def _err(v):
    return v.get('error') if isinstance(v, dict) else None


def _parse_time(v):
    if not v:
        return None
    try:
        s = str(v).replace('Z', '+00:00')
        s = __import__('re').sub(r'(\.\d{6})\d+', r'\1', s)   # PowerShell emits 7 fractional digits
        t = datetime.datetime.fromisoformat(s)
        return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def audit_to_events(data, raw_hash=''):
    """Converts collector JSON into (records, checks_summary)."""
    host = data.get('host') or {}
    computer = host.get('computer') or 'localhost'
    now = datetime.datetime.now(datetime.timezone.utc)
    audit_time = host.get('audit_time') or now.isoformat()
    run_id = hashlib.sha256(f'{computer}|{audit_time}'.encode()).hexdigest()[:8]
    records, checks = [], []

    def add(check, category, severity, title, details, username='', src='', dst='', proto='', command='', key=''):
        rid = hashlib.sha256(f'{run_id}|{check}|{key or title}'.encode('utf-8', 'replace')).hexdigest()[:16]
        records.append({
            'id': f'host-{rid}', 'event_time': audit_time, 'source': 'System audit', 'category': category,
            'severity': severity, 'title': title, 'username': username, 'source_ip': src, 'destination_ip': dst,
            'protocol': proto, 'command': command,
            'details': f'{details} | Check: {check} | Computer: {computer} | AuditRun: {run_id}'[:1400],
            'evidence_reference': f'AUDIT-{run_id}-{check.upper()}-{len(records) + 1:03d}',
            'is_demo': 0, 'imported_at': now.isoformat(), 'raw_payload': f'host_audit sha256={raw_hash}',
        })

    def check(name, status, note):
        checks.append({'check': name, 'status': status, 'note': note})

    # ---- Host summary ---------------------------------------------------
    add('host', 'System', 'Informational', f'System audit of {computer}',
        f"OS: {host.get('os')} build {host.get('build')} | Audited as: {host.get('user')} "
        f"(administrator: {host.get('is_admin')}) | Last boot: {host.get('last_boot')}",
        username=str(host.get('user') or ''), key='host')

    # ---- Accounts --------------------------------------------------------
    users = _as_list(data.get('local_users'))
    if _err(data.get('local_users')):
        check('Local accounts', 'error', _err(data['local_users']))
    else:
        issues = 0
        for u in users:
            name = u.get('name', '')
            if not u.get('enabled'):
                continue
            if name.lower() == 'guest':
                issues += 1
                add('accounts', 'Account', 'High', "Guest account is ENABLED",
                    'Observation: The built-in Guest account allows anonymous interactive access. CIS 2.3.1.2 requires it disabled.',
                    username=name, key=f'guest-{name}')
            if u.get('password_required') is False:
                add('accounts', 'Account', 'Medium', f"Account '{name}' is allowed a blank password",
                    'Observation: The PasswordRequired flag is not set, so a blank password is permitted for this account. '
                    'Accounts that sign in with a Microsoft account often show this flag; verify the account really has a '
                    'password or PIN (CIS 1.1.x / net user <name> /passwordreq:yes).',
                    username=name, key=f'nopw-{name}')
            if u.get('password_expires') is False:
                add('accounts', 'Account', 'Low', f"Password for '{name}' never expires",
                    f"Observation: Password last set {u.get('password_last_set') or 'unknown'}. Long-lived passwords increase exposure if leaked.",
                    username=name, key=f'noexp-{name}')
            add('accounts', 'Account', 'Informational', f"Local account '{name}' (enabled)",
                f"Last logon: {u.get('last_logon') or 'never'} | Password last set: {u.get('password_last_set') or 'unknown'}",
                username=name, key=f'inv-{name}')
        blank = sum(1 for u in users if u.get('enabled') and u.get('password_required') is False)
        check('Local accounts', 'fail' if issues else 'warn' if blank else 'pass',
              f'{len(users)} accounts, {issues} high-risk, {blank} allowed a blank password')

    admins = _as_list(data.get('administrators'))
    if _err(data.get('administrators')):
        check('Administrators group', 'error', _err(data['administrators']))
    else:
        human = [a for a in admins if 'administrator' != a.get('name', '').split('\\')[-1].lower()]
        sev = 'Medium' if len(human) > 2 else 'Informational'
        add('accounts', 'Account', sev, f'Administrators group has {len(admins)} member(s)',
            'Members: ' + ', '.join(a.get('name', '?') for a in admins) +
            ('. Observation: many administrators widens the attack surface (least privilege).' if sev == 'Medium' else ''),
            key='admins')
        check('Administrators group', 'warn' if sev == 'Medium' else 'pass', f'{len(admins)} members')

    # ---- Network: listening ports ---------------------------------------
    listening = _as_list(data.get('listening_ports'))
    if _err(data.get('listening_ports')):
        check('Listening ports', 'error', _err(data['listening_ports']))
    else:
        exposed = 0
        seen = set()
        for p in listening:
            port, addr, proc = int(p.get('port') or 0), p.get('address', ''), p.get('process') or '?'
            if (port, addr) in seen:
                continue
            seen.add((port, addr))
            network_wide = addr in ('0.0.0.0', '::')
            if port in RISKY_LISTEN_PORTS:
                svc, sev, why = RISKY_LISTEN_PORTS[port]
                if not network_wide and sev != 'Critical':
                    sev = 'Low'
                exposed += 1
                add('ports', 'Network', sev, f'{svc} service listening on port {port} ({proc})',
                    f"Observation: {why}. Bound to {addr} ({'all interfaces - reachable from the network' if network_wide else 'local interface only'}). PID {p.get('pid')}.",
                    dst=addr, proto='TCP', command=f'{proc} :{port}', key=f'listen-{addr}-{port}')
        add('ports', 'Network', 'Informational', f'{len(seen)} listening TCP ports inventoried',
            'Ports: ' + ', '.join(f"{a}:{p}" for p, a in sorted(seen))[:1200], key='listen-inv')
        check('Listening ports', 'warn' if exposed else 'pass', f'{len(seen)} listening, {exposed} risky services')

    # ---- Network: established connections (process attribution) ---------
    conns = _as_list(data.get('connections'))
    if _err(data.get('connections')):
        check('Active connections', 'error', _err(data['connections']))
    else:
        for c in conns:
            proc, rport = c.get('process') or '?', int(c.get('remote_port') or 0)
            susp_port = rport in (4444, 1337, 31337, 6667, 9001, 8888, 5555, 12345)
            script = any(m in proc.lower() for m in ('powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32'))
            sev = 'High' if susp_port else 'Medium' if script else 'Informational'
            add('connections', 'Network', sev, f"{proc} connected to {c.get('remote')}:{rport}",
                f"Observation: Established TCP session (process attribution from the host). "
                f"{'Destination port is a known backdoor/C2 port. ' if susp_port else ''}"
                f"{'Script interpreter with a network connection. ' if script else ''}"
                f"Local {c.get('local')}:{c.get('local_port')} | PID {c.get('pid')} | Destination: {c.get('remote')}:{rport}",
                src=c.get('local', ''), dst=c.get('remote', ''), proto='TCP',
                command=f"{proc} {c.get('local_port')} → {rport}",
                key=f"conn-{c.get('remote')}-{rport}-{c.get('local_port')}")
        check('Active connections', 'pass', f'{len(conns)} established outbound sessions attributed to processes')

    # ---- Hardening -------------------------------------------------------
    fw = _as_list(data.get('firewall'))
    if _err(data.get('firewall')):
        check('Windows Firewall', 'error', _err(data['firewall']))
    else:
        off = [f['profile'] for f in fw if not f.get('enabled')]
        add('firewall', 'System', 'High' if off else 'Informational',
            f"Windows Firewall disabled for: {', '.join(off)}" if off else 'Windows Firewall enabled on all profiles',
            'Profiles: ' + ', '.join(f"{f['profile']}={'on' if f.get('enabled') else 'OFF'}" for f in fw), key='fw')
        check('Windows Firewall', 'fail' if off else 'pass', 'off: ' + ', '.join(off) if off else 'all profiles on')

    d = data.get('defender') or {}
    if _err(d):
        check('Microsoft Defender', 'error', _err(d))
    else:
        problems = []
        if d.get('antivirus_enabled') is False:
            problems.append('antivirus disabled')
        if d.get('realtime_protection') is False:
            problems.append('real-time protection OFF')
        if (d.get('signature_age_days') or 0) > 7:
            problems.append(f"signatures {d.get('signature_age_days')} days old")
        add('defender', 'System', 'High' if problems else 'Informational',
            'Microsoft Defender: ' + ('; '.join(problems) if problems else 'protection active'),
            f"Antivirus: {d.get('antivirus_enabled')} | Real-time: {d.get('realtime_protection')} | Tamper protection: "
            f"{d.get('tamper_protection')} | Signature age: {d.get('signature_age_days')} days", key='defender')
        check('Microsoft Defender', 'fail' if problems else 'pass', '; '.join(problems) or 'active, signatures current')

    uac = data.get('uac') or {}
    if not _err(uac):
        on = uac.get('enable_lua') == 1
        add('uac', 'System', 'Informational' if on else 'High', f"User Account Control {'enabled' if on else 'DISABLED'}",
            'Observation: UAC separates admin and standard tokens; disabling it lets any program run with full rights.'
            if not on else f"EnableLUA=1, admin prompt behaviour={uac.get('consent_prompt_admin')}", key='uac')
        check('User Account Control', 'pass' if on else 'fail', 'enabled' if on else 'disabled')

    rdp = data.get('rdp') or {}
    if not _err(rdp):
        add('rdp', 'System', 'Medium' if rdp.get('enabled') else 'Informational',
            f"Remote Desktop {'ENABLED' if rdp.get('enabled') else 'disabled'}",
            'Observation: RDP is the most brute-forced Windows service; restrict it with NLA, VPN and lockout.'
            if rdp.get('enabled') else 'fDenyTSConnections=1', key='rdp')
        check('Remote Desktop', 'warn' if rdp.get('enabled') else 'pass', 'enabled' if rdp.get('enabled') else 'disabled')

    smb = data.get('smb1') or {}
    if not _err(smb):
        on = smb.get('server_smb1') is True or smb.get('client_driver_present')
        add('smb1', 'System', 'High' if on else 'Informational', f"SMBv1 {'present/enabled' if on else 'not enabled'}",
            'Observation: SMBv1 is obsolete and was exploited by WannaCry/NotPetya (MS17-010).' if on else 'SMBv1 server and client driver absent.',
            key='smb1')
        check('SMBv1', 'fail' if on else 'pass', 'enabled' if on else 'disabled')

    # ---- Persistence ----------------------------------------------------
    autoruns = _as_list(data.get('autoruns'))
    if _err(data.get('autoruns')):
        check('Autostart entries', 'error', _err(data['autoruns']))
    else:
        flagged = 0
        for a in autoruns:
            cmd = a.get('command', '')
            low = cmd.lower()
            bad = any(m in low for m in SUSPICIOUS_PATH_MARKERS) or any(m in low for m in SCRIPT_MARKERS)
            flagged += bad
            add('autoruns', 'Process', 'Medium' if bad else 'Informational', f"Autostart entry: {a.get('name')}",
                ('Observation: Starts from a temporary/user-writable folder or via a script interpreter - a common '
                 'malware persistence technique (MITRE T1547.001). ' if bad else 'Program launched automatically at logon. ')
                + f"Location: {a.get('location')}", command=cmd, key=f"run-{a.get('location')}-{a.get('name')}")
        check('Autostart entries', 'warn' if flagged else 'pass', f'{len(autoruns)} entries, {flagged} suspicious')

    tasks = _as_list(data.get('scheduled_tasks'))
    if _err(data.get('scheduled_tasks')):
        check('Scheduled tasks', 'error', _err(data['scheduled_tasks']))
    else:
        flagged = 0
        for t in tasks:
            cmd = t.get('command', '')
            low = cmd.lower()
            bad = any(m in low for m in SUSPICIOUS_PATH_MARKERS) or any(m in low for m in ('-enc', 'mshta', 'certutil', 'bitsadmin', 'wscript'))
            flagged += bad
            add('tasks', 'Process', 'Medium' if bad else 'Informational', f"Scheduled task: {t.get('path', '')}{t.get('name')}",
                ('Observation: Task runs from a temporary folder or uses an obfuscation/download tool (MITRE T1053.005). ' if bad else
                 'Non-Microsoft scheduled task. ') + f"Author: {t.get('author') or 'unknown'} | State: {t.get('state')}",
                command=cmd, key=f"task-{t.get('path')}{t.get('name')}")
        check('Scheduled tasks', 'warn' if flagged else 'pass', f'{len(tasks)} third-party tasks, {flagged} suspicious')

    # ---- Patching -------------------------------------------------------
    hf = data.get('hotfixes') or {}
    if _err(hf):
        check('Windows Update', 'error', _err(hf))
    else:
        last = _parse_time(hf.get('latest_installed'))
        age = (now - last).days if last else None
        sev = 'High' if age is None or age > 90 else 'Medium' if age > 45 else 'Informational'
        add('patching', 'System', sev,
            f'Last Windows update installed {age} days ago' if age is not None else 'No installed updates found',
            f"Latest: {hf.get('latest_id')} on {hf.get('latest_installed')} | Updates recorded: {hf.get('count')}. "
            + ('Observation: Missing security updates leave known vulnerabilities exploitable.' if sev != 'Informational' else ''),
            key='patch')
        check('Windows Update', 'pass' if sev == 'Informational' else 'warn' if sev == 'Medium' else 'fail',
              f'{age} days since last update' if age is not None else 'unknown')

    # ---- Processes from risky locations ---------------------------------
    rp = _as_list(data.get('risky_processes'))
    if not _err(data.get('risky_processes')):
        for p in rp:
            add('processes', 'Process', 'Medium', f"Process running from user-writable folder: {p.get('name')}",
                f"Observation: Executables launched from Temp/Downloads/Public are a common malware pattern. PID {p.get('pid')}",
                command=p.get('path', ''), key=f"proc-{p.get('pid')}")
        check('Process locations', 'warn' if rp else 'pass', f'{len(rp)} processes from Temp/Downloads/Public')

    # ---- Security event log --------------------------------------------
    sl = data.get('security_log')
    if _err(sl):
        check('Security event log', 'skipped', 'Requires Administrator: ' + _err(sl)[:120])
    else:
        evs = _as_list(sl)
        failed = [e for e in evs if e.get('id') == 4625]
        for e in evs:
            eid = e.get('id')
            sev = {4625: 'High', 4720: 'Medium', 4726: 'High', 4732: 'Medium'}.get(eid, 'Low')
            cat = 'Authentication' if eid == 4625 else 'Account'
            label = {4625: 'Failed login attempt', 4720: 'User account created', 4726: 'User account deleted',
                     4732: 'Member added to security group'}.get(eid, 'Security event')
            records.append({**records[0], 'id': 'host-' + hashlib.sha256(f"{run_id}|sec|{e.get('time')}|{eid}|{e.get('message')}".encode()).hexdigest()[:16],
                            'event_time': e.get('time') or audit_time, 'category': cat, 'severity': sev, 'username': '',
                            'title': f'Event {eid}: {label}', 'details': f"{e.get('message')} | Check: security_log | Computer: {computer}",
                            'evidence_reference': f'AUDIT-{run_id}-SEC-{eid}'})
        check('Security event log', 'warn' if failed else 'pass', f'{len(evs)} relevant events in 24 h ({len(failed)} failed logons)')

    return records, checks, {'computer': computer, 'run_id': run_id, 'audit_time': audit_time,
                             'is_admin': host.get('is_admin'), 'os': host.get('os')}
