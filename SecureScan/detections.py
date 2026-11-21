"""
SecureScan Correlation & Detection Engine
=========================================

The individual parsers (Windows, Sysmon, Linux auditd, Wireshark, Autopsy) flag
*single* events in isolation ("one failed logon", "one SYN packet").  Real
intrusions only become visible when several events are linked together:

    6 failed logons  ->  1 successful logon from the same IP   = compromised account
    1 source IP      ->  20 different destination ports        = port scan
    a process        ->  connects to IP that also appears in the packet capture
                                                               = corroborated C2 lead

This module runs transparent, explainable correlation rules over the unified
`events` table and produces *detections*.  Every detection carries:

  * the MITRE ATT&CK technique(s) it maps to,
  * the exact evidence event IDs that triggered it (so an analyst can verify it),
  * a plain-English explanation and a recommended next step.

Detections are investigative leads, NOT proof of compromise.  They are computed
on demand from SQLite (nothing is written back), so they always reflect the
current evidence and disappear automatically when demo data is cleared.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# MITRE ATT&CK reference (subset used by the rules)
# ---------------------------------------------------------------------------
MITRE = {
    'T1110':     ('Brute Force', 'Credential Access'),
    'T1078':     ('Valid Accounts', 'Initial Access'),
    'T1033':     ('System Owner/User Discovery', 'Discovery'),
    'T1087':     ('Account Discovery', 'Discovery'),
    'T1082':     ('System Information Discovery', 'Discovery'),
    'T1136':     ('Create Account', 'Persistence'),
    'T1531':     ('Account Access Removal', 'Impact'),
    'T1003':     ('OS Credential Dumping', 'Credential Access'),
    'T1490':     ('Inhibit System Recovery', 'Impact'),
    'T1059.001': ('Command and Scripting Interpreter: PowerShell', 'Execution'),
    'T1105':     ('Ingress Tool Transfer', 'Command and Control'),
    'T1046':     ('Network Service Discovery', 'Discovery'),
    'T1571':     ('Non-Standard Port', 'Command and Control'),
    'T1071':     ('Application Layer Protocol (beaconing)', 'Command and Control'),
    'T1071.004': ('Application Layer Protocol: DNS', 'Command and Control'),
    'T1568.002': ('Dynamic Resolution: Domain Generation Algorithms', 'Command and Control'),
    'T1070.001': ('Indicator Removal: Clear Windows Event Logs', 'Defense Evasion'),
    'T1070.004': ('Indicator Removal: File Deletion', 'Defense Evasion'),
    'T1552.004': ('Unsecured Credentials: Private Keys', 'Credential Access'),
}

# Kill-chain ordering used to present tactics as an attack progression.
TACTIC_ORDER = [
    'Initial Access', 'Execution', 'Persistence', 'Credential Access',
    'Discovery', 'Command and Control', 'Defense Evasion', 'Impact',
]

SEVERITY_WEIGHT = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1}
RISK_POINTS = {'Critical': 30, 'High': 15, 'Medium': 6, 'Low': 2, 'Informational': 0}

# ---------------------------------------------------------------------------
# Tunable thresholds (kept at module level so they are easy to explain/adjust)
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 5            # failed logons ...
BRUTE_FORCE_WINDOW = 10 * 60         # ... within 10 minutes
BRUTE_SUCCESS_WINDOW = 60 * 60       # success within 60 min after the burst
RECON_THRESHOLD = 3                  # distinct discovery commands ...
RECON_WINDOW = 15 * 60               # ... within 15 minutes by one user
PORT_SCAN_THRESHOLD = 10             # distinct destination ports ...
PORT_SCAN_WINDOW = 5 * 60            # ... within 5 minutes from one source IP
BEACON_THRESHOLD = 3                 # repeated connections to a suspicious port
ACCOUNT_CHURN_WINDOW = 24 * 3600     # account created and deleted within 24 h

SUSPICIOUS_PORTS = {
    4444: 'Metasploit default listener', 1337: 'common backdoor port',
    31337: 'Back Orifice / "elite" port', 6667: 'IRC (legacy botnet C2)',
    8888: 'common alt-HTTP / C2 port', 9001: 'Tor ORPort / C2',
    5555: 'Android ADB / RAT port', 12345: 'NetBus trojan port',
    6666: 'IRC / backdoor port', 2222: 'alternate SSH',
}

SUSPICIOUS_DOMAIN_MARKERS = [
    'ngrok', 'duckdns', 'no-ip', 'noip', 'dyndns', 'pastebin', 'transfer.sh',
    'serveo', 'trycloudflare', 'portmap.io', '.onion', 'hopto.org', 'ddns.net',
]

RECON_PATTERNS = [
    (r'\bwhoami(\.exe)?\b', 'whoami'), (r'\bnet1?(\.exe)?\s+(user|group|localgroup|view|accounts|share)\b', 'net'),
    (r'\bnltest(\.exe)?\b', 'nltest'), (r'\bipconfig(\.exe)?\b', 'ipconfig'),
    (r'\bsysteminfo(\.exe)?\b', 'systeminfo'), (r'\bquser(\.exe)?\b', 'quser'),
    (r'\btasklist(\.exe)?\b', 'tasklist'), (r'\bnetstat(\.exe)?\b', 'netstat'),
    (r'\barp(\.exe)?\s+-a\b', 'arp'), (r'(^|[/\s])id(\s|$)', 'id'), (r'\buname\b', 'uname'),
    (r'\bhostname(\.exe)?\b', 'hostname'), (r'/etc/passwd', 'cat /etc/passwd'),
    (r'\bget-(localuser|aduser|adgroupmember|computerinfo)\b', 'powershell-recon'),
]

CRED_DUMP_PATTERNS = [
    (r'mimikatz', 'Mimikatz'), (r'sekurlsa', 'sekurlsa::logonpasswords'), (r'lsadump', 'lsadump'),
    (r'procdump.*lsass', 'ProcDump of LSASS'), (r'comsvcs(\.dll)?.*minidump', 'comsvcs.dll MiniDump of LSASS'),
    (r'reg(\.exe)?\s+save\s+hklm\\(sam|system|security)', 'registry hive export (SAM/SYSTEM)'),
    (r'ntds\.dit', 'NTDS.dit access'), (r'\blsass\.dmp\b', 'LSASS memory dump file'),
]

RECOVERY_INHIBIT_PATTERNS = [
    (r'vssadmin(\.exe)?\s+delete\s+shadows', 'vssadmin delete shadows'),
    (r'wbadmin(\.exe)?\s+delete', 'wbadmin delete backup'),
    (r'bcdedit.*recoveryenabled\s+no', 'bcdedit recovery disabled'),
    (r'shadowcopy\s+delete', 'WMI shadowcopy delete'),
]

MALICIOUS_SCRIPT_PATTERNS = [
    (r'-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}', 'Base64-encoded PowerShell command'),
    (r'\biex\b|invoke-expression', 'Invoke-Expression (in-memory execution)'),
    (r'downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer', 'PowerShell download cradle'),
    (r'certutil(\.exe)?.*-urlcache', 'certutil used as downloader (LOLBin)'),
    (r'bitsadmin(\.exe)?.*/transfer', 'bitsadmin used as downloader (LOLBin)'),
    (r'mshta(\.exe)?\s+https?://', 'mshta executing remote content'),
    (r'(curl|wget)\s+[^|]*\|\s*(ba)?sh', 'Linux download-and-execute pipe'),
    (r'-w(indowstyle)?\s+hidden', 'Hidden PowerShell window'),
]

LOG_CLEAR_PATTERNS = [
    (r'wevtutil(\.exe)?\s+cl\b', 'wevtutil clear-log'),
    (r'clear-eventlog|remove-eventlog', 'PowerShell Clear-EventLog'),
    (r'auditctl\s+-D', 'auditctl rule deletion'),
    (r'shred\b.*?/var/log', 'shred of /var/log file'),
    (r'rm\s+-[rf]+\s+/var/log', 'rm of /var/log'),
    (r'history\s+-c', 'shell history wipe'),
]

PRIVATE_KEY_PATTERN = r'(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem\b|\.ppk\b|\.kdbx\b|wallet\.dat)'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ts(value):
    """Parses an ISO 8601 string into an aware datetime (UTC fallback)."""
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _clean(v):
    v = (v or '').strip()
    if '\\' in v:                      # 'WS-FIN-07\j.mercer' -> 'j.mercer' (Sysmon vs Security log)
        v = v.split('\\')[-1]
    return '' if v in ('—', '-', 'None', 'unknown', '?') else v


def _text(ev):
    return ' '.join(str(ev.get(k) or '') for k in ('title', 'command', 'details')).lower()


def _max_sev(evts, floor='Low'):
    best = floor
    for e in evts:
        if SEVERITY_WEIGHT.get(e.get('severity'), 1) > SEVERITY_WEIGHT.get(best, 1):
            best = e['severity']
    return best


def _dst_port(ev):
    """Extracts a destination port from the normalised network fields."""
    cmd = ev.get('command') or ''
    m = re.search(r'(\d{1,5})\s*(?:→|->)\s*(\d{1,5})', cmd)
    if m:
        return int(m.group(2))
    m = re.search(r'Destination:\s*[\d\.:a-fA-F]+:(\d{1,5})', ev.get('details') or '')
    if m:
        return int(m.group(1))
    m = re.search(r'(?:→|->)\s*[\d\.]+:(\d{1,5})', ev.get('title') or '')
    if m:
        return int(m.group(1))
    m = re.search(r'port (\d{1,5})', (ev.get('title') or '') + ' ' + (ev.get('details') or ''), re.I)
    return int(m.group(1)) if m else None


def _entropy(label):
    if not label:
        return 0.0
    counts = defaultdict(int)
    for ch in label:
        counts[ch] += 1
    return -sum((c / len(label)) * math.log2(c / len(label)) for c in counts.values())


def _dns_name(ev):
    blob = f"{ev.get('title') or ''} {ev.get('details') or ''} {ev.get('command') or ''}"
    for pat in (r'DNS Query:\s*([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})',
                r'QueryName[:\s]+([a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})',
                r"query(?:\s+for)?[:\s]+'?([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+)'?",
                r'\bA{1,4}\s+([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+)'):
        m = re.search(pat, blob, re.I)
        if m and not m.group(1).lower().startswith('0x'):
            return m.group(1).lower().rstrip('.')
    return None


def _is_failed_auth(ev):
    if ev.get('category') != 'Authentication':
        return False
    t = (ev.get('title') or '').lower()
    return 'fail' in t or '4625' in t


def _is_success_auth(ev):
    if ev.get('category') != 'Authentication':
        return False
    t = (ev.get('title') or '').lower()
    return ('success' in t or '4624' in t) and 'fail' not in t


def _sliding_clusters(items, window_seconds, threshold, key_fn=None):
    """Returns maximal clusters of time-sorted (ts, ev) items where at least
    `threshold` items (or distinct key_fn values) fall inside `window_seconds`."""
    items = sorted(items, key=lambda x: x[0])
    clusters, i = [], 0
    while i < len(items):
        j = i
        while j + 1 < len(items) and (items[j + 1][0] - items[i][0]).total_seconds() <= window_seconds:
            j += 1
        window = items[i:j + 1]
        size = len({key_fn(ev) for _, ev in window}) if key_fn else len(window)
        if size >= threshold:
            # extend while subsequent items keep chaining within the window
            while j + 1 < len(items) and (items[j + 1][0] - items[j][0]).total_seconds() <= window_seconds:
                j += 1
            clusters.append(items[i:j + 1])
            i = j + 1
        else:
            i += 1
    return clusters


class _Builder:
    """Collects detections and guarantees stable IDs + consistent shape."""

    def __init__(self):
        self.items = []

    def add(self, rule_id, name, severity, techniques, evts, summary, recommendation,
            key='', confidence='Medium', entities=None):
        if not evts:
            return
        times = [t for t in (_ts(e.get('event_time')) for e in evts) if t]
        ents = {'users': set(), 'ips': set(), 'processes': set(), 'domains': set()}
        for e in evts:
            if _clean(e.get('username')):
                ents['users'].add(_clean(e['username']))
            for k in ('source_ip', 'destination_ip'):
                if _clean(e.get(k)):
                    ents['ips'].add(_clean(e[k]))
        for k, vals in (entities or {}).items():
            ents.setdefault(k, set()).update(v for v in vals if v)
        digest = hashlib.sha256(f"{rule_id}|{key}|{sorted(e['id'] for e in evts)}".encode()).hexdigest()[:12]
        self.items.append({
            'id': f"det-{digest}",
            'rule_id': rule_id,
            'name': name,
            'severity': severity,
            'confidence': confidence,
            'mitre': [{'id': t, 'name': MITRE[t][0], 'tactic': MITRE[t][1]} for t in techniques],
            'first_seen': min(times).isoformat() if times else None,
            'last_seen': max(times).isoformat() if times else None,
            'event_count': len(evts),
            'event_ids': [e['id'] for e in evts][:50],
            'evidence': [
                {k: e.get(k) for k in ('id', 'event_time', 'source', 'severity', 'title', 'evidence_reference')}
                for e in sorted(evts, key=lambda x: x.get('event_time') or '')[:15]
            ],
            'evidence_refs': sorted({e.get('evidence_reference') for e in evts if e.get('evidence_reference')})[:12],
            'sources': sorted({e.get('source') for e in evts if e.get('source')}),
            'entities': {k: sorted(v)[:10] for k, v in ents.items() if v},
            'summary': summary,
            'recommendation': recommendation,
            'is_demo': all(bool(e.get('is_demo')) for e in evts),
        })


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------
def _rule_brute_force(events, out):
    """SS-001 / SS-002: failed-logon bursts, and bursts followed by a success."""
    failed = [(t, e) for e in events if _is_failed_auth(e) for t in [_ts(e.get('event_time'))] if t]
    success = [(t, e) for e in events if _is_success_auth(e) for t in [_ts(e.get('event_time'))] if t]

    groups = defaultdict(list)
    for t, e in failed:
        actor = _clean(e.get('source_ip')) or _clean(e.get('username'))
        if actor:
            groups[actor].append((t, e))

    for actor, items in groups.items():
        for cluster in _sliding_clusters(items, BRUTE_FORCE_WINDOW, BRUTE_FORCE_THRESHOLD):
            evts = [e for _, e in cluster]
            users = sorted({_clean(e.get('username')) for e in evts if _clean(e.get('username'))})
            start, end = cluster[0][0], cluster[-1][0]
            mins = max(1, round((end - start).total_seconds() / 60))

            # Look for a success from the same IP or for a targeted user shortly after.
            follow = [
                (t, e) for t, e in success
                if start <= t <= end + datetime.timedelta(seconds=BRUTE_SUCCESS_WINDOW)
                and (_clean(e.get('source_ip')) == actor or _clean(e.get('username')) in users)
            ]
            if follow:
                ok_t, ok_e = sorted(follow, key=lambda x: x[0])[0]
                out.add(
                    'SS-002', 'Brute force followed by successful logon', 'Critical',
                    ['T1110', 'T1078'], evts + [ok_e],
                    f"{len(evts)} failed logons from {actor} against {', '.join(users) or 'an account'} "
                    f"in ~{mins} min, then a SUCCESSFUL logon as '{_clean(ok_e.get('username')) or '?'}' "
                    f"at {ok_t.strftime('%H:%M:%S')} UTC. The password was very likely guessed.",
                    "Treat the account as compromised: disable or reset it, terminate its sessions, "
                    "block the source IP, and review everything the account did after the successful logon.",
                    key=actor, confidence='High')
            else:
                out.add(
                    'SS-001', 'Password brute-force attempt', 'High', ['T1110'], evts,
                    f"{len(evts)} failed logons from {actor} targeting {', '.join(users) or 'accounts'} "
                    f"within ~{mins} min (threshold: {BRUTE_FORCE_THRESHOLD} in {BRUTE_FORCE_WINDOW // 60} min). "
                    "No successful logon followed.",
                    "Confirm whether the source is authorised; consider account lockout policy and blocking the IP.",
                    key=actor, confidence='High')


def _rule_recon_burst(events, out):
    """SS-003: several distinct discovery commands by one user in a short window."""
    per_user = defaultdict(list)
    for e in events:
        if e.get('category') != 'Process':
            continue
        text = f"{e.get('command') or ''} {e.get('title') or ''}".lower()
        for pat, label in RECON_PATTERNS:
            if re.search(pat, text, re.I):
                t = _ts(e.get('event_time'))
                if t:
                    per_user[_clean(e.get('username')) or 'unknown'].append((t, dict(e, _recon=label)))
                break
    for user, items in per_user.items():
        for cluster in _sliding_clusters(items, RECON_WINDOW, RECON_THRESHOLD, key_fn=lambda ev: ev['_recon']):
            evts = [e for _, e in cluster]
            cmds = sorted({e['_recon'] for e in evts})
            out.add(
                'SS-003', 'Host & account discovery burst', 'High' if len(cmds) >= 5 else 'Medium',
                ['T1033', 'T1087', 'T1082'], evts,
                f"User '{user}' ran {len(cmds)} different discovery commands ({', '.join(cmds)}) within "
                f"{RECON_WINDOW // 60} min. Attackers typically do this right after gaining access to learn "
                "who they are, what privileges they have and what else is on the network.",
                "Check whether this was an administrator doing legitimate work; if not, scope the session "
                "that launched these commands.",
                key=user, entities={'processes': cmds})


def _rule_account_churn(events, out):
    """SS-004: account created then deleted within 24 h (temporary backdoor account)."""
    created, deleted = defaultdict(list), defaultdict(list)
    for e in events:
        if e.get('category') != 'Account':
            continue
        t, title = _ts(e.get('event_time')), (e.get('title') or '').lower()
        user = _clean(e.get('username'))
        m = re.search(r"(?:created|deleted):?\s*'([^']+)'", e.get('title') or '', re.I)
        if m:
            user = m.group(1)
        if not t or not user:
            continue
        if 'created' in title or '4720' in title:
            created[user.lower()].append((t, e))
        elif 'deleted' in title or '4726' in title:
            deleted[user.lower()].append((t, e))
    for user, c_items in created.items():
        for ct, ce in c_items:
            for dt, de in deleted.get(user, []):
                if 0 <= (dt - ct).total_seconds() <= ACCOUNT_CHURN_WINDOW:
                    hrs = round((dt - ct).total_seconds() / 3600, 1)
                    out.add(
                        'SS-004', 'Short-lived local account (create → delete)', 'High',
                        ['T1136', 'T1531'], [ce, de],
                        f"Account '{user}' was created and then deleted {hrs} h later. Short-lived accounts "
                        "are a common way to keep temporary access and then cover tracks.",
                        "Verify a change ticket exists for both actions; review logons made by this account "
                        "while it existed.", key=user, entities={'users': [user]})


def _rule_pattern(events, out, rule_id, name, severity, techniques, patterns, summary_fmt,
                  recommendation, confidence='High'):
    """Generic: group events whose command/title/details match any regex in `patterns`."""
    hits = defaultdict(list)
    labels = defaultdict(set)
    for e in events:
        text = _text(e)
        for p in patterns:
            pat, label = (p if isinstance(p, tuple) else (p, None))
            m = re.search(pat, text, re.I)
            if m:
                host_key = _clean(e.get('username')) or 'unknown'
                hits[host_key].append(e)
                labels[host_key].add(label or m.group(0).strip()[:40])
                break
    for user, evts in hits.items():
        lab = sorted(labels[user])
        out.add(rule_id, name, severity, techniques, evts,
                summary_fmt.format(user=user, n=len(evts), labels=', '.join(lab)),
                recommendation, key=user, confidence=confidence)


def _rule_port_scan(events, out):
    """SS-008: one source IP probing many destination ports in a short time."""
    per_src = defaultdict(list)
    for e in events:
        if e.get('category') != 'Network':
            continue
        # Count only connection ATTEMPTS: packets with SYN but no ACK, or host-logged
        # connections (no flags). Replies (SYN-ACK / RST-ACK) would otherwise make the
        # victim look like it is scanning the attacker.
        flags = re.search(r'TCP Flags:\s*\[([^\]]*)\]', e.get('details') or '')
        if flags and ('SYN' not in flags.group(1) or 'ACK' in flags.group(1)):
            continue
        src, port, t = _clean(e.get('source_ip')), _dst_port(e), _ts(e.get('event_time'))
        if src and port and t:
            per_src[src].append((t, dict(e, _port=port)))
    for src, items in per_src.items():
        for cluster in _sliding_clusters(items, PORT_SCAN_WINDOW, PORT_SCAN_THRESHOLD, key_fn=lambda ev: ev['_port']):
            evts = [e for _, e in cluster]
            ports = sorted({e['_port'] for e in evts})
            targets = sorted({_clean(e.get('destination_ip')) for e in evts if _clean(e.get('destination_ip'))})
            out.add(
                'SS-008', 'Port scan / service discovery', 'High', ['T1046'], evts,
                f"{src} probed {len(ports)} distinct ports on {', '.join(targets[:4]) or 'targets'} in under "
                f"{PORT_SCAN_WINDOW // 60} min (ports {', '.join(map(str, ports[:12]))}{'…' if len(ports) > 12 else ''}). "
                "This is the classic signature of a scanner such as nmap mapping open services.",
                "Identify the scanning host; if it is not an approved vulnerability scanner, isolate it and "
                "check the targets for follow-up connections on the ports that answered.",
                key=src, confidence='High')


def _rule_suspicious_port(events, out):
    """SS-009: connections to well-known backdoor / C2 ports (beaconing if repeated)."""
    groups = defaultdict(list)
    for e in events:
        if e.get('category') != 'Network':
            continue
        port = _dst_port(e)
        if port in SUSPICIOUS_PORTS:
            groups[(_clean(e.get('destination_ip')) or '?', port)].append(e)
    for (dst, port), evts in groups.items():
        beacon = len(evts) >= BEACON_THRESHOLD
        out.add(
            'SS-009', 'Command-and-control beaconing on non-standard port' if beacon
            else 'Connection to known backdoor port',
            'Critical' if beacon else 'High',
            ['T1571', 'T1071'] if beacon else ['T1571'], evts,
            f"{len(evts)} connection event(s) to {dst}:{port} ({SUSPICIOUS_PORTS[port]}). "
            + ("Repeated connections to the same uncommon port look like an implant checking in with its controller."
               if beacon else "Legitimate software rarely uses this port."),
            "Find the process that owns the connection (Sysmon Event 3 / netstat -ano), capture its binary "
            "and hash, and block the destination at the firewall.",
            key=f"{dst}:{port}", confidence='High' if beacon else 'Medium')


def _rule_suspicious_dns(events, out):
    """SS-010: DNS lookups of tunnelling / dynamic-DNS / paste sites or DGA-like names."""
    groups = defaultdict(list)
    reasons = {}
    for e in events:
        if e.get('category') != 'Network':
            continue
        name = _dns_name(e)
        if not name:
            continue
        marker = next((m for m in SUSPICIOUS_DOMAIN_MARKERS if m in name), None)
        first_label = name.split('.')[0]
        if marker:
            groups[name].append(e)
            reasons[name] = f"matches '{marker}' (tunnelling / dynamic-DNS / paste service)"
        elif len(first_label) >= 16 and _entropy(first_label) >= 3.5:
            groups[name].append(e)
            reasons[name] = f"random-looking label (entropy {_entropy(first_label):.1f}) typical of DGA malware"
    for name, evts in groups.items():
        techniques = ['T1071.004', 'T1568.002'] if 'entropy' in reasons[name] else ['T1071.004']
        out.add(
            'SS-010', 'Suspicious DNS resolution', 'Medium', techniques, evts,
            f"Host resolved '{name}' {len(evts)} time(s): {reasons[name]}. Attackers use such domains to "
            "reach command-and-control servers or exfiltrate data while blending into normal web traffic.",
            "Check which process made the query (Sysmon Event 22) and whether any data was sent to the "
            "resolved address.", key=name, entities={'domains': [name]})


def _rule_cross_source(events, out):
    """SS-011: the same remote IP observed by host telemetry AND by the packet capture."""
    host_side, wire_side = defaultdict(list), defaultdict(list)
    for e in events:
        ip = _clean(e.get('destination_ip'))
        if not ip or ip.startswith(('127.', '::1')):
            continue
        if e.get('source') in ('Sysmon', 'Windows audit', 'Linux audit', 'System audit'):
            host_side[ip].append(e)
        elif e.get('source') == 'Wireshark':
            wire_side[ip].append(e)
    for ip in sorted(set(host_side) & set(wire_side)):
        hevts, wevts = host_side[ip], wire_side[ip]
        procs = sorted({(e.get('command') or '').split('\\')[-1].split(' ')[0] for e in hevts if e.get('command')})
        worst = _max_sev(hevts + wevts)
        if SEVERITY_WEIGHT[worst] < SEVERITY_WEIGHT['Medium']:
            continue  # only escalate corroboration of something already interesting
        out.add(
            'SS-011', 'Cross-source corroboration: process ↔ network capture', worst,
            ['T1071'], hevts[:10] + wevts[:10],
            f"Remote address {ip} appears in host telemetry ({', '.join(sorted({e['source'] for e in hevts}))}"
            f"{' – process ' + ', '.join(procs[:3]) if procs else ''}) AND in the Wireshark capture "
            f"({len(wevts)} packets). Two independent evidence sources agree, which raises confidence "
            "and attributes the traffic to a specific program.",
            "Use this pairing to attribute network traffic to the process; preserve both the PCAP and the "
            "host log with their SHA-256 hashes.", key=ip, confidence='High',
            entities={'processes': procs})


def _rule_deleted_after_attack(events, out, existing):
    """SS-013: forensic deleted-file entries near other high-severity detections."""
    deleted = [e for e in events if e.get('source') == 'Autopsy' and 'deleted' in (e.get('title') or '').lower()]
    if not deleted:
        return
    hot = [(_ts(d['first_seen']), _ts(d['last_seen'])) for d in existing
           if d['severity'] in ('Critical', 'High') and d['first_seen']]
    if not hot:
        return
    near = []
    for e in deleted:
        t = _ts(e.get('event_time'))
        if t and any(s - datetime.timedelta(hours=24) <= t <= l + datetime.timedelta(hours=24) for s, l in hot):
            near.append(e)
    if near:
        out.add(
            'SS-013', 'File deletion during incident window', 'Medium', ['T1070.004'], near,
            f"{len(near)} file(s) recovered by Autopsy were deleted within 24 h of other high-severity "
            "activity. Deleting tools or output files is a typical clean-up step.",
            "Recover and hash the deleted files from the disk image; compare their names against commands "
            "seen in process telemetry.", confidence='Low')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_detections(events):
    """
    Runs every correlation rule over a list of event dicts (rows from `events`).
    Returns a dict with detections, a risk score, and an ATT&CK tactic summary.
    """
    events = [dict(e) for e in events]
    out = _Builder()

    _rule_brute_force(events, out)
    _rule_recon_burst(events, out)
    _rule_account_churn(events, out)
    _rule_pattern(
        events, out, 'SS-005', 'Credential dumping tool or technique', 'Critical', ['T1003'], CRED_DUMP_PATTERNS,
        "{n} event(s) for '{user}' match credential-dumping indicators ({labels}). These tools read password "
        "hashes or clear-text credentials from memory (LSASS) or the SAM/NTDS databases.",
        "Assume every credential used on this host is exposed: reset passwords (including service and "
        "krbtgt accounts if a DC is involved) and isolate the host.")
    _rule_pattern(
        events, out, 'SS-006', 'Backup / shadow copy deletion', 'Critical', ['T1490'], RECOVERY_INHIBIT_PATTERNS,
        "{n} event(s) for '{user}' delete shadow copies or backups ({labels}). Ransomware does this "
        "immediately before encrypting files so victims cannot restore them.",
        "Isolate the host from the network immediately and verify offline backups are intact.")
    _rule_pattern(
        events, out, 'SS-007', 'Malicious script / download cradle', 'High', ['T1059.001', 'T1105'],
        MALICIOUS_SCRIPT_PATTERNS,
        "{n} command(s) run by '{user}' show offensive scripting tradecraft: {labels}.",
        "Decode any Base64 payload, retrieve the downloaded file, and hash it against threat intelligence.")
    _rule_port_scan(events, out)
    _rule_suspicious_port(events, out)
    _rule_suspicious_dns(events, out)
    _rule_cross_source(events, out)
    _rule_pattern(
        events, out, 'SS-012', 'Log clearing / anti-forensics', 'High', ['T1070.001'], LOG_CLEAR_PATTERNS,
        "{n} event(s) by '{user}' clear or tamper with logs ({labels}). Attackers erase logs to hide what "
        "they did, so surrounding gaps in the timeline deserve attention.",
        "Pull logs from any central collector / backups for the missing period.")
    _rule_pattern(
        events, out, 'SS-014', 'Private key or credential store exposed', 'Medium', ['T1552.004'],
        [PRIVATE_KEY_PATTERN],
        "{n} artefact(s) associated with '{user}' are private keys or password vaults ({labels}).",
        "Determine whether the key was copied off the host; rotate it if so.", confidence='Medium')
    _rule_deleted_after_attack(events, out, list(out.items))

    detections = sorted(
        out.items,
        key=lambda d: (-SEVERITY_WEIGHT.get(d['severity'], 1), d['first_seen'] or ''),
    )

    # Risk score: diminishing sum so one Critical ≈ 30, many findings saturate at 100.
    raw = sum(RISK_POINTS.get(d['severity'], 0) for d in detections)
    risk_score = min(100, raw)
    risk_level = ('Critical' if risk_score >= 70 else 'High' if risk_score >= 40
                  else 'Medium' if risk_score >= 15 else 'Low' if risk_score > 0 else 'None')

    tactics = defaultdict(lambda: {'count': 0, 'techniques': set()})
    for d in detections:
        for m in d['mitre']:
            tactics[m['tactic']]['count'] += 1
            tactics[m['tactic']]['techniques'].add(f"{m['id']} {m['name']}")
    kill_chain = [
        {'tactic': t, 'count': tactics[t]['count'], 'techniques': sorted(tactics[t]['techniques'])}
        for t in TACTIC_ORDER
    ]

    # Entity risk ranking (users and IPs implicated by the most severe detections)
    entity_scores = defaultdict(int)
    for d in detections:
        for kind in ('users', 'ips'):
            for v in d['entities'].get(kind, []):
                entity_scores[(kind[:-1], v)] += RISK_POINTS.get(d['severity'], 0)
    top_entities = [
        {'type': k, 'value': v, 'score': min(100, s)}
        for (k, v), s in sorted(entity_scores.items(), key=lambda x: -x[1])[:8]
    ]

    sev_counts = defaultdict(int)
    for d in detections:
        sev_counts[d['severity']] += 1

    return {
        'detections': detections,
        'total': len(detections),
        'severity_counts': {s: sev_counts.get(s, 0) for s in ('Critical', 'High', 'Medium', 'Low')},
        'risk_score': risk_score,
        'risk_level': risk_level,
        'kill_chain': kill_chain,
        'top_entities': top_entities,
        'rules_evaluated': 14,
        'disclaimer': ('Detections are correlation-based investigative leads mapped to MITRE ATT&CK. '
                       'They require analyst validation and do not by themselves prove malicious activity.'),
    }
