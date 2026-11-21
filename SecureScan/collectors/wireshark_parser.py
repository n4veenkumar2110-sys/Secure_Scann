"""
SecureScan Wireshark & TShark Network Traffic Parser
====================================================
Parses Wireshark CSV exports and PCAP/PCAPNG capture files (via TShark).
Normalises network observations into the SecureScan events schema.

Supports:
  - Standard Wireshark CSV exports (with all common column variations)
  - Raw .pcap and .pcapng captures (via TShark field extraction)
  - IPv4 and IPv6 addresses
  - TCP, UDP, DNS, TLS, HTTP, SMB, ICMP, and related protocols
  - Port, packet length, TCP flag, and DNS query extraction
  - Transparent network observation rules (without premature malicious accusations)
  - Deterministic duplicate prevention
"""

import os
import csv
import io
import re
import json
import shutil
import hashlib
import datetime
import subprocess
from pathlib import Path


# Standard and common ports dictionary for context
_STANDARD_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    88: 'Kerberos', 110: 'POP3', 123: 'NTP', 135: 'MS-RPC',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    587: 'SMTP-Submission', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MS-SQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
}

# Ports frequently noted in security assessments or unusual egress
_UNUSUAL_PORTS = {
    4444: 'Common reverse shell listener (Metasploit default)',
    1337: 'Non-standard port commonly used in testing/challenges',
    31337: 'Historical Back Orifice / remote admin port',
    6667: 'IRC (historically used for botnet C2)',
    6697: 'IRC over TLS',
    9001: 'Tor default relay / alternate web control',
    9050: 'Tor SOCKS proxy',
    8888: 'Alternate HTTP listener / staging server'
}


def find_tshark_path():
    """
    Locates the tshark.exe binary on the system without guessing.
    Checks PATH and standard Wireshark installation directories on Windows.
    """
    # 1. Check PATH
    which_path = shutil.which('tshark')
    if which_path and os.path.isfile(which_path):
        return str(Path(which_path).resolve())

    # 2. Check standard Windows program file locations
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%ProgramFiles%\Wireshark\tshark.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Wireshark\tshark.exe"),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return str(Path(c).resolve())

    return None


def get_tshark_info():
    """
    Returns installation status and version details of TShark.
    """
    path = find_tshark_path()
    if not path:
        return {
            'available': False,
            'path': None,
            'version': None,
            'install_guide': (
                "TShark was not found in standard paths. To enable direct PCAP/PCAPNG "
                "processing, download Wireshark from https://www.wireshark.org and ensure "
                "the 'TShark' and 'Npcap' components are selected during installation."
            )
        }

    version_str = "Installed"
    try:
        proc = subprocess.run(
            [path, "-v"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        first_line = proc.stdout.splitlines()
        if first_line:
            version_str = first_line[0].strip()
        elif proc.stderr:
            for l in proc.stderr.splitlines():
                if 'TShark' in l:
                    version_str = l.strip()
                    break
    except Exception as e:
        version_str = f"Installed (version check note: {str(e)})"

    return {
        'available': True,
        'path': path,
        'version': version_str,
        'install_guide': "TShark is installed and available for packet processing."
    }


def normalize_col(name):
    """Normalises column header by lowercasing and stripping non-alphanumeric characters."""
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


def pick_value(row_dict, candidate_names):
    """Picks the first non-empty value matching any normalized candidate name."""
    norm_map = {normalize_col(k): v for k, v in row_dict.items() if v is not None}
    for candidate in candidate_names:
        norm_key = normalize_col(candidate)
        if norm_key in norm_map:
            val = str(norm_map[norm_key]).strip()
            if val and val != '-':
                return val
    return ''


def parse_wireshark_time(time_str):
    """
    Normalises various Wireshark timestamp formats into ISO 8601 UTC.
    Handles Unix epoch floats, standard datetimes, and ISO strings.
    """
    if not time_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    clean_str = str(time_str).strip().strip('"')

    # 1. Unix epoch float (e.g. 1716042121.123456)
    if re.match(r'^\d{9,11}(\.\d+)?$', clean_str):
        try:
            num = float(clean_str)
            dt = datetime.datetime.fromtimestamp(num, tz=datetime.timezone.utc)
            return dt.isoformat()
        except Exception:
            pass

    # 2. Standard timestamp formats
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%SZ',
        '%b %d, %Y %H:%M:%S',
        '%b %d, %Y %H:%M:%S.%f',
        '%d/%m/%Y %H:%M:%S',
        '%m/%d/%Y %H:%M:%S',
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except Exception:
            continue

    # 3. ISO format with timezone
    try:
        return datetime.datetime.fromisoformat(clean_str.replace('Z', '+00:00')).isoformat()
    except Exception:
        pass

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def extract_packet_details(info, proto_hint='', src_port_col='', dst_port_col='', dns_col='', flags_col=''):
    """
    Extracts structured fields (source/dest ports, DNS query, TCP flags)
    from explicit columns or the Wireshark Info column string.
    """
    src_port = src_port_col or ''
    dst_port = dst_port_col or ''
    dns_query = dns_col or ''
    tcp_flags = flags_col or ''

    # 1. Port extraction from Info column if missing (e.g. "54321 → 8080 [SYN]")
    if (not src_port or not dst_port) and info:
        port_arrow_match = re.search(r'\b(\d{1,5})\s*(?:→|->)\s*(\d{1,5})\b', info)
        if port_arrow_match:
            if not src_port:
                src_port = port_arrow_match.group(1)
            if not dst_port:
                dst_port = port_arrow_match.group(2)

    # 2. TCP flags extraction if missing (e.g. "[SYN]", "[SYN, ACK]", "[FIN, ACK]")
    if not tcp_flags and info:
        flag_match = re.search(r'\[([A-Z,\s]+)\]', info)
        if flag_match:
            cand = flag_match.group(1).strip()
            if any(f in cand for f in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']):
                tcp_flags = f"[{cand}]"

    # 3. DNS query extraction if missing (e.g. "Standard query 0x1a2b A lab-service.internal")
    if not dns_query and info:
        # Match standard DNS queries
        dns_match = re.search(
            r'Standard query\s+(?:response\s+)?(?:0x[0-9a-fA-F]+\s+)?(?:[A-Z0-9]+\s+)?([a-zA-Z0-9_\-\.]+)',
            info,
            re.IGNORECASE
        )
        if dns_match:
            cand = dns_match.group(1).strip()
            if '.' in cand and not cand.startswith('0x'):
                dns_query = cand

    return src_port, dst_port, dns_query, tcp_flags


def generate_wireshark_event_id(source, event_time, src_ip, dst_ip, src_port, dst_port, protocol, length, info, ref_id):
    """
    Generates a deterministic hash-based ID to prevent duplicate packet imports.
    """
    key = f"{source}|{event_time}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{protocol}|{length}|{info[:60]}|{ref_id}"
    digest = hashlib.sha256(key.encode('utf-8', errors='replace')).hexdigest()[:16]
    return f"wireshark-{digest}"


def build_network_observation(protocol, src_ip, dst_ip, src_port, dst_port, dns_query, tcp_flags, length, info):
    """
    Builds transparent network observations with educational explanations.
    Guiding Principle: Explain observations clearly without making unfounded accusations of maliciousness.
    """
    proto_upper = (protocol or 'IP').upper()
    severity = 'Informational'
    title = f"{proto_upper} packet: {src_ip or 'unknown'} → {dst_ip or 'unknown'}"
    rule_reasons = []

    # Parse port numbers if integer-compatible
    dst_port_int = None
    if dst_port and dst_port.isdigit():
        dst_port_int = int(dst_port)

    # 1. Unusual Port Observation
    if dst_port_int and dst_port_int in _UNUSUAL_PORTS:
        severity = 'Medium'
        desc = _UNUSUAL_PORTS[dst_port_int]
        title = f"Unusual destination port {dst_port_int} observed ({proto_upper})"
        rule_reasons.append(
            f"Observation: Destination port {dst_port_int} ({desc}) detected. "
            f"This port is non-standard for routine workstation egress and warrants validation "
            f"of the associated local process."
        )
    elif dst_port_int and dst_port_int > 1024 and dst_port_int not in _STANDARD_PORTS and proto_upper in ('TCP', 'UDP'):
        # High non-standard port
        if proto_upper == 'TCP' and '[SYN]' in tcp_flags and '[ACK]' not in tcp_flags:
            severity = 'Low'
            title = f"TCP SYN to high port {dst_port_int}"
            rule_reasons.append(
                f"Observation: TCP handshake initiation to unassigned high port {dst_port_int}. "
                f"May represent a custom internal application, peer-to-peer communication, or scanning."
            )

    # 2. DNS Query Observation
    if proto_upper == 'DNS' or dns_query:
        if not rule_reasons:
            title = f"DNS query: '{dns_query}'" if dns_query else f"DNS packet ({src_ip} → {dst_ip})"
        # Check for dynamic DNS / tunnelling services
        suspicious_ddns = ['ngrok', 'duckdns', 'pastebin', 'transfer.sh', 'dynamic-dns']
        if dns_query and any(s in dns_query.lower() for s in suspicious_ddns):
            severity = 'Medium'
            title = f"DNS query to dynamic/tunnelling service: '{dns_query}'"
            rule_reasons.append(
                f"Observation: DNS resolution request for domain '{dns_query}'. "
                f"Domains utilizing dynamic DNS or tunnelling services are frequently used for external testing or proxies; "
                f"verify if this activity was authorized."
            )
        elif not rule_reasons:
            rule_reasons.append(
                f"Observation: Standard DNS name resolution request observed for '{dns_query or 'host'}'. "
                f"DNS traffic correlates host activity with remote destinations."
            )

    # 3. Lateral Movement Protocols (SMB, RPC, RDP)
    elif any(p in proto_upper for p in ['SMB', 'SMB2', 'RPC', 'RPC_NETLOGON']):
        severity = 'Medium'
        title = f"Internal administrative protocol observed: {proto_upper}"
        rule_reasons.append(
            f"Observation: {proto_upper} protocol exchange recorded. This protocol provides internal file sharing "
            f"and Windows RPC management. While normal in Windows domain environments, unexpected lateral sessions "
            f"should be reviewed."
        )

    # 4. TCP SYN Handshake (Initial Connection)
    elif 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
        if severity == 'Informational':
            severity = 'Low'
        if not rule_reasons:
            title = f"TCP SYN connection initiation to {dst_ip}:{dst_port or 'port'}"
            rule_reasons.append(
                f"Observation: Outbound TCP SYN packet observed. Indicates the start of a network connection. "
                f"Check whether a corresponding SYN-ACK response was received to confirm connection establishment."
            )

    # 5. TCP RST (Connection Termination or Closed Port)
    elif 'RST' in tcp_flags:
        if severity == 'Informational':
            severity = 'Low'
        title = f"TCP RST (Connection Reset) on port {dst_port or 'port'}"
        rule_reasons.append(
            f"Observation: TCP connection reset ([RST]) observed. Can indicate a refused connection, a closed port, "
            f"or active session termination."
        )

    # 6. TLS / HTTPS Encrypted Session
    elif proto_upper in ('TLS', 'SSL', 'HTTPS'):
        if not rule_reasons:
            title = f"Encrypted TLS session ({src_ip} → {dst_ip})"
            rule_reasons.append(
                f"Observation: Encrypted transport layer security session. Payload contents are ciphertext "
                f"and protected in transit."
            )

    # General explanation note if none applied
    if not rule_reasons:
        rule_reasons.append(
            f"Observation: Packet recorded from capture export ({proto_upper}). "
            f"Observation is an investigative lead; does not confirm malicious activity."
        )

    return title, severity, " ".join(rule_reasons)


def normalize_network_event(item, index=0, source_fn="capture", capture_hash=""):
    """
    Normalises a network packet record into the SecureScan unified schema.
    """
    raw_time = (
        pick_value(item, ['frame.time_epoch', 'time_epoch', 'Time', 'Time Displayed', 'frame.time', 'Timestamp', 'Date'])
    )
    event_time = parse_wireshark_time(raw_time)

    # IP resolution (support IPv4 and IPv6)
    src_ip = pick_value(item, ['Source', 'Source IP', 'ip.src', 'ipv6.src', 'src', 'ip_src', 'ipv6_src'])
    dst_ip = pick_value(item, ['Destination', 'Destination IP', 'ip.dst', 'ipv6.dst', 'dst', 'ip_dst', 'ipv6_dst'])

    # Protocols
    proto_raw = pick_value(item, ['Protocol', 'frame.protocols', 'proto', '_ws.col.protocol', 'col_proto'])
    # If protocols string is layered (e.g. "eth:ethertype:ip:tcp:tls"), take the most specific protocol
    protocol = 'IP'
    if proto_raw:
        if ':' in proto_raw:
            parts = [p.upper() for p in proto_raw.split(':') if p.lower() not in ('eth', 'ethertype', 'frame')]
            protocol = parts[-1] if parts else 'IP'
        else:
            protocol = proto_raw.upper()

    # Packet length
    length = pick_value(item, ['Length', 'Packet Length', 'frame.len', 'len', 'bytes'])

    # Info column
    info = pick_value(item, ['Info', 'Packet Info', 'Description', 'summary', 'details', '_ws.col.info', 'col_info'])

    # Ports, DNS, and Flags (from dedicated fields or Info)
    src_port_col = pick_value(item, ['Source Port', 'src port', 'sport', 'tcp.srcport', 'udp.srcport'])
    dst_port_col = pick_value(item, ['Destination Port', 'dst port', 'dport', 'tcp.dstport', 'udp.dstport'])
    dns_col = pick_value(item, ['DNS Query', 'dns query', 'dns.qry.name', 'query name', 'query'])
    flags_col = pick_value(item, ['TCP Flags', 'tcp flags', 'tcp.flags', 'flags'])

    src_port, dst_port, dns_query, tcp_flags = extract_packet_details(
        info, protocol, src_port_col, dst_port_col, dns_col, flags_col
    )

    # Observation rule processing
    title, severity, rule_reason = build_network_observation(
        protocol, src_ip, dst_ip, src_port, dst_port, dns_query, tcp_flags, length, info
    )

    # Build structured details string
    details_parts = []
    if rule_reason:
        details_parts.append(rule_reason)
    if src_port or dst_port:
        port_desc = f"Ports: {src_port or '?'}" + (f" → {dst_port}" if dst_port else "")
        details_parts.append(port_desc)
    if dns_query:
        details_parts.append(f"DNS Query: {dns_query}")
    if tcp_flags:
        details_parts.append(f"TCP Flags: {tcp_flags}")
    if length:
        details_parts.append(f"Length: {length} bytes")
    if info and info != title:
        details_parts.append(f"Info: {info}")
    if source_fn:
        details_parts.append(f"File: {source_fn}")

    details_text = " | ".join(details_parts) if details_parts else "Network packet observation."

    # Evidence reference
    rec_num = pick_value(item, ['No.', 'number', 'frame.number']) or str(index + 1)
    evidence_ref = f"WIRESHARK-{rec_num.zfill(4)}"

    # Deterministic event ID for duplicate prevention
    deterministic_id = generate_wireshark_event_id(
        "Wireshark", event_time, src_ip, dst_ip, src_port, dst_port, protocol, length, info, rec_num
    )

    # Raw payload payload dictionary for forensics
    payload_data = {
        'source_file': source_fn,
        'capture_hash': capture_hash,
        'src_port': src_port,
        'dst_port': dst_port,
        'dns_query': dns_query,
        'tcp_flags': tcp_flags,
        'length': length,
        'info': info
    }

    return {
        'id': deterministic_id,
        'event_time': event_time,
        'source': 'Wireshark',
        'category': 'Network',
        'severity': severity,
        'title': title,
        'username': '',
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'protocol': protocol,
        'command': f"{src_port} → {dst_port}" if (src_port and dst_port) else (dns_query or ''),
        'details': details_text[:1400],
        'evidence_reference': evidence_ref,
        'is_demo': 0,
        'imported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'raw_payload': json.dumps(payload_data)[:1000]
    }


def parse_wireshark_csv_text(csv_text, import_ref_prefix="WIRESHARK", filename="wireshark.csv", capture_hash=""):
    """
    Parses Wireshark CSV export text.
    Returns: (records, successful_count, failed_count)
    """
    clean_text = csv_text.lstrip('\ufeff').strip()
    if not clean_text:
        return [], 0, 0

    reader = csv.DictReader(io.StringIO(clean_text))
    if not reader.fieldnames:
        return [], 0, 0

    records = []
    successful = 0
    failed = 0

    for idx, row in enumerate(reader):
        # Validate that row has at least an IP or protocol or info
        src = pick_value(row, ['Source', 'Source IP', 'ip.src', 'ipv6.src', 'src'])
        dst = pick_value(row, ['Destination', 'Destination IP', 'ip.dst', 'ipv6.dst', 'dst'])
        proto = pick_value(row, ['Protocol', 'frame.protocols', 'proto'])
        info = pick_value(row, ['Info', 'Packet Info', 'description', 'summary'])

        if not src and not dst and not proto and not info:
            failed += 1
            continue

        try:
            rec = normalize_network_event(row, idx, source_fn=filename, capture_hash=capture_hash)
            records.append(rec)
            successful += 1
        except Exception:
            failed += 1

    return records, successful, failed


def parse_pcap_file(file_path, import_ref_prefix="PCAP", capture_hash="", timeout=30):
    """
    Processes a raw .pcap or .pcapng file using TShark with strict security rules:
      - Uses fixed arguments list (NO shell=True)
      - Captures stdout using tab delimiter
      - Enforces processing timeout (default 30 seconds)
      - Safe handling of packets with missing fields
    Returns: (records, successful_count, failed_count)
    """
    tshark_path = find_tshark_path()
    if not tshark_path:
        raise FileNotFoundError(
            "TShark executable not found. Please install Wireshark with TShark component "
            "from https://www.wireshark.org or upload exported CSV files."
        )

    resolved_path = str(Path(file_path).resolve())
    if not os.path.isfile(resolved_path):
        raise FileNotFoundError(f"Capture file not found: {file_path}")

    # Build TShark field extraction command
    cmd = [
        tshark_path,
        "-r", resolved_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "dns.qry.name",
        "-e", "tcp.flags",
        "-e", "_ws.col.Info"
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"TShark processing timed out after {timeout} seconds. The capture file may be too large.")
    except Exception as e:
        raise RuntimeError(f"Failed to execute TShark: {str(e)}")

    if proc.returncode != 0 and not proc.stdout.strip():
        # Clean up permission or config warnings from error message
        err_lines = [l for l in proc.stderr.splitlines() if 'permission to read' not in l.lower()]
        err_msg = " | ".join(err_lines) if err_lines else f"TShark exited with code {proc.returncode}"
        raise RuntimeError(f"TShark processing failed: {err_msg}")

    tsv_output = proc.stdout
    if not tsv_output.strip():
        return [], 0, 0

    reader = csv.DictReader(io.StringIO(tsv_output), delimiter='\t')
    if not reader.fieldnames:
        return [], 0, 0

    filename = Path(file_path).name
    records = []
    successful = 0
    failed = 0

    for idx, row in enumerate(reader):
        src = row.get('ip.src') or row.get('ipv6.src') or ''
        dst = row.get('ip.dst') or row.get('ipv6.dst') or ''
        proto = row.get('frame.protocols') or ''
        info = row.get('_ws.col.Info') or ''

        if not src and not dst and not proto and not info:
            failed += 1
            continue

        try:
            rec = normalize_network_event(row, idx, source_fn=filename, capture_hash=capture_hash)
            records.append(rec)
            successful += 1
        except Exception:
            failed += 1

    return records, successful, failed
