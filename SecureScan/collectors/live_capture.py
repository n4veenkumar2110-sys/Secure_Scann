"""
SecureScan live network audit via Wireshark's TShark
===================================================

Captures real packets from a local network interface with TShark (the command-line
engine of Wireshark), saves the capture as a .pcapng evidence file and hands it to
the existing PCAP parser.

Safety rules:
  * The interface must be one that `tshark -D` itself reports (no free-form input).
  * Duration (5-120 s) and packet count (10-20000) are clamped.
  * TShark is called with a fixed argument list - never through a shell.
  * Capture needs the Npcap driver (installed with Wireshark). On most installs a
    normal user can capture; if Npcap was installed "admin-only", TShark reports
    a permission error which is passed back to the analyst.
"""

import re
import subprocess
from pathlib import Path

from collectors.wireshark_parser import find_tshark_path

MIN_DURATION, MAX_DURATION = 5, 120
MIN_PACKETS, MAX_PACKETS = 10, 20000

_IFACE_LINE = re.compile(r'^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$')


def list_interfaces(timeout=15):
    """Returns the capture interfaces TShark can see: [{'id','device','name'}]."""
    tshark = find_tshark_path()
    if not tshark:
        return []
    try:
        proc = subprocess.run([tshark, '-D'], capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return []
    interfaces = []
    for line in proc.stdout.splitlines():
        m = _IFACE_LINE.match(line)
        if not m:
            continue
        idx, device, name = m.group(1), m.group(2), (m.group(3) or m.group(2))
        # ETW / extcap pseudo-interfaces are not packet sources
        if device.lower() in ('etwdump', 'ciscodump', 'randpkt', 'sshdump', 'udpdump', 'wifidump'):
            continue
        interfaces.append({'id': idx, 'device': device, 'name': name})
    return interfaces


def capture_packets(interface_id, duration, max_packets, output_path, capture_filter=''):
    """
    Runs a bounded live capture and writes it to `output_path` (.pcapng).
    Returns a dict describing the capture. Raises ValueError / RuntimeError.
    """
    tshark = find_tshark_path()
    if not tshark:
        raise RuntimeError('TShark not found. Install Wireshark with the TShark and Npcap components.')

    valid = {i['id']: i for i in list_interfaces()}
    iface = valid.get(str(interface_id))
    if not iface:
        raise ValueError(f'Unknown capture interface "{interface_id}". Choose one listed by TShark.')

    duration = max(MIN_DURATION, min(MAX_DURATION, int(duration)))
    max_packets = max(MIN_PACKETS, min(MAX_PACKETS, int(max_packets)))

    cmd = [tshark, '-i', iface['id'], '-a', f'duration:{duration}', '-c', str(max_packets),
           '-w', str(Path(output_path).resolve()), '-q']
    if capture_filter:
        # BPF capture filters are a small expression language; allow only its character set.
        if not re.fullmatch(r"[A-Za-z0-9 .:/()!&|<>=\-]{1,200}", capture_filter):
            raise ValueError('Capture filter contains unsupported characters.')
        cmd += ['-f', capture_filter]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError('TShark capture did not stop in time.')

    out = Path(output_path)
    if proc.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        err = ' | '.join(l for l in proc.stderr.splitlines() if l.strip() and 'Capturing on' not in l)
        raise RuntimeError(f'TShark capture failed: {err or "exit code " + str(proc.returncode)}')

    m = re.search(r'(\d+)\s+packets? captured', proc.stderr)
    return {
        'interface': iface['name'],
        'interface_id': iface['id'],
        'duration_seconds': duration,
        'max_packets': max_packets,
        'packets_captured': int(m.group(1)) if m else None,
        'filter': capture_filter or None,
    }
