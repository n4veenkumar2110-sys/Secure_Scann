"""
Root backwards-compatibility wrapper for Wireshark parsing.
Delegates to collectors/wireshark_parser.py.
"""

from collectors.wireshark_parser import (
    parse_wireshark_csv_text,
    parse_pcap_file,
    find_tshark_path,
    get_tshark_info,
    normalize_network_event
)

__all__ = [
    'parse_wireshark_csv_text',
    'parse_pcap_file',
    'find_tshark_path',
    'get_tshark_info',
    'normalize_network_event'
]
