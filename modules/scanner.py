"""
scanner.py - AP Scanner Module
Based on Lecture 7 (Ch.11): Wardriving, Network Stumbler concepts.
Uses 'netsh wlan show networks mode=bssid' on Windows.
"""

import subprocess
import re
import json
import os


def load_default_ssids():
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'default_ssids.json')
    with open(data_path, 'r') as f:
        data = json.load(f)
    return [s.lower() for s in data['default_ssids']]


def parse_netsh_output(raw: str) -> list[dict]:
    """
    Parse 'netsh wlan show networks mode=bssid' output into a list of AP dicts.
    Each dict: ssid, bssid, signal, channel, security, encryption, radio_type
    """
    networks = []
    blocks = re.split(r'\nSSID\s+\d+\s*:', raw)

    for block in blocks[1:]:
        ap = {}
        ssid_match = re.match(r'\s*(.+)', block)
        ap['ssid'] = ssid_match.group(1).strip() if ssid_match else 'Unknown'

        bssid_match = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]+)', block)
        ap['bssid'] = bssid_match.group(1).strip() if bssid_match else 'N/A'

        signal_match = re.search(r'Signal\s*:\s*(\d+)%', block)
        ap['signal'] = int(signal_match.group(1)) if signal_match else 0

        channel_match = re.search(r'Channel\s*:\s*(\d+)', block)
        ap['channel'] = int(channel_match.group(1)) if channel_match else 0

        auth_match = re.search(r'Authentication\s*:\s*(.+)', block)
        ap['security'] = auth_match.group(1).strip() if auth_match else 'Unknown'

        enc_match = re.search(r'Encryption\s*:\s*(.+)', block)
        ap['encryption'] = enc_match.group(1).strip() if enc_match else 'Unknown'

        radio_match = re.search(r'Radio type\s*:\s*(.+)', block)
        ap['radio_type'] = radio_match.group(1).strip() if radio_match else 'Unknown'

        networks.append(ap)

    return networks


def scan_networks() -> list[dict]:
    """Run netsh scan and return parsed network list with risk flags."""
    default_ssids = load_default_ssids()

    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        return [{'error': str(e)}]

    networks = parse_netsh_output(raw)

    # Enrich each network with flags + vendor lookup
    from modules.oui_lookup import lookup_vendor
    for ap in networks:
        ssid_lower = ap.get('ssid', '').lower()
        ap['is_default_ssid'] = ssid_lower in default_ssids
        ap['encryption_risk'] = classify_encryption(ap.get('security', ''), ap.get('encryption', ''))
        ap['signal_bars'] = signal_to_bars(ap.get('signal', 0))
        ap['vendor'] = lookup_vendor(ap.get('bssid', ''))

    return networks


def classify_encryption(auth: str, enc: str) -> str:
    """
    From Lecture 7:
    - WEP = CRITICAL (RC4, crackable)
    - TKIP = MEDIUM (still uses RC4 but with per-packet mixing)
    - WPA2 + CCMP/AES = SAFE
    - Open = CRITICAL
    """
    combined = (auth + enc).upper()
    if 'WEP' in combined:
        return 'CRITICAL'
    elif 'TKIP' in combined:
        return 'MEDIUM'
    elif 'CCMP' in combined or 'AES' in combined:
        return 'SAFE'
    elif 'WPA2' in combined:
        return 'SAFE'
    elif 'WPA' in combined:
        return 'MEDIUM'
    elif 'OPEN' in combined or 'NONE' in combined:
        return 'CRITICAL'
    return 'UNKNOWN'


def signal_to_bars(signal: int) -> str:
    if signal >= 80:
        return '████'
    elif signal >= 60:
        return '███░'
    elif signal >= 40:
        return '██░░'
    elif signal >= 20:
        return '█░░░'
    return '░░░░'
