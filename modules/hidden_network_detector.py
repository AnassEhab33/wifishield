"""
hidden_network_detector.py - Hidden Network (Cloaked SSID) Detector
Based on Lecture 7 (Ch.11):
  - "An AP can be configured to not broadcast its SSID until after authentication"
  - "Wireless hackers can attempt to GUESS the SSID"
  - Disabling SSID broadcast forces attackers to use active tools like Kismet
    rather than passive scanners like NetStumbler
"""

import subprocess
import re


def detect_hidden_networks() -> dict:
    """
    Detect hidden/cloaked networks via two methods:
    1. Parse netsh for entries with empty/blank SSID (hidden SSIDs show as empty)
    2. Check 'netsh wlan show all' for more detailed probe data
    Returns dict with findings.
    """
    hidden = []
    visible = []
    raw_text = ""

    try:
        # Method 1: Standard scan - hidden APs appear with empty SSID
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=15
        )
        raw_text = result.stdout
        _parse_for_hidden(raw_text, hidden, visible)

        # Method 2: Extended scan with 'show all'
        result2 = subprocess.run(
            ['netsh', 'wlan', 'show', 'all'],
            capture_output=True, text=True, timeout=15
        )
        _parse_show_all(result2.stdout, hidden)

    except Exception as e:
        return {
            'hidden': [],
            'visible_count': 0,
            'error': str(e),
            'lecture_note': _lecture_note()
        }

    # Deduplicate hidden by BSSID
    seen_bssids = set()
    unique_hidden = []
    for h in hidden:
        bssid = h.get('bssid', '')
        if bssid and bssid not in seen_bssids:
            seen_bssids.add(bssid)
            unique_hidden.append(h)

    return {
        'hidden': unique_hidden,
        'visible_count': len(visible),
        'total_detected': len(unique_hidden),
        'risk': 'HIGH' if unique_hidden else 'NONE',
        'lecture_note': _lecture_note(),
        'attacker_note': (
            "From Lecture 7: An attacker uses active tools like Kismet to detect hidden networks "
            "by capturing probe-request/probe-response frames. "
            "NetStumbler (passive scanner) will MISS hidden networks, "
            "but Kismet (active) will detect them. "
            "A hidden SSID is NOT a security measure — it only stops passive scanners."
        ),
        'defense_note': (
            "Disabling SSID broadcast is a secondary measure only (Lecture 7, Figure 11-8). "
            "Always combine with WPA2-AES encryption and MAC filtering."
        )
    }


def _parse_for_hidden(raw: str, hidden: list, visible: list):
    """
    Parse netsh output. Hidden networks appear as SSIDs with no name or '<hidden>'.
    """
    blocks = re.split(r'SSID\s+\d+\s*:', raw)

    for block in blocks[1:]:
        # Get the SSID value (first line after the colon)
        ssid_line = block.split('\n')[0].strip() if block.strip() else ''

        # Get BSSID
        bssid_match = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]+)', block)
        bssid = bssid_match.group(1).strip() if bssid_match else 'N/A'

        # Get Signal
        signal_match = re.search(r'Signal\s*:\s*(\d+)%', block)
        signal = int(signal_match.group(1)) if signal_match else 0

        # Get Auth
        auth_match = re.search(r'Authentication\s*:\s*(.+)', block)
        auth = auth_match.group(1).strip() if auth_match else 'Unknown'

        # Get channel
        chan_match = re.search(r'Channel\s*:\s*(\d+)', block)
        channel = int(chan_match.group(1)) if chan_match else 0

        entry = {
            'ssid': ssid_line or '<Hidden>',
            'bssid': bssid,
            'signal': signal,
            'auth': auth,
            'channel': channel,
            'detection_method': 'netsh passive scan'
        }

        # Hidden = empty SSID, or literally blank
        if not ssid_line or ssid_line.lower() in ['', '<hidden>', 'hidden']:
            entry['ssid'] = '<Hidden Network>'
            hidden.append(entry)
        else:
            visible.append(entry)


def _parse_show_all(raw: str, hidden: list):
    """
    Parse 'netsh wlan show all' output for additional hidden network indicators.
    Looks for BSSIDs responding with empty SSID in probe responses.
    """
    # Hidden networks in 'show all' appear as entries with "SSID" showing blank
    lines = raw.split('\n')
    current_bssid = None
    i = 0
    while i < len(lines):
        line = lines[i]

        bssid_match = re.search(r'BSSID\s*:\s*([0-9a-fA-F:]{17})', line, re.IGNORECASE)
        if bssid_match:
            current_bssid = bssid_match.group(1).strip()

        # Check for hidden SSID indicators
        ssid_match = re.search(r'^\s*SSID\s*:\s*$', line)  # Empty SSID line
        if ssid_match and current_bssid:
            # Check if this BSSID is already in hidden list
            existing = [h for h in hidden if h.get('bssid') == current_bssid]
            if not existing:
                hidden.append({
                    'ssid': '<Hidden Network>',
                    'bssid': current_bssid,
                    'signal': 0,
                    'auth': 'Unknown',
                    'channel': 0,
                    'detection_method': 'netsh show all (empty SSID in probe response)'
                })
        i += 1


def _lecture_note() -> str:
    return (
        "Lecture 7 (Ch.11): 'An AP can be configured to NOT broadcast its SSID until after authentication.' "
        "Hidden networks do not appear in NetStumbler (passive scanner) but ARE detected by Kismet (active). "
        "Hiding SSID is a security-through-obscurity measure — NOT a replacement for encryption."
    )
