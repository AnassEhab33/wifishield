"""
hidden_network_detector.py - Hidden Network (Cloaked SSID) Detector

On Windows, hidden APs do NOT appear in 'netsh wlan show networks' at all.
They appear only in the BSS-level scan table inside 'netsh wlan show all',
where the SSID field is empty (beacon suppressed).

Approach:
  1. Collect all visible SSIDs from 'netsh wlan show networks mode=bssid'
  2. Parse ALL BSS entries from 'netsh wlan show all' (AP BSSID blocks)
  3. Any BSS entry whose SSID field is empty/blank = hidden AP
  4. Also check 'netsh wlan show profiles' for saved hidden-network profiles
"""

import subprocess
import re


def detect_hidden_networks() -> dict:
    hidden = []
    visible_bssids = set()
    errors = []

    try:
        # ── Step 1: Collect all visible BSSIDs from standard scan ──────────
        visible_bssids = _get_visible_bssids()

        # ── Step 2: Parse BSS table from 'netsh wlan show all' ─────────────
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'all'],
            capture_output=True, text=True, timeout=20
        )
        bss_entries = _parse_bss_table(result.stdout)

        # ── Step 3: Any BSS entry with empty/blank SSID = hidden ───────────
        for entry in bss_entries:
            ssid = entry.get('ssid', '').strip()
            bssid = entry.get('bssid', '')
            if not ssid:
                hidden.append({
                    'ssid': '<Hidden Network>',
                    'bssid': bssid,
                    'signal': entry.get('signal', 0),
                    'auth': entry.get('auth', 'Unknown'),
                    'channel': entry.get('channel', 0),
                    'detection_method': 'BSS scan cache (empty SSID beacon)'
                })

        # ── Step 4: Saved hidden profiles ──────────────────────────────────
        saved_hidden = _get_saved_hidden_profiles()
        for sh in saved_hidden:
            # Only add if not already in hidden list
            if not any(h.get('bssid') == sh.get('bssid') for h in hidden):
                hidden.append(sh)

    except Exception as e:
        errors.append(str(e))

    # Deduplicate by BSSID
    seen = set()
    unique_hidden = []
    for h in hidden:
        b = h.get('bssid', '').lower()
        if b and b not in seen:
            seen.add(b)
            unique_hidden.append(h)

    return {
        'hidden': unique_hidden,
        'visible_count': len(visible_bssids),
        'total_detected': len(unique_hidden),
        'risk': 'HIGH' if unique_hidden else 'NONE',
        'errors': errors,
        'note': (
            "Hidden networks suppress their SSID beacon. "
            "Detected by scanning for BSS entries with an empty SSID field. "
            "A hidden SSID is NOT a security measure — the BSSID is still visible."
        ),
        'attacker_note': (
            "An attacker can detect hidden networks by capturing probe-request and "
            "probe-response frames using active tools. "
            "A hidden SSID only stops passive scanners, not active reconnaissance."
        ),
        'defense_note': (
            "Hiding the SSID is a secondary measure. "
            "Always combine with WPA2-AES encryption and MAC filtering."
        ),
        # Keep these for backward compat with templates
        'lecture_note': (
            "Hidden networks suppress their SSID beacon. "
            "Detected via BSS-level scan cache (empty SSID field in beacon frame)."
        ),
    }


def _get_visible_bssids() -> set:
    """Return set of all BSSIDs visible in standard netsh scan."""
    bssids = set()
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=15
        )
        for match in re.finditer(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', result.stdout):
            bssids.add(match.group(1).lower())
    except Exception:
        pass
    return bssids


def _parse_bss_table(raw: str) -> list:
    """
    Parse the BSS/AP entries from 'netsh wlan show all'.
    Each AP block starts with 'SSID' and contains 'AP BSSID'.
    Returns list of dicts with bssid, ssid, signal, channel, auth.
    """
    entries = []

    # Split on the BSS SSID header pattern: "    SSID                   : ..."
    # This pattern appears in the per-AP capability sections
    blocks = re.split(r'\n(?=\s{4}SSID\s+:)', raw)

    for block in blocks:
        # Check for AP BSSID (this is the BSS table section)
        bssid_match = re.search(r'AP BSSID\s*:\s*([0-9a-fA-F:]{17})', block)
        if not bssid_match:
            continue

        bssid = bssid_match.group(1).strip()

        # Extract SSID (the value right after "SSID :")
        ssid_match = re.search(r'SSID\s{2,}:\s*(.*?)(?:\r?\n|$)', block)
        ssid = ssid_match.group(1).strip() if ssid_match else ''

        # Signal
        signal_match = re.search(r'Signal\s*:\s*(\d+)%', block)
        signal = int(signal_match.group(1)) if signal_match else 0

        # Channel
        chan_match = re.search(r'Channel\s*:\s*(\d+)', block)
        channel = int(chan_match.group(1)) if chan_match else 0

        # Auth
        auth_match = re.search(r'Authentication\s*:\s*(.+)', block)
        auth = auth_match.group(1).strip() if auth_match else 'Unknown'

        entries.append({
            'bssid': bssid,
            'ssid': ssid,
            'signal': signal,
            'channel': channel,
            'auth': auth,
        })

    return entries


def _get_saved_hidden_profiles() -> list:
    """
    Check saved WiFi profiles for networks marked as 'non-broadcast' (hidden).
    Returns list of hidden saved profiles.
    """
    hidden_profiles = []
    try:
        # List all saved profiles
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'profiles'],
            capture_output=True, text=True, timeout=10
        )
        # Extract profile names
        profile_names = re.findall(r'All User Profile\s*:\s*(.+)', result.stdout)

        for name in profile_names:
            name = name.strip()
            # Get profile details
            detail = subprocess.run(
                ['netsh', 'wlan', 'show', 'profile', f'name={name}'],
                capture_output=True, text=True, timeout=10
            )
            # Check if profile is set as non-broadcast (hidden)
            if re.search(r'Non[- ]broadcast\s*:\s*Yes', detail.stdout, re.IGNORECASE):
                hidden_profiles.append({
                    'ssid': name,
                    'bssid': 'N/A (saved profile)',
                    'signal': 0,
                    'auth': 'Saved Profile',
                    'channel': 0,
                    'detection_method': f'Saved hidden profile: "{name}"'
                })
    except Exception:
        pass

    return hidden_profiles
