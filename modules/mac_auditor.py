"""
mac_auditor.py - MAC Address Whitelist Advisor
Based on Lecture 7 (Ch.11) Countermeasures slide (page 95):
  "Allow only predetermined MAC addresses and IP addresses to have access to the wireless LAN"
  Note from lecture: "A sophisticated attacker can still spoof a MAC address,
  so this should be a secondary layer of defense."
"""

import subprocess
import re
import json
import os


WHITELIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'mac_whitelist.json')


def get_connected_devices() -> list:
    """
    Get ARP table to find devices currently on the local network.
    Uses 'arp -a' on Windows.
    Returns list of dicts: ip, mac, type
    Only returns real dynamic devices (filters out multicast/broadcast/static entries).
    """
    devices = []
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.split('\n')
        for line in lines:
            match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w-]{17})\s+(\w+)',
                line
            )
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                entry_type = match.group(3)

                # Skip broadcast addresses (x.x.x.255)
                if ip.endswith('.255'):
                    continue
                # Skip multicast IP ranges (224.x.x.x - 239.x.x.x)
                first_octet = int(ip.split('.')[0])
                if 224 <= first_octet <= 239:
                    continue
                # Skip broadcast and multicast MACs
                if mac.startswith('FF') or mac.startswith('01:00:5E'):
                    continue
                # Skip static entries (multicast/system entries are always static)
                if entry_type.lower() == 'static':
                    continue

                devices.append({'ip': ip, 'mac': mac, 'type': entry_type})

    except Exception as e:
        devices.append({'error': str(e)})
    return devices


def load_whitelist() -> list:
    """Load MAC whitelist from file."""
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            data = json.load(f)
            return [m.upper() for m in data.get('whitelist', [])]
    return []


def save_whitelist(macs: list):
    """Save MAC whitelist to file."""
    os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
    with open(WHITELIST_FILE, 'w') as f:
        json.dump({'whitelist': [m.upper() for m in macs]}, f, indent=2)


def audit_mac_addresses() -> dict:
    """
    Main audit function:
    - Get all real devices on the network (ARP table, dynamic only)
    - Compare against whitelist
    - Flag unknown/unauthorized devices
    Returns audit result dict.
    """
    devices = get_connected_devices()
    whitelist = load_whitelist()

    authorized = []
    unauthorized = []
    unknown_status = []

    for device in devices:
        if 'error' in device:
            continue
        mac = device['mac']
        if not whitelist:
            device['status'] = 'NO_WHITELIST'
            unknown_status.append(device)
        elif mac in whitelist:
            device['status'] = 'AUTHORIZED'
            authorized.append(device)
        else:
            device['status'] = 'UNAUTHORIZED'
            unauthorized.append(device)

    return {
        'authorized': authorized,
        'unauthorized': unauthorized,
        'unknown_status': unknown_status,
        'whitelist_defined': len(whitelist) > 0,
        'total_devices': len(devices),
        'lecture_note': (
            "Lecture 7 Countermeasures: Allow only predetermined MAC addresses to access the WLAN. "
            "CAUTION: A sophisticated attacker can still spoof a MAC address (as noted in the lecture), "
            "so MAC filtering is a secondary defense layer, not a primary one."
        )
    }
