"""
wps_detector.py - WPS Vulnerability Detector
Based on Lecture 7 (Ch.11):
  - "Attacking WPS" section (page 75)
  - Reaver tool brute-forces WPS PIN (cracked in ~70,000 seconds)
  - WPS PIN: '33194028', WPA PSK recovered automatically
  - WPS-enabled APs are HIGH RISK even if WPA2 password is strong
"""

import subprocess
import re


def detect_wps(networks: list[dict]) -> list[dict]:
    """
    Attempt to detect WPS status for each network.
    Uses 'netsh wlan show networks mode=bssid' extended info.
    On Windows, WPS info is limited — we flag based on available data
    and provide the warning from the lecture.
    """
    # Try to get more detail via netsh interface show
    wps_capable_bssids = _get_wps_capable_bssids()

    for ap in networks:
        bssid = ap.get('bssid', '').lower()
        wps_detected = bssid in wps_capable_bssids

        ap['wps_enabled'] = wps_detected
        ap['wps_score_deduction'] = -15 if wps_detected else 0

        if wps_detected:
            ap['wps_issue'] = (
                "WPS (Wi-Fi Protected Setup) is enabled on this AP. "
                "Lecture 7 demonstrates the Reaver tool cracking WPS PINs "
                "in approximately 70,000 seconds (~19 hours), recovering the full WPA-PSK password. "
                "WPS PIN brute-force (Pixie Dust attack) can be much faster on vulnerable routers."
            )
            ap['wps_advice'] = (
                "Disable WPS immediately in your router's advanced wireless settings. "
                "WPS provides no security benefit that outweighs its vulnerability risk."
            )
        else:
            ap['wps_issue'] = None
            ap['wps_advice'] = (
                "WPS status not confirmed via passive scan. "
                "Log into your router admin panel and verify WPS is disabled "
                "(especially if using D-Link, Belkin, or Netgear — common targets from Lecture 7)."
            )

    return networks


def _get_wps_capable_bssids() -> set:
    """
    On Windows, query 'netsh wlan show networks mode=bssid' for WPS indicators.
    Returns a set of BSSIDs that appear to support WPS.
    Note: Windows netsh has limited WPS visibility — this is a best-effort check.
    """
    wps_bssids = set()
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, timeout=10
        )
        # Look for WPS-related flags in output
        lines = result.stdout.lower().split('\n')
        current_bssid = None
        for line in lines:
            bssid_match = re.search(r'bssid\s+\d+\s*:\s*([0-9a-f:]+)', line)
            if bssid_match:
                current_bssid = bssid_match.group(1).strip()
            if 'wps' in line and current_bssid:
                wps_bssids.add(current_bssid)
    except Exception:
        pass
    return wps_bssids
