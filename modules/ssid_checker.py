"""
ssid_checker.py - SSID Broadcast & Default SSID Checker
Based on Lecture 7 (Ch.11):
  - Table 11-1: Default SSIDs from major vendors
  - Figure 11-8: Disabling SSID broadcast on D-Link router
  - "Verify that your clients are not using a default SSID"
  - "Turn off SSID broadcast" — key hardening step
"""

import json
import os


def load_default_ssid_map():
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'default_ssids.json')
    with open(data_path, 'r') as f:
        data = json.load(f)
    vendor_map = {k.lower(): v for k, v in data['vendor_map'].items()}
    default_list = [s.lower() for s in data['default_ssids']]
    return default_list, vendor_map


def check_ssid(networks: list[dict]) -> list[dict]:
    """
    Enrich each AP with SSID security checks:
    - is_default_ssid: matches Table 11-1
    - ssid_vendor: which vendor the default SSID belongs to
    - ssid_score_deduction: score penalty
    - ssid_advice: hardening recommendation
    """
    default_list, vendor_map = load_default_ssid_map()

    for ap in networks:
        ssid = ap.get('ssid', '').strip()
        ssid_lower = ssid.lower()

        is_default = ssid_lower in default_list
        ap['is_default_ssid'] = is_default
        ap['ssid_vendor'] = vendor_map.get(ssid_lower, None) if is_default else None

        if is_default:
            vendor_info = f" (Vendor: {ap['ssid_vendor']})" if ap['ssid_vendor'] else ''
            ap['ssid_issue'] = (
                f"Default SSID detected{vendor_info}. "
                f"Attackers use Network Stumbler and similar tools to identify networks by their "
                f"default SSIDs from the vendor table (Lecture 7, Table 11-1). "
                f"This makes the AP immediately identifiable."
            )
            ap['ssid_advice'] = (
                "Change the SSID to a non-identifiable name (not related to the vendor or location). "
                "Also disable SSID broadcast as described in Lecture 7, Figure 11-8."
            )
            ap['ssid_score_deduction'] = -15
        else:
            ap['ssid_issue'] = None
            ap['ssid_advice'] = (
                "SSID is not a default vendor name. "
                "Consider also disabling SSID broadcast to force attackers to use "
                "active sniffing tools (like Kismet) rather than passive scanners (like NetStumbler)."
            )
            ap['ssid_score_deduction'] = 0

    return networks


def check_broadcast(networks: list[dict]) -> list[dict]:
    """
    All networks returned by netsh are broadcasting their SSID.
    Networks that have hidden SSIDs will not appear under normal mode.
    We flag all visible networks as 'broadcast_on' = True.
    """
    for ap in networks:
        ap['broadcast_on'] = True
        ap['broadcast_advice'] = (
            "This AP is broadcasting its SSID. "
            "Lecture 7 (Figure 11-8) shows how to disable SSID broadcast on your AP. "
            "Disabling broadcast forces attackers to use active tools like Kismet "
            "instead of simple passive scanners like NetStumbler."
        )
        ap['broadcast_score_deduction'] = -10

    return networks
