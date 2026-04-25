"""
evil_twin_detector.py - Evil Twin / Rogue AP Detector

An Evil Twin attack plants a rogue AP with the same SSID as a legitimate
network, tricking clients into connecting to it instead.

Detection strategy (works purely from standard netsh scan data):
  1. Same SSID, multiple BSSIDs → potential evil twin
  2. Same SSID, different security level (one open, one WPA2) → HIGH risk
  3. Same SSID, different vendor OUI → CRITICAL risk (different hardware)
  4. Open network with the same SSID as a WPA2 network → CRITICAL
"""

from modules.oui_lookup import lookup_vendor


def detect_evil_twins(networks: list) -> dict:
    """
    Analyze scanned networks for Evil Twin indicators.
    Returns a structured result with flagged SSID groups and risk levels.
    """
    if not networks:
        return _empty_result()

    # Group all APs by SSID (case-insensitive)
    ssid_groups: dict = {}
    for ap in networks:
        ssid = (ap.get('ssid') or '').strip()
        if not ssid:
            continue
        key = ssid.lower()
        if key not in ssid_groups:
            ssid_groups[key] = []
        ssid_groups[key].append(ap)

    flagged = []

    for ssid_key, aps in ssid_groups.items():
        if len(aps) < 2:
            continue  # Single AP = no conflict

        ssid_display = aps[0].get('ssid', ssid_key)

        # Collect properties across all APs sharing this SSID
        bssids       = [ap.get('bssid', '') for ap in aps]
        encryptions  = [ap.get('encryption_risk', 'UNKNOWN') for ap in aps]
        vendors      = [lookup_vendor(bssid) for bssid in bssids]
        channels     = [ap.get('channel', 0) for ap in aps]
        signals      = [ap.get('signal', 0) for ap in aps]
        securities   = [ap.get('security', '') for ap in aps]

        unique_vendors = set(v for v in vendors if v != 'Unknown Vendor')
        has_open       = any(e == 'CRITICAL' or s.upper() in ('OPEN', 'NONE')
                             for e, s in zip(encryptions, securities))
        has_secure     = any(e == 'SAFE' for e in encryptions)
        vendor_conflict = len(unique_vendors) > 1
        channel_hops   = len(set(channels)) > 1  # Same SSID, different channels

        # Risk scoring
        if has_open and has_secure:
            risk = 'CRITICAL'
            reason = 'Same SSID has both open and encrypted variants — classic evil twin'
        elif vendor_conflict:
            risk = 'CRITICAL'
            reason = f'Same SSID broadcast by different hardware vendors: {", ".join(unique_vendors)}'
        elif channel_hops:
            risk = 'HIGH'
            reason = f'Same SSID on multiple channels ({set(channels)}) — unusual, possible rogue AP'
        else:
            risk = 'MEDIUM'
            reason = f'Same SSID seen from {len(aps)} different BSSIDs'

        flagged.append({
            'ssid': ssid_display,
            'count': len(aps),
            'risk': risk,
            'reason': reason,
            'has_open': has_open,
            'has_secure': has_secure,
            'vendor_conflict': vendor_conflict,
            'channel_hops': channel_hops,
            'aps': [
                {
                    'bssid': ap.get('bssid', 'N/A'),
                    'security': ap.get('security', '?'),
                    'encryption': ap.get('encryption', '?'),
                    'encryption_risk': ap.get('encryption_risk', 'UNKNOWN'),
                    'channel': ap.get('channel', 0),
                    'signal': ap.get('signal', 0),
                    'vendor': lookup_vendor(ap.get('bssid', '')),
                }
                for ap in aps
            ]
        })

    # Sort by risk severity
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    flagged.sort(key=lambda x: risk_order.get(x['risk'], 3))

    return {
        'flagged': flagged,
        'total': len(flagged),
        'critical_count': sum(1 for f in flagged if f['risk'] == 'CRITICAL'),
        'note': (
            'An Evil Twin attack uses a rogue AP with the same SSID as a '
            'legitimate network to intercept traffic. '
            'Red flags: same SSID with different hardware, or one open variant alongside a secured one.'
        )
    }


def _empty_result() -> dict:
    return {
        'flagged': [],
        'total': 0,
        'critical_count': 0,
        'note': 'No networks scanned.'
    }
