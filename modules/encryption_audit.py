"""
encryption_audit.py - Encryption Protocol Auditor
Based on Lecture 7 (Ch.11):
  - WEP uses RC4 (Wired Equivalent Privacy) — BROKEN
  - TKIP = Temporal Key Integrity Protocol — vulnerable but better
  - CCMP/AES (WPA2) = most secure method available
"""


ENCRYPTION_DETAILS = {
    'CRITICAL': {
        'label': 'CRITICAL RISK',
        'color': 'red',
        'icon': '🔴',
        'description': (
            'WEP encryption or Open network detected. '
            'WEP uses the RC4 algorithm and is trivially crackable using packet injection tools. '
            'An attacker can crack WEP in minutes using techniques covered in the lecture.'
        ),
        'recommendation': (
            'Immediately upgrade to WPA2 with AES (CCMP) encryption. '
            'WPA2-AES is the most secure method available and prevents WEP-cracking attacks.'
        ),
        'lecture_ref': 'Lecture 7 — Chapter 11: WEP Vulnerabilities (RC4 algorithm, IV attacks)'
    },
    'MEDIUM': {
        'label': 'MEDIUM RISK',
        'color': 'orange',
        'icon': '🟠',
        'description': (
            'TKIP (Temporal Key Integrity Protocol) detected. '
            'IEEE developed TKIP to allow older hardware to use a more secure encryption method than WEP. '
            'However, TKIP still uses the RC4 algorithm and is not considered fully secure.'
        ),
        'recommendation': (
            'Upgrade to WPA2 with CCMP (AES) if your hardware supports it. '
            'CCMP uses AES counter mode encryption — the strongest method available.'
        ),
        'lecture_ref': 'Lecture 7 — Chapter 11: TKIP section (per-packet key mixing, MIC countermeasures)'
    },
    'SAFE': {
        'label': 'SECURE',
        'color': 'green',
        'icon': '🟢',
        'description': (
            'WPA2 with AES/CCMP encryption detected. '
            'CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol) '
            'uses AES counter mode encryption — the most secure method available.'
        ),
        'recommendation': 'No action required. Continue using WPA2-AES/CCMP.',
        'lecture_ref': 'Lecture 7 — Chapter 11: CCMP (AES) — most secure encryption method available'
    },
    'UNKNOWN': {
        'label': 'UNKNOWN',
        'color': 'gray',
        'icon': '⚪',
        'description': 'Could not determine encryption protocol.',
        'recommendation': 'Investigate manually.',
        'lecture_ref': 'N/A'
    }
}


def audit_encryption(networks: list[dict]) -> list[dict]:
    """
    Add full encryption audit details to each network.
    Returns enriched list with audit_result key.
    """
    for ap in networks:
        risk = ap.get('encryption_risk', 'UNKNOWN')
        ap['audit_result'] = ENCRYPTION_DETAILS.get(risk, ENCRYPTION_DETAILS['UNKNOWN'])
    return networks


def get_encryption_score(risk: str) -> int:
    """Score deduction based on encryption type."""
    return {
        'CRITICAL': -40,
        'MEDIUM': -20,
        'SAFE': 0,
        'UNKNOWN': -10
    }.get(risk, -10)
