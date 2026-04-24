"""
scorer.py - Security Score Calculator
Aggregates all module results into a 0-100 security score per AP.
Deductions based on lecture concepts:
  - WEP/Open encryption: -40 (most critical, lecture says crackable in minutes)
  - TKIP: -20 (still uses RC4, vulnerable)
  - Default SSID: -15 (makes AP immediately identifiable via Network Stumbler)
  - SSID Broadcast: -10 (allows passive wardriving tools like NetStumbler)
  - WPS Enabled: -15 (Reaver attack cracks in ~19 hours per lecture demo)
"""


def calculate_score(ap: dict) -> dict:
    """Calculate a security score and risk label for a single AP."""
    score = 100
    findings = []

    # 1. Encryption check (Lecture 7: WEP/TKIP/WPA2-AES)
    enc_risk = ap.get('encryption_risk', 'UNKNOWN')
    enc_deduction = {
        'CRITICAL': -40,
        'MEDIUM': -20,
        'SAFE': 0,
        'UNKNOWN': -10
    }.get(enc_risk, -10)

    if enc_deduction < 0:
        score += enc_deduction
        label = {
            'CRITICAL': '🔴 WEP/Open — crackable (Lecture 7: RC4 IV attacks)',
            'MEDIUM': '🟠 TKIP — still uses RC4 (Lecture 7: upgrade to AES)',
            'UNKNOWN': '⚪ Unknown encryption protocol'
        }.get(enc_risk, '')
        findings.append({'type': 'encryption', 'severity': enc_risk, 'deduction': enc_deduction, 'label': label})

    # 2. Default SSID check (Table 11-1)
    if ap.get('is_default_ssid'):
        score -= 15
        findings.append({
            'type': 'ssid',
            'severity': 'HIGH',
            'deduction': -15,
            'label': f"🟠 Default vendor SSID — identifiable via Network Stumbler (Lecture 7, Table 11-1)"
        })

    # 3. SSID Broadcast (Figure 11-8)
    if ap.get('broadcast_on'):
        score -= 10
        findings.append({
            'type': 'broadcast',
            'severity': 'MEDIUM',
            'deduction': -10,
            'label': '🟡 SSID broadcast ON — visible to passive scanners (Lecture 7, Fig 11-8)'
        })

    # 4. WPS (Lecture 7: Reaver attack)
    if ap.get('wps_enabled'):
        score -= 15
        findings.append({
            'type': 'wps',
            'severity': 'HIGH',
            'deduction': -15,
            'label': '🟠 WPS enabled — vulnerable to Reaver PIN brute-force (Lecture 7)'
        })

    score = max(0, score)  # Floor at 0

    # Risk label
    if score >= 80:
        risk_label = '🟢 SECURE'
        risk_color = '#22c55e'
    elif score >= 55:
        risk_label = '🟡 MODERATE RISK'
        risk_color = '#eab308'
    elif score >= 30:
        risk_label = '🟠 HIGH RISK'
        risk_color = '#f97316'
    else:
        risk_label = '🔴 CRITICAL RISK'
        risk_color = '#ef4444'

    return {
        'score': score,
        'risk_label': risk_label,
        'risk_color': risk_color,
        'findings': findings
    }


def score_all_networks(networks: list[dict]) -> list[dict]:
    """Attach security scores to all networks."""
    for ap in networks:
        ap['security_score'] = calculate_score(ap)
    return networks
