"""
report_gen.py - HTML Security Report Generator
Renders the Jinja2 template with all scan results.
"""

import os
import webbrowser
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_report(networks: list, mac_audit: dict,
                    evil_twin_audit: dict = None,
                    deauth_audit: dict = None,
                    arp_audit: dict = None,
                    output_dir: str = None) -> str:
    """
    Generate HTML security report.
    Returns path to the generated HTML file.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')

    os.makedirs(output_dir, exist_ok=True)

    templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template('report.html')

    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Count by risk level
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'safe': 0}
    for ap in networks:
        score = ap.get('security_score', {}).get('score', 50)
        if score < 30:
            counts['critical'] += 1
        elif score < 55:
            counts['high'] += 1
        elif score < 80:
            counts['medium'] += 1
        else:
            counts['safe'] += 1

    if evil_twin_audit is None:
        evil_twin_audit = {
            'flagged': [], 'total': 0, 'critical_count': 0,
            'note': ''
        }
    if deauth_audit is None:
        deauth_audit = {'attack_detected': False, 'disconnect_count': 0, 'risk': 'SAFE'}
    if arp_audit is None:
        arp_audit = {'attack_detected': False, 'risk': 'SAFE', 'details': ''}

    html_content = template.render(
        networks=networks,
        mac_audit=mac_audit,
        evil_twin_audit=evil_twin_audit,
        deauth_audit=deauth_audit,
        arp_audit=arp_audit,
        scan_time=scan_time,
        total_aps=len(networks),
        counts=counts
    )

    report_path = os.path.join(output_dir, f'wifi_audit_{timestamp}.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return report_path


def open_report(path: str):
    """Open the report in the default browser."""
    webbrowser.open(f'file:///{os.path.abspath(path)}')
