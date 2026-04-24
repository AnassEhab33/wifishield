import sys
sys.path.insert(0, '.')
from modules.scanner import scan_networks
from modules.encryption_audit import audit_encryption
from modules.ssid_checker import check_ssid, check_broadcast
from modules.wps_detector import detect_wps
from modules.mac_auditor import audit_mac_addresses
from modules.scorer import score_all_networks
from modules.report_gen import generate_report, open_report

print('All modules imported OK')
print('Scanning networks...')
networks = scan_networks()
print(f'Found {len(networks)} networks')

networks = audit_encryption(networks)
networks = check_ssid(networks)
networks = check_broadcast(networks)
networks = detect_wps(networks)
networks = score_all_networks(networks)
mac_audit = audit_mac_addresses()

total = mac_audit['total_devices']
print(f'MAC devices found: {total}')

report_path = generate_report(networks, mac_audit)
print(f'Report generated: {report_path}')

if networks:
    ap = networks[0]
    score = ap['security_score']['score']
    risk = ap['encryption_risk']
    print(f"  First AP: {ap['ssid']} | Score: {score} | Risk: {risk}")
