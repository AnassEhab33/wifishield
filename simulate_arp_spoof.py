import subprocess
import re
import sys

print("=========================================")
print("   ARP Spoof Simulator (Test Script)     ")
print("=========================================")

print("Detecting active network adapter...")
try:
    ipconfig_out = subprocess.run(['ipconfig'], capture_output=True, text=True).stdout
except Exception:
    print("Failed to run ipconfig")
    sys.exit(1)

gateway = None
for line in ipconfig_out.split('\n'):
    if "Default Gateway" in line and not "::" in line:
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if match:
            gateway = match.group(1)
            break

if not gateway:
    print("Error: Could not find Default Gateway.")
    sys.exit(1)

print(f"Found Gateway: {gateway}")

try:
    netsh_out = subprocess.run(['netsh', 'interface', 'ipv4', 'show', 'interfaces'], capture_output=True, text=True).stdout
except Exception:
    print("Failed to run netsh")
    sys.exit(1)

idx = None
for line in netsh_out.split('\n'):
    if "connected" in line.lower() and "wi-fi" in line.lower():
        parts = line.strip().split()
        if parts:
            idx = parts[0]
            break

if not idx:
    idx = "Wi-Fi"

parts = gateway.split('.')
fake_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.250"
fake_mac = "AA-BB-CC-DD-EE-FF"

print(f"Interface Index: {idx}")
print(f"Injecting duplicate MAC ({fake_mac})...")

try:
    res1 = subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'neighbors', str(idx), gateway, fake_mac], capture_output=True, text=True)
    subprocess.run(['netsh', 'interface', 'ipv4', 'set', 'neighbors', str(idx), fake_ip, fake_mac], capture_output=True, text=True)
    
    if res1.returncode != 0:
        print("\nERROR: This script MUST be run as Administrator!")
        print("Please open your terminal as Administrator and try again.")
        sys.exit(1)
        
    print("\n[+] ARP Table successfully poisoned!")
    print(">>> RUN WIFISHIELD NOW TO DETECT THE ATTACK <<<\n")
    input("Press ENTER when you are done testing to clean up the ARP table...")
    
    print("Cleaning up ARP table...")
    subprocess.run(['netsh', 'interface', 'ipv4', 'delete', 'neighbors', str(idx), gateway], capture_output=True)
    subprocess.run(['netsh', 'interface', 'ipv4', 'delete', 'neighbors', str(idx), fake_ip], capture_output=True)
    print("Cleanup complete! You are safe.")
    
except Exception as e:
    print(f"ERROR: {e}")
