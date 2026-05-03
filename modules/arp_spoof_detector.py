import subprocess
import re

def get_default_gateway() -> str:
    """Find the default gateway IP using ipconfig."""
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if "Default Gateway" in line:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return ""

def detect_arp_spoofing() -> dict:
    """
    Analyzes the ARP table for duplicate MAC addresses,
    specifically focusing on the Default Gateway to detect MitM.
    """
    result = {
        'attack_detected': False,
        'gateway_ip': '',
        'spoofed_mac': '',
        'attacker_ip': '',
        'risk': 'SAFE',
        'details': ''
    }

    gateway_ip = get_default_gateway()
    if gateway_ip:
        result['gateway_ip'] = gateway_ip

    mac_to_ips = {}
    
    try:
        arp_result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        lines = arp_result.stdout.split('\n')
        
        for line in lines:
            # Match IP, MAC, and Type (dynamic/static)
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w-]{17})\s+(\w+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                entry_type = match.group(3)

                # Ignore broadcast and multicast entries
                if ip.endswith('.255') or ip.startswith('224.') or ip.startswith('239.'):
                    continue
                if mac.startswith('FF') or mac.startswith('01:00:5E'):
                    continue
                
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)

        # Look for duplicates
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                # We found a duplicate MAC. Check if it targets the gateway.
                if gateway_ip in ips:
                    result['attack_detected'] = True
                    result['risk'] = 'CRITICAL'
                    result['spoofed_mac'] = mac
                    # The attacker is the other IP sharing this MAC
                    attacker_ips = [ip for ip in ips if ip != gateway_ip]
                    result['attacker_ip'] = attacker_ips[0] if attacker_ips else "Unknown"
                    result['details'] = (
                        f"CRITICAL: The Default Gateway ({gateway_ip}) and another device "
                        f"({result['attacker_ip']}) are both claiming the same MAC address ({mac}). "
                        "This is a confirmed ARP Spoofing / Man-in-the-Middle attack."
                    )
                    break
                else:
                    # Duplicate MACs not involving gateway (might still be an attack against another client)
                    result['attack_detected'] = True
                    result['risk'] = 'HIGH'
                    result['spoofed_mac'] = mac
                    result['details'] = (
                        f"Warning: Multiple IP addresses ({', '.join(ips)}) share the same MAC address ({mac}). "
                        "This indicates potential ARP Poisoning on the network."
                    )
                    break
                    
    except Exception as e:
        result['details'] = f"Error scanning ARP table: {str(e)}"

    return result

def prevent_arp_spoof() -> tuple[bool, str]:
    """
    Attempt to flush the ARP cache and disconnect the network.
    Returns (success, message).
    """
    try:
        # Try to flush ARP
        result = subprocess.run(['arp', '-d', '*'], capture_output=True, text=True, timeout=5)
        
        # Disconnect to protect user
        subprocess.run(['netsh', 'wlan', 'disconnect'], capture_output=True, timeout=5)
        
        if result.returncode != 0:
            if "elevation" in result.stdout.lower() or "elevation" in result.stderr.lower() or "requires" in result.stdout.lower():
                return False, "Failed to flush ARP cache. Please run WifiShield as Administrator to clear the poisoned cache. (Wi-Fi disconnected for safety)."
            return False, f"Failed to flush ARP: {result.stderr or result.stdout}"
            
        return True, "ARP cache successfully flushed and Wi-Fi disconnected."
    except Exception as e:
        return False, f"Error applying prevention: {str(e)}"
