import subprocess
import time
from datetime import datetime, timedelta

def detect_deauth_attack(time_window_minutes=2, disconnect_threshold=3) -> dict:
    """
    Detects potential Deauthentication attacks by parsing Windows Event Logs
    for rapid, repeated disconnections (Event ID 11004).
    """
    result = {
        'attack_detected': False,
        'disconnect_count': 0,
        'events': [],
        'risk': 'SAFE'
    }

    try:
        # PowerShell command to fetch Event ID 11004 from the last X minutes
        ps_script = (
            f"$StartTime = (Get-Date).AddMinutes(-{time_window_minutes}); "
            "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; ID=11004; StartTime=$StartTime} "
            "-ErrorAction SilentlyContinue | Select-Object -Property TimeCreated | Format-List"
        )
        
        proc = subprocess.run(['powershell', '-Command', ps_script], capture_output=True, text=True, timeout=10)
        
        if proc.returncode != 0 and "No events were found" not in proc.stderr:
            # Command failed for some reason other than "no events"
            return result

        output = proc.stdout.strip()
        if not output:
            return result

        # Count the number of 'TimeCreated' entries
        lines = output.split('\n')
        for line in lines:
            if line.startswith("TimeCreated"):
                result['disconnect_count'] += 1
                result['events'].append(line.split(':', 1)[1].strip())

        if result['disconnect_count'] >= disconnect_threshold:
            result['attack_detected'] = True
            result['risk'] = 'CRITICAL'

    except Exception as e:
        # Ignore errors if event log reading fails (e.g., permissions)
        pass

    return result


def prevent_deauth_attack(ssid: str) -> bool:
    """
    Prevents a Deauth attack loop by disconnecting from the network
    and disabling auto-connect for the targeted SSID.
    """
    try:
        # Disconnect immediately
        subprocess.run(['netsh', 'wlan', 'disconnect'], capture_output=True, timeout=5)
        
        if ssid and ssid != 'Hidden':
            # Disable auto-connect for this profile
            subprocess.run(
                ['netsh', 'wlan', 'set', 'profileparameter', f'name="{ssid}"', 'connectionMode=manual'],
                capture_output=True, timeout=5
            )
        return True
    except Exception:
        return False
