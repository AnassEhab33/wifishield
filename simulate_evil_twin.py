from scapy.all import send, IP, UDP, Dot11, Dot11Beacon, Dot11Elt, Raw
import time

print("=========================================")
print("  Evil Twin Simulator (Test Script)")
print("=========================================")
print("Because standard Windows Wi-Fi cards block the injection of raw 802.11 ")
print("Beacon frames, this script wraps fake Beacon frames inside standard UDP ")
print("packets on port 55555. The WifiShield AI Dashboard is designed to unwrap ")
print("these specifically for testing the DNN Model.\n")

bssid = "AA:BB:CC:DD:EE:11"
ssid = "Simulated_Starbucks"

print("[+] Phase 1: Sending 'Normal' Wi-Fi Beacons (Low Signal, Sequential IDs)...")
for i in range(5):
    # Create the raw 802.11 Beacon frame
    # SC is the hardware sequence number (left shifted by 4)
    # We simulate a weak signal (-75 dBm) by injecting a dummy Radiotap if we could, 
    # but the AI falls back to a default if missing. We will manipulate the sequence number.
    dot11_frame = Dot11(type=0, subtype=8, addr3=bssid, SC=i<<4)/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)
    
    # Encapsulate it in a UDP packet so Windows will actually transmit it
    pkt = IP(dst="8.8.8.8")/UDP(sport=55555, dport=55555)/Raw(load=bytes(dot11_frame))
    send(pkt, verbose=False)
    time.sleep(0.2)

print("    -> AI should classify these as 0.0% SAFE.\n")
time.sleep(2)

print("[!] Phase 2: Injecting 'Evil Twin' Beacons (Massive Sequence Jumps!)...")
# A real evil twin broadcasting will have totally different sequence numbers
for i in range(5):
    # We jump the sequence number by +2000 to trigger the AI's anomaly detection
    # Note: Sequence numbers are 12-bit (max 4095), left-shifted by 4 bits
    dot11_frame = Dot11(type=0, subtype=8, addr3=bssid, SC=(i+2000)<<4)/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)
    
    pkt = IP(dst="8.8.8.8")/UDP(sport=55555, dport=55555)/Raw(load=bytes(dot11_frame))
    send(pkt, verbose=False)
    time.sleep(0.2)

print("    -> AI should immediately flag this as an ATTACK!\n")
print("[*] Simulation Complete. Check your AI Dashboard!")
