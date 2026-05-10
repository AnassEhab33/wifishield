import os
import time
import numpy as np
from collections import deque
from scapy.all import sniff, ARP, Dot11, Dot11Beacon
import tensorflow as tf

# Suppress TF logging for cleaner terminal output
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# --- Configuration ---
LSTM_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'arp_lstm_model.h5')
DNN_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'evil_twin_dnn_model.h5')

# We need the same time steps used in training
TIME_STEPS = 5 
# In-memory sliding window for ARP packets
arp_sequence = deque(maxlen=TIME_STEPS)
last_arp_time = 0

# Track sequence numbers to calculate deltas
last_seq_nums = {}

# --- Load Models ---
arp_model = None
dnn_model = None

def load_models():
    global arp_model, dnn_model
    if arp_model is not None and dnn_model is not None:
        return True
        
    print("[*] Loading Deep Learning Models...")
    try:
        arp_model = tf.keras.models.load_model(LSTM_MODEL_PATH)
        dnn_model = tf.keras.models.load_model(DNN_MODEL_PATH)
        print("[+] Models loaded successfully.")
        return True
    except Exception as e:
        print(f"[-] Error loading models. Did you run the training scripts first? Error: {e}")
        return False

# Note: In a real environment, you must load the EXACT SAME scalers 
# (MinMaxScaler/StandardScaler) fitted during training. 
# For this script, we apply a simulated heuristic scaling matching the training synthetic data bounds.

def process_packet(packet):
    """
    Callback function executed by Scapy for every sniffed packet.
    Extracts features dynamically and runs real-time inference.
    """
    global last_arp_time
    
    # ---------------------------------------------------------
    # 1. ARP Spoofing Detection (LSTM)
    # ---------------------------------------------------------
    if packet.haslayer(ARP):
        current_time = float(packet.time)
        
        # Calculate Delta Time (ms)
        dt = (current_time - last_arp_time) * 1000 if last_arp_time else 100.0
        last_arp_time = current_time
        
        # Determine Ratio & Frequency heuristics
        # Op 1: Request, Op 2: Reply
        ratio = 0.1 if packet[ARP].op == 2 else 1.0 
        freq = 1000 / dt if dt > 0 else 200 # Packets per second
        
        # Heuristic Scaling (Normally done via loaded MinMaxScaler)
        dt_scaled = min(dt / 100.0, 1.0)
        ratio_scaled = ratio / 1.2
        freq_scaled = min(freq / 200.0, 1.0)
        
        arp_sequence.append([dt_scaled, ratio_scaled, freq_scaled])
        
        # If we have enough packets to form a sequence window
        if len(arp_sequence) == TIME_STEPS:
            # Reshape to (1, TIME_STEPS, FEATURES)
            input_data = np.array([list(arp_sequence)])
            
            # Use model(inputs, training=False) which is faster than model.predict() for single samples
            prediction = arp_model(input_data, training=False).numpy()[0][0]
            
            if prediction > 0.8:
                print(f"[!] DYNAMIC ALERT: ARP Spoofing Detected! (Confidence: {prediction*100:.1f}%) | MAC: {packet[ARP].hwsrc}")

    # ---------------------------------------------------------
    # 2. Evil Twin Detection (DNN)
    # ---------------------------------------------------------
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
        
        # Get RSSI (Signal Strength). Depends on the radio tap header.
        # Fallback to simulated value if adapter doesn't provide it
        try:
            rssi = packet.dBm_AntSignal
        except:
            rssi = -60 # Default fallback
            
        # Calculate Sequence Number Delta
        seq_num = packet[Dot11].SC >> 4
        if bssid in last_seq_nums:
            seq_delta = abs(seq_num - last_seq_nums[bssid])
        else:
            seq_delta = 1
        last_seq_nums[bssid] = seq_num
        
        # Frame Control Subtype (Beacon = 8)
        fc_subtype = packet[Dot11].subtype
        
        # Heuristic Scaling (Normally done via loaded StandardScaler)
        # Using the bounds from our synthetic generator (-40 to -75 RSSI, Deltas 1 to 2000)
        rssi_scaled = (rssi - (-60)) / 15.0 
        seq_scaled = (seq_delta - 1000) / 1000.0
        fc_scaled = (fc_subtype - 8) / 1.0
        
        # Reshape to (1, FEATURES)
        input_data = np.array([[rssi_scaled, seq_scaled, fc_scaled]])
        
        prediction = dnn_model(input_data, training=False).numpy()[0][0]
        
        if prediction > 0.8:
            try:
                ssid = packet.info.decode()
            except:
                ssid = "Hidden"
            print(f"[!] DYNAMIC ALERT: Evil Twin/Rogue AP Detected! (Confidence: {prediction*100:.1f}%) | BSSID: {bssid} | SSID: {ssid}")

def main():
    print("=" * 60)
    print("WifiShield AI - Real-Time Inference Engine")
    print("=" * 60)
    
    if not load_models():
        exit(1)
        
    print("Capturing live network traffic...")
    print("Press Ctrl+C to stop.\n")
    
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping inference engine.")

def run_ai_audit(timeout=5):
    """
    Runs a short background sniff to gather AI analysis for the HTML report.
    Returns: ai_stats dictionary
    """
    ai_stats = {
        'packets_analyzed': 0,
        'arp_threats': [],
        'evil_twin_threats': []
    }
    
    if not load_models():
        return ai_stats
        
    def audit_packet(packet):
        ai_stats['packets_analyzed'] += 1
        
        # --- SIMULATION HOOK ---
        from scapy.all import UDP, Raw, Dot11, Dot11Beacon
        if packet.haslayer(UDP) and packet.haslayer(Raw):
            if packet[UDP].dport == 55555:
                try:
                    simulated_pkt = Dot11(packet[Raw].load)
                    if simulated_pkt.haslayer(Dot11Beacon):
                        packet = simulated_pkt
                except:
                    pass
        # -----------------------
        
        # ARP Spoofing (LSTM)
        if packet.haslayer(ARP):
            global last_arp_time
            current_time = float(packet.time)
            dt = (current_time - last_arp_time) * 1000 if last_arp_time else 100.0
            last_arp_time = current_time
            ratio = 0.1 if packet[ARP].op == 2 else 1.0 
            freq = 1000 / dt if dt > 0 else 200
            
            dt_scaled = min(dt / 100.0, 1.0)
            ratio_scaled = ratio / 1.2
            freq_scaled = min(freq / 200.0, 1.0)
            
            arp_sequence.append([dt_scaled, ratio_scaled, freq_scaled])
            
            if len(arp_sequence) == TIME_STEPS:
                input_data = np.array([list(arp_sequence)])
                prediction = arp_model(input_data, training=False).numpy()[0][0]
                if prediction > 0.8:
                    mac = packet[ARP].hwsrc
                    threat = {'mac': mac, 'confidence': round(prediction * 100, 1)}
                    if threat not in ai_stats['arp_threats']:
                        ai_stats['arp_threats'].append(threat)

        # Evil Twin (DNN)
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr3
            try:
                rssi = packet.dBm_AntSignal
            except:
                rssi = -60
                
            seq_num = packet[Dot11].SC >> 4
            if bssid in last_seq_nums:
                seq_delta = abs(seq_num - last_seq_nums[bssid])
            else:
                seq_delta = 1
            last_seq_nums[bssid] = seq_num
            
            fc_subtype = packet[Dot11].subtype
            rssi_scaled = (rssi - (-60)) / 15.0 
            seq_scaled = (seq_delta - 1000) / 1000.0
            fc_scaled = (fc_subtype - 8) / 1.0
            
            input_data = np.array([[rssi_scaled, seq_scaled, fc_scaled]])
            prediction = dnn_model(input_data, training=False).numpy()[0][0]
            
            if prediction > 0.8:
                try:
                    ssid = packet.info.decode()
                except:
                    ssid = "Hidden"
                threat = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'confidence': round(prediction * 100, 1)
                }
                if threat not in ai_stats['evil_twin_threats']:
                    ai_stats['evil_twin_threats'].append(threat)

    sniff(prn=audit_packet, store=False, timeout=timeout)
    return ai_stats

if __name__ == "__main__":
    main()
