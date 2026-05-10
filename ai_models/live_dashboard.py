import os
import time
import threading
from collections import deque
import numpy as np

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.align import Align
    from rich.markup import escape
    from scapy.all import sniff, ARP, Dot11, Dot11Beacon
    import tensorflow as tf
except ImportError:
    print("Dependencies missing for AI Dashboard.")
    exit(1)

# Suppress TF logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

LSTM_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'arp_lstm_model.h5')
DNN_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'evil_twin_dnn_model.h5')

# Models
arp_model = None
dnn_model = None

# Global state for UI
packet_log = deque(maxlen=10)
threat_log = deque(maxlen=5)
stats = {
    'start_time': 0,
    'total_packets': 0,
    'arp_analyzed': 0,
    'beacon_analyzed': 0,
    'threats_detected': 0
}

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'ai_dashboard_log.txt')
# Clear log file on startup
with open(LOG_FILE, 'w', encoding='utf-8') as f:
    f.write("WifiShield AI - Full Packet Inference Log\n")
    f.write("==========================================\n")

def log_to_file(model, target, conf, classification):
    """Saves every processed packet to a text file so the user can scroll through the history."""
    # Remove rich markup tags for clean text logging
    import re
    clean_target = re.sub(r'\[.*?\]', '', target)
    clean_class = re.sub(r'\[.*?\]', '', classification)
    clean_model = re.sub(r'\[.*?\]', '', model)
    timestamp = time.strftime('%H:%M:%S')
    
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {clean_model} | {clean_target} | Conf: {conf} | {clean_class}\n")

def add_threat(row):
    """Adds to threat log only if it's not spamming the exact same target."""
    target = row[1]
    for existing in threat_log:
        if existing[1] == target:
            return # Already tracking this specific threat on screen
    threat_log.append(row)


# Heuristic vars
TIME_STEPS = 5 
arp_sequence = deque(maxlen=TIME_STEPS)
last_arp_time = 0
last_seq_nums = {}

def load_models():
    global arp_model, dnn_model
    packet_log.append(("[dim]System[/]", "Loading AI Models...", "-", "[cyan]INITIALIZING[/]"))
    try:
        arp_model = tf.keras.models.load_model(LSTM_MODEL_PATH)
        dnn_model = tf.keras.models.load_model(DNN_MODEL_PATH)
        packet_log.append(("[dim]System[/]", "Models Loaded Successfully", "-", "[bold green]READY[/]"))
    except Exception as e:
        packet_log.append(("[dim]System[/]", f"Model Load Error", "-", "[bold red]FAILED[/]"))

def process_packet(packet):
    """Callback for Scapy sniffing"""
    global last_arp_time
    stats['total_packets'] += 1

    if not arp_model or not dnn_model:
        return

    # --- SIMULATION HOOK ---
    # Windows doesn't allow raw 802.11 frame injection without special hardware.
    # We allow simulated 802.11 frames to be encapsulated in UDP port 55555 for testing.
    if packet.haslayer('UDP') and packet.haslayer('Raw'):
        if packet['UDP'].dport == 55555:
            try:
                simulated_pkt = Dot11(packet['Raw'].load)
                if simulated_pkt.haslayer(Dot11Beacon):
                    packet = simulated_pkt
            except:
                pass
    # -----------------------

    # 1. ARP Spoofing (LSTM)
    if packet.haslayer(ARP):
        stats['arp_analyzed'] += 1
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
            
            target = escape(f"MAC: {packet[ARP].hwsrc}")
            conf = f"{prediction*100:.1f}%"
            
            model_str = "[bold cyan]LSTM (ARP)[/]" if prediction > 0.8 else "[cyan]LSTM (ARP)[/]"
            class_str = "[bold red blink]ATTACK DETECTED[/]" if prediction > 0.8 else "[green]SAFE[/]"
            
            row = (model_str, target, conf, class_str)
            packet_log.append(row)
            log_to_file(model_str, target, conf, class_str)
            
            if prediction > 0.8:
                stats['threats_detected'] += 1
                add_threat(row)

    # 2. Evil Twin (DNN)
    if packet.haslayer(Dot11Beacon):
        stats['beacon_analyzed'] += 1
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
        
        try:
            ssid = packet.info.decode()
        except:
            ssid = "Hidden"
            
        target = escape(f"SSID: {ssid[:10]} | BSSID: {bssid}")
        conf = f"{prediction*100:.1f}%"
        
        model_str = "[bold magenta]DNN (Evil Twin)[/]" if prediction > 0.8 else "[magenta]DNN (Evil Twin)[/]"
        class_str = "[bold red blink]ROGUE AP DETECTED[/]" if prediction > 0.8 else "[green]SAFE[/]"
        
        row = (model_str, target, conf, class_str)
        packet_log.append(row)
        log_to_file(model_str, target, conf, class_str)
        
        if prediction > 0.8:
            stats['threats_detected'] += 1
            add_threat(row)

def generate_layout() -> Layout:
    """Creates the Rich layout."""
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )
    layout["main"].split_column(
        Layout(name="threats", size=9),
        Layout(name="traffic")
    )
    return layout

def generate_threat_table() -> Table:
    """Generates the persistent threats log table."""
    table = Table(expand=True, border_style="red", show_edge=False)
    table.add_column("AI Model", style="bold white", width=20)
    table.add_column("Threat Signature", style="dim", width=40)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Classification", justify="center", width=20)
    
    if not threat_log:
        table.add_row("[dim]-[/]", "[dim]No active threats detected.[/]", "", "")
    else:
        for row in threat_log:
            table.add_row(*row)
    
    return Panel(table, title="[bold red blink]🚨 Persistent Threats Detected[/]", border_style="red")

def generate_table() -> Table:
    """Generates the updating packet log table."""
    table = Table(expand=True, border_style="blue", show_edge=False)
    table.add_column("AI Model", style="bold white", width=20)
    table.add_column("Target Signature", style="dim", width=40)
    table.add_column("Confidence", justify="right", width=12)
    table.add_column("Classification", justify="center", width=20)
    
    for row in packet_log:
        table.add_row(*row)
    
    return Panel(table, title="[bold]Real-Time Neural Network Inference Log[/]", border_style="cyan")

def update_ui(layout):
    """Updates the dynamic components of the layout."""
    # Header
    status_text = "[bold red blink]⚠ THREATS DETECTED ⚠[/]" if stats['threats_detected'] > 0 else "[bold green]✓ SYSTEM SECURE[/]"
    header = Panel(
        Align.center(f"[bold cyan]WifiShield[/] AI Cyber Defense Dashboard | Status: {status_text}"),
        style="white on dark_blue"
    )
    
    # Footer
    elapsed = int(time.time() - stats['start_time'])
    footer_text = (
        f"[bold]Total Packets:[/] {stats['total_packets']} | "
        f"[bold cyan]ARP Evaluated:[/] {stats['arp_analyzed']} | "
        f"[bold magenta]Beacons Evaluated:[/] {stats['beacon_analyzed']} | "
        f"[bold]Threats Caught:[/] {stats['threats_detected']} | "
        f"⏱️ {elapsed}s"
    )
    footer = Panel(Align.center(footer_text), style="white")
    
    layout["header"].update(header)
    layout["threats"].update(generate_threat_table())
    layout["traffic"].update(generate_table())
    layout["footer"].update(footer)
    return layout

def sniff_worker():
    """Background thread to sniff packets."""
    try:
        sniff(prn=process_packet, store=False)
    except Exception as e:
        packet_log.append(("[dim]System[/]", escape(f"Sniffer Error: {e}"), "-", "[bold red]ERROR[/]"))

def run_dashboard():
    """Entry point for the dashboard UI."""
    stats['start_time'] = time.time()
    
    # Load models synchronously before starting the UI so TF spam goes to standard output
    print("Loading Deep Learning Models... (Please wait)")
    load_models()
    
    layout = generate_layout()
    
    # Start sniffing thread
    t = threading.Thread(target=sniff_worker, daemon=True)
    t.start()
    
    packet_log.append(("[dim]System[/]", "Network Sniffer Active. Awaiting packets...", "-", "[blue]MONITORING[/]"))
    
    try:
        with Live(update_ui(layout), refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(0.25)
                live.update(update_ui(layout))
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Exited AI Dashboard.")

if __name__ == "__main__":
    run_dashboard()
