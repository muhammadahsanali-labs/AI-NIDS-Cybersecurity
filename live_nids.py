import time
import pandas as pd
import joblib
from scapy.all import sniff, IP

print("[*] Loading Multi-Class AI-NIDS Engine...")
model = joblib.load('nids_model.pkl')
print("[+] Model Active with Risk Scoring & Heuristic Smoothing Logic!")

window_start = time.time()
window_packets = 0
window_bytes = 0

def process_and_classify(packet):
    global window_start, window_packets, window_bytes
    
    if packet.haslayer(IP):
        current_time = time.time()
        elapsed = current_time - window_start
        
        # Hard reset window every 1 second
        if elapsed >= 1.0:
            window_start = current_time
            window_packets = 0
            window_bytes = 0
            elapsed = 0.001
            
        window_packets += 1
        window_bytes += len(packet)
        
        # Prevent micro-time fraction division spikes on packet 1
        effective_elapsed = max(elapsed, 0.05)  # minimum 50ms floor for accurate rate
        bytes_per_sec = window_bytes / effective_elapsed
        
        dest_port = packet[IP].dport if hasattr(packet[IP], 'dport') else 80
        
        flow_features = pd.DataFrame([{
            'Destination_Port': dest_port,
            'Flow_Duration': effective_elapsed * 1000,
            'Total_Fwd_Packets': window_packets,
            'Flow_Bytes_s': bytes_per_sec
        }])
        
        # Predict Attack Category
        attack_type = model.predict(flow_features)[0]
        
        # Heuristic Safety Filter: Ignore single-packet isolated micro spikes
        if window_packets < 2 and attack_type == 'PortScan':
            attack_type = 'Normal'
            
        # Assign Severity & Risk Level
        if attack_type == 'Normal':
            status = "✅ NORMAL (LOW RISK)"
        elif attack_type == 'PortScan':
            status = "⚠️ PORTSCAN DETECTED (MEDIUM RISK)"
        elif attack_type == 'DDoS':
            status = "🚨 DDOS ATTACK (CRITICAL RISK)"
        else:
            status = f"⚡ UNKNOWN ({attack_type})"
        
        print(f"[LIVE INFERENCE] Target Port: {dest_port:<5} | Pkts: {window_packets:<3} | Rate: {bytes_per_sec:<8.1f} B/s | Alert: {status}")

print("\n[*] Sniffing Live Traffic Across All Interfaces... (Press Ctrl+C to stop)")
sniff(iface=None, prn=process_and_classify)
