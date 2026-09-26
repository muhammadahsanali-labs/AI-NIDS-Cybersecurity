import time
import sqlite3
import pandas as pd
import joblib
from scapy.all import sniff, IP
from xai_engine import generate_evidence

# -------------------------------------------------------------
# PHASE 11: Initialize SQLite Database & Table Schema
# -------------------------------------------------------------
conn = sqlite3.connect('incidents.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        target_port INTEGER NOT NULL,
        packet_count INTEGER NOT NULL,
        rate_bytes_sec REAL NOT NULL,
        attack_type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        evidence TEXT NOT NULL
    )
''')
conn.commit()

print("[*] SQLite Database 'incidents.db' Initialized Successfully!")
print("[*] Loading Multi-Class AI-NIDS Engine...")
model = joblib.load('nids_model.pkl')
print("[+] Model Active with Phase 10 XAI & Phase 11 Database Logging!")

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
        
        effective_elapsed = max(elapsed, 0.05)
        bytes_per_sec = window_bytes / effective_elapsed
        dest_port = packet[IP].dport if hasattr(packet[IP], 'dport') else 80
        
        flow_features = pd.DataFrame([{
            'Destination_Port': dest_port,
            'Flow_Duration': effective_elapsed * 1000,
            'Total_Fwd_Packets': window_packets,
            'Flow_Bytes_s': bytes_per_sec
        }])
        
        attack_type = model.predict(flow_features)[0]
        
        # Heuristic Safety Filter
        if window_packets < 2 and attack_type == 'PortScan':
            attack_type = 'Normal'
            
        # Phase 10: XAI Evidence Generation
        evidence_text = generate_evidence(attack_type, dest_port, window_packets, bytes_per_sec)
        
        # Assign Severity & Risk Level
        if attack_type == 'Normal':
            status = "✅ NORMAL (LOW RISK)"
            risk = "LOW"
        elif attack_type == 'PortScan':
            status = "⚠️ PORTSCAN DETECTED (MEDIUM RISK)"
            risk = "MEDIUM"
        elif attack_type == 'DDoS':
            status = "🚨 DDOS ATTACK (CRITICAL RISK)"
            risk = "CRITICAL"
        else:
            status = f"⚡ UNKNOWN ({attack_type})"
            risk = "UNKNOWN"
            
        print(f"\n[LIVE INFERENCE] Target Port: {dest_port:<5} | Pkts: {window_packets:<3} | Alert: {status}")
        print(f" └─[XAI EVIDENCE]: {evidence_text}")
        
        # -------------------------------------------------------------
        # PHASE 11: Auto-Log Threats (MEDIUM & CRITICAL) to SQLite DB
        # -------------------------------------------------------------
        if risk in ['MEDIUM', 'CRITICAL']:
            timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT INTO incidents 
                (timestamp, target_port, packet_count, rate_bytes_sec, attack_type, risk_level, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp_str, dest_port, window_packets, bytes_per_sec, attack_type, risk, evidence_text))
            conn.commit()
            print(f" └─[DB LOG]: Incident recorded into 'incidents.db' successfully.")

print("\n[*] Sniffing Live Traffic Across All Interfaces... (Press Ctrl+C to stop)")
sniff(iface=None, prn=process_and_classify)
