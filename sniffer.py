import time
from scapy.all import sniff, IP

start_time = time.time()
packet_count = 0
total_bytes = 0

def process_packet(packet):
    global packet_count, total_bytes, start_time
    
    if packet.haslayer(IP):
        packet_count += 1
        total_bytes += len(packet)
        duration = (time.time() - start_time) * 1000  # in ms
        bytes_per_sec = total_bytes / (duration / 1000) if duration > 0 else 0
        
        # Get destination port if available (TCP/UDP), default to 80
        dest_port = packet[IP].dport if hasattr(packet[IP], 'dport') else 80
        
        print(f"[LIVE FLOW] Port: {dest_port} | Duration: {duration:.2f}ms | Packets: {packet_count} | Bytes/s: {bytes_per_sec:.2f}")

print("[*] Listening for live network traffic with Scapy...")
# Sniffs 10 live IP packets on any active interface
sniff(filter="ip", prn=process_packet, count=10)

