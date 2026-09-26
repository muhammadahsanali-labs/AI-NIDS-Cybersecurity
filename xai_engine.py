# Phase 10: Explainable AI (XAI) Evidence Module

def generate_evidence(prediction_label, dest_port, pkt_count, bytes_per_sec):
    """
    Generates human-readable, forensic evidence explaining WHY the AI model flagged the traffic.
    """
    if prediction_label == 'Normal':
        return (
            f"BASELINE TRAFFIC: Target Port {dest_port} received {pkt_count} packet(s) "
            f"at {bytes_per_sec:.1f} B/s. Metrics align with normal network behavior."
        )
        
    elif prediction_label == 'PortScan':
        return (
            f"RECONNAISSANCE EVIDENCE: High-frequency port probing detected on target port {dest_port}. "
            f"Low packet payload density with {pkt_count} packet(s) in window."
        )
        
    elif prediction_label == 'DDoS':
        return (
            f"VOLUMETRIC ANOMALY EVIDENCE: Bandwidth spike detected on port {dest_port}. "
            f"Traffic rate jumped to {bytes_per_sec:.1f} Bytes/sec across {pkt_count} packet(s)/sec."
        )
        
    else:
        return f"UNKNOWN ANOMALY: Pattern unclassified on port {dest_port}."
