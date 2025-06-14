from scapy.all import sniff, IP
from datetime import datetime

packet_counts = {}

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        packet_counts[ip_src] = packet_counts.get(ip_src, 0) + 1
        
        if packet_counts[ip_src] == 100:
            alert = f"[{datetime.now()}] ⚠️ ALERT: High traffic from {ip_src}\n"
            print(alert)
            with open("alerts.txt", "a") as f:
                f.write(alert)

print("Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=packet_callback)
