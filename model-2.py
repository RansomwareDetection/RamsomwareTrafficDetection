import scapy.all as scapy
import time
from collections import defaultdict
import os

port_scan_attempts = defaultdict(lambda: defaultdict(int))
syn_flood_attempts = defaultdict(int)
dns_query_attempts = defaultdict(int)
packet_count = defaultdict(int)
suspicious_data = []  

def packet_callback(packet):
    # Large packet size
    if len(packet) > 1500:
        suspicious_data.append(packet)
    
    # Port Scan Detection
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        ip_src = packet[scapy.IP].src
        port_dst = packet[scapy.TCP].dport
        port_scan_attempts[ip_src][port_dst] += 1
        if port_scan_attempts[ip_src][port_dst] > 10:
            suspicious_data.append(packet)
    
    # SYN Flood Detection
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 'S':  # SYN flag set
            ip_src = packet[scapy.IP].src
            syn_flood_attempts[ip_src] += 1
            if syn_flood_attempts[ip_src] > 100:
                suspicious_data.append(packet)
    
    # DNS Amplification Detection
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
        if packet[scapy.DNS].qr == 0:  
            ip_src = packet[scapy.IP].src
            dns_query_attempts[ip_src] += 1
            if dns_query_attempts[ip_src] > 50:
                suspicious_data.append(packet)
    
    # Packet Flooding Detection
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        packet_count[ip_src] += 1
        if packet_count[ip_src] > 100:
            suspicious_data.append(packet)
    
    # HTTP-based Threat Detection (SQL Injection, XSS, etc.)
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:  
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors="ignore")
                if "SELECT" in payload or "UNION" in payload or "DROP" in payload:
                    suspicious_data.append(packet)
                elif "<script>" in payload:
                    suspicious_data.append(packet)

def capture_and_analyze_packets():
    scapy.sniff(prn=packet_callback, store=0, timeout=60)  
    if suspicious_data: 
        save_suspicious_data(suspicious_data)
    time.sleep(60)  

def save_suspicious_data(suspicious_data):
    temp_dir = "suspicious_data"
    os.makedirs(temp_dir, exist_ok=True)
    pcap_filename = os.path.join(temp_dir, "suspicious_data.pcap")
    scapy.wrpcap(pcap_filename, suspicious_data)
    print(f"Suspicious data saved to {pcap_filename}")

# Run the system
capture_and_analyze_packets()
