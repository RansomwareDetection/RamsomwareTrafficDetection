# network_traffic_monitor.py
from scapy.all import sniff, IP, TCP
import datetime
import numpy as np

# Function to process packets and extract metrics
def process_sniffed_packets(packets):
    processed_packets = []
    for packet in packets:
        packet_features = {
            'Timestamp': datetime.datetime.now(),
            'Packet Length': len(packet),
            ' ACK Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x10 else 0,
            ' SYN Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x02 else 0,
            'FIN Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x01 else 0,
            ' PSH Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x08 else 0,
            ' RST Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x04 else 0,
            ' URG Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags == 0x20 else 0,
            ' Fwd Header Length.1': len(packet[IP]) if packet.haslayer(IP) else None,
            ' Avg Fwd Segment Size': packet[IP].len / 2 if packet.haslayer(IP) else None,
            ' Avg Bwd Segment Size': packet[IP].len / 2 if packet.haslayer(IP) else None,
            ' Average Packet Size': len(packet),
            ' Min Packet Length': min(len(packet), 1500),
            ' Max Packet Length': max(len(packet), 1500),
            ' Down/Up Ratio': packet[IP].len / 1500 if packet.haslayer(IP) else None,
            ' ECE Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x80 else 0,
            ' CWE Flag Count': 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x40 else 0,
            'Fwd Packets/s': 1 if packet.haslayer(IP) else 0,
            # Placeholder for other fields that can be calculated based on the traffic data
        }
        processed_packets.append(packet_features)
    return processed_packets

# Function to gather metrics and return relevant features for logging
def gather_metrics(handler, packet_data):
    return [
        packet_data['Timestamp'], packet_data[' ACK Flag Count'], packet_data[' SYN Flag Count'],
        packet_data['FIN Flag Count'], packet_data[' PSH Flag Count'], packet_data[' RST Flag Count'],
        packet_data[' URG Flag Count'], packet_data[' Fwd Header Length.1'], packet_data[' Avg Fwd Segment Size'],
        packet_data[' Avg Bwd Segment Size'], packet_data[' Average Packet Size'], packet_data[' Min Packet Length'],
        packet_data[' Max Packet Length'], packet_data[' Down/Up Ratio'], packet_data[' ECE Flag Count'],
        packet_data[' CWE Flag Count'], packet_data['Fwd Packets/s']
    ]
