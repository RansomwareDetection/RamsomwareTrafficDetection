import pandas as pd
from scapy.all import sniff, IP, TCP, wrpcap

packets_list = []
raw_packets_list = []  

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        timestamp = packet.time
        flags = packet[TCP].flags
        syn_flag = 1 if 'S' in flags else 0
        ack_flag = 1 if 'A' in flags else 0
        fin_flag = 1 if 'F' in flags else 0
        rst_flag = 1 if 'R' in flags else 0
        psh_flag = 1 if 'P' in flags else 0
        urg_flag = 1 if 'U' in flags else 0
        # flow_duration = packet.time - packet.sniff_timestamp
        
        
        packet_data = {
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Protocol': protocol,
            'Timestamp': timestamp,
            'Flags': flags,
            'SYN Flag': syn_flag,
            'ACK Flag': ack_flag,
            'FIN Flag': fin_flag,
            'RST Flag': rst_flag,
            'PSH Flag': psh_flag,
            'URG Flag': urg_flag,
            # 'Flow Duration': flow_duration
        }
        
        return packet_data
      
def capture_packets(packet):
    packet_data = process_packet(packet)
    if packet_data:
        packets_list.append(packet_data)
        raw_packets_list.append(packet)  

sniff(iface='Wi-Fi', prn=capture_packets, filter="tcp", count=100)

df = pd.DataFrame(packets_list)

print(df.head())

wrpcap("captured_traffic.pcap", raw_packets_list)  
