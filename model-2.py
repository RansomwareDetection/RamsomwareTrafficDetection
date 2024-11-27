import scapy.all as scapy
import time
from collections import defaultdict
import os
from datetime import datetime

# Configuration for detection thresholds
THRESHOLDS = {
    'MAX_FRAME_SIZE': 1518,  # Ethernet standard maximum frame size
    'PORT_SCAN_THRESHOLD': 20,  # NIST recommended threshold
    'SYN_FLOOD_THRESHOLD': 200,  # More conservative SYN flood detection
    'DNS_QUERY_THRESHOLD': 100,  # Adjusted DNS query threshold
    'PACKET_FLOOD_THRESHOLD': 200,  # Higher threshold for packet count
    'OBSERVATION_WINDOW': 120  # Seconds for tracking attempts
}

# Advanced threat tracking
class NetworkThreatDetector:
    def __init__(self):
        self.reset_tracking_structures()
    
    def reset_tracking_structures(self):
        # Use more robust tracking mechanisms
        self.port_scan_attempts = defaultdict(lambda: {
            'ports': defaultdict(int),
            'timestamp': datetime.now()
        })
        self.syn_flood_attempts = defaultdict(lambda: {
            'count': 0,
            'timestamp': datetime.now()
        })
        self.dns_query_attempts = defaultdict(lambda: {
            'count': 0,
            'timestamp': datetime.now()
        })
        self.packet_count = defaultdict(lambda: {
            'count': 0,
            'timestamp': datetime.now()
        })
        self.suspicious_data = []

    def is_within_observation_window(self, tracked_item):
        """Check if item is within observation window"""
        return (datetime.now() - tracked_item['timestamp']).total_seconds() < THRESHOLDS['OBSERVATION_WINDOW']

    def packet_callback(self, packet):
        # Advanced packet size detection
        if len(packet) > THRESHOLDS['MAX_FRAME_SIZE']:
            self.log_suspicious_packet(packet, "Oversized Frame")
        
        # Enhanced port scan detection
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            ip_src = packet[scapy.IP].src
            port_dst = packet[scapy.TCP].dport
            
            if not self.is_within_observation_window(self.port_scan_attempts[ip_src]):
                self.port_scan_attempts[ip_src] = {
                    'ports': defaultdict(int),
                    'timestamp': datetime.now()
                }
            
            # Track port attempts
            self.port_scan_attempts[ip_src]['ports'][port_dst] += 1
            
            if len(self.port_scan_attempts[ip_src]['ports']) > THRESHOLDS['PORT_SCAN_THRESHOLD']:
                self.log_suspicious_packet(packet, "Potential Port Scan")
        
        # SYN Flood Detection with more robust tracking
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].flags == 'S':  # SYN flag
                ip_src = packet[scapy.IP].src
                
                if not self.is_within_observation_window(self.syn_flood_attempts[ip_src]):
                    self.syn_flood_attempts[ip_src] = {
                        'count': 0,
                        'timestamp': datetime.now()
                    }
                
                self.syn_flood_attempts[ip_src]['count'] += 1
                
                if self.syn_flood_attempts[ip_src]['count'] > THRESHOLDS['SYN_FLOOD_THRESHOLD']:
                    self.log_suspicious_packet(packet, "Potential SYN Flood")
        
        # DNS Amplification Detection
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP) and packet.haslayer(scapy.DNS):
            if packet[scapy.DNS].qr == 0:  # Query packet
                ip_src = packet[scapy.IP].src
                
                if not self.is_within_observation_window(self.dns_query_attempts[ip_src]):
                    self.dns_query_attempts[ip_src] = {
                        'count': 0,
                        'timestamp': datetime.now()
                    }
                
                self.dns_query_attempts[ip_src]['count'] += 1
                
                if self.dns_query_attempts[ip_src]['count'] > THRESHOLDS['DNS_QUERY_THRESHOLD']:
                    self.log_suspicious_packet(packet, "Potential DNS Amplification")
        
        # Advanced Packet Flooding Detection
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            
            if not self.is_within_observation_window(self.packet_count[ip_src]):
                self.packet_count[ip_src] = {
                    'count': 0,
                    'timestamp': datetime.now()
                }
            
            self.packet_count[ip_src]['count'] += 1
            
            if self.packet_count[ip_src]['count'] > THRESHOLDS['PACKET_FLOOD_THRESHOLD']:
                self.log_suspicious_packet(packet, "Packet Flooding")
        
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                if packet.haslayer(scapy.Raw):
                    try:
                        payload = packet[scapy.Raw].load.decode(errors="ignore")
                        
                        sql_injection_patterns = [
                            "SELECT", "UNION", "DROP", "DELETE", 
                            "INSERT", "TRUNCATE", "--", ";"
                        ]
                        xss_patterns = [
                            "<script>", "javascript:", 
                            "onerror=", "onload=", 
                            "eval(", "document.cookie"
                        ]
                        
                        if any(pattern in payload.upper() for pattern in sql_injection_patterns):
                            self.log_suspicious_packet(packet, "Potential SQL Injection")
                        
                        if any(pattern in payload.lower() for pattern in xss_patterns):
                            self.log_suspicious_packet(packet, "Potential XSS Attempt")
                    
                    except Exception as e:
                        pass

    def log_suspicious_packet(self, packet, reason):
        """Log suspicious packets with reason"""
        suspicious_entry = {
            'packet': packet,
            'reason': reason,
            'timestamp': datetime.now()
        }
        self.suspicious_data.append(suspicious_entry)

    def capture_and_analyze_packets(self):
        """Capture and analyze network packets"""
        try:
            self.reset_tracking_structures()
            
            scapy.sniff(prn=self.packet_callback, store=0, timeout=THRESHOLDS['OBSERVATION_WINDOW'])
            
            if self.suspicious_data:
                self.save_suspicious_data()
        
        except Exception as e:
            print(f"Capture error: {e}")

    def save_suspicious_data(self):
        """Save suspicious packets with more detailed logging"""
        temp_dir = "suspicious_data"
        os.makedirs(temp_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = os.path.join(temp_dir, f"suspicious_data_{timestamp}.pcap")
        
        packets_to_save = [entry['packet'] for entry in self.suspicious_data]
        
        try:
            scapy.wrpcap(pcap_filename, packets_to_save)
            
            log_filename = pcap_filename.replace('.pcap', '.log')
            with open(log_filename, 'w') as log_file:
                for entry in self.suspicious_data:
                    log_file.write(f"Timestamp: {entry['timestamp']}\n")
                    log_file.write(f"Reason: {entry['reason']}\n\n")
            
            print(f"Suspicious data saved to {pcap_filename}")
            print(f"Suspicious data log saved to {log_filename}")
        
        except Exception as e:
            print(f"Error saving suspicious data: {e}")

detector = NetworkThreatDetector()
detector.capture_and_analyze_packets()