import csv
import time
from datetime import datetime
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import hashlib
import scapy.all as scapy
from scapy.all import sniff

# Output CSV file
output_file = "ransomware_activities.csv"

# Define activities to monitor
activities = [
    "Timestamp",
    "Mass File Modification",
    "Bulk Encryption",
    "File Renaming",
    "Unexpected File Deletion",
    "Creation of Ransom Notes",
    "CPU Usage (%)",
    "Disk Usage (%)",
    "Outbound Traffic to Unknown IPs",
    "Port Scanning Attempts",
    "Suspicious Processes",
    "Shadow Copy Deletion Attempts",
    "Source MAC",
    "Destination MAC",
    "Source IP",
    "Destination IP",
    "Protocol",
    "TTL",
    "Source Port",
    "Destination Port",
    "Packet Length"
]

# Initialize the CSV file
def initialize_csv(file_name):
    with open(file_name, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(activities)

# Log real-time data to CSV
def log_to_csv(activity_data):
    with open(output_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(activity_data)

# Monitor file system activity
class FileActivityHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_renames = 0
        self.file_modifications = 0
        self.file_deletions = 0
        self.file_creations = 0
        self.hashed_files = {}

    def on_modified(self, event):
        if event.is_directory:
            return
        self.file_modifications += 1
        self.detect_encryption(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.file_creations += 1

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_deletions += 1

    def on_moved(self, event):
        self.file_renames += 1

    def detect_encryption(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                if file_path in self.hashed_files:
                    if self.hashed_files[file_path] != file_hash:
                        print(f"Encryption detected: {file_path}")
                self.hashed_files[file_path] = file_hash
        except Exception:
            pass

# Start file observer
def start_file_observer(path):
    handler = FileActivityHandler()
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    return handler, observer

# Detect outbound traffic to unknown IPs
def detect_outbound_traffic():
    unknown_ip_count = 0
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip
                if not ip.startswith(("10.", "172.", "192.")):
                    unknown_ip_count += 1
    except Exception:
        pass
    return unknown_ip_count

# Detect port scanning attempts
def detect_port_scanning():
    try:
        captured_packets = scapy.sniff(timeout=5, filter="tcp")
        port_counts = {}
        for packet in captured_packets:
            if packet.haslayer(scapy.TCP):
                port = packet[scapy.TCP].dport
                port_counts[port] = port_counts.get(port, 0) + 1
        return sum(1 for count in port_counts.values() if count > 10)
    except Exception:
        return 0

# Detect shadow copy deletion attempts
def detect_shadow_copy_deletion():
    try:
        subprocess.check_output("vssadmin list shadows", shell=True, stderr=subprocess.DEVNULL)
        return 0
    except subprocess.CalledProcessError:
        return 1

# Check for suspicious processes
def check_suspicious_processes():
    suspicious_keywords = ["powershell", "cmd", "vssadmin"]
    suspicious_count = 0
    for proc in psutil.process_iter(['name']):
        try:
            if any(keyword in proc.info['name'].lower() for keyword in suspicious_keywords):
                suspicious_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_count

# Process captured packets
def process_packet(packet):
    data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "Source MAC": packet.src if packet.haslayer("Ethernet") else None,
        "Destination MAC": packet.dst if packet.haslayer("Ethernet") else None,
        "Source IP": packet[0][1].src if packet.haslayer("IP") else None,
        "Destination IP": packet[0][1].dst if packet.haslayer("IP") else None,
        "Protocol": packet[0][1].proto if packet.haslayer("IP") else None,
        "TTL": packet[0][1].ttl if packet.haslayer("IP") else None,
        "Source Port": packet[0][2].sport if packet.haslayer("TCP") or packet.haslayer("UDP") else None,
        "Destination Port": packet[0][2].dport if packet.haslayer("TCP") or packet.haslayer("UDP") else None,
        "Packet Length": len(packet)
    }
    return data

# Gather metrics
def gather_metrics(file_handler, packet_data):
    activity_data = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_handler.file_modifications,
        0,  # Encryption will be incremented within detect_encryption
        file_handler.file_renames,
        file_handler.file_deletions,
        file_handler.file_creations,
        psutil.cpu_percent(interval=1),
        psutil.disk_usage('/').percent,
        detect_outbound_traffic(),
        detect_port_scanning(),
        check_suspicious_processes(),
        detect_shadow_copy_deletion(),
        packet_data.get("Source MAC"),
        packet_data.get("Destination MAC"),
        packet_data.get("Source IP"),
        packet_data.get("Destination IP"),
        packet_data.get("Protocol"),
        packet_data.get("TTL"),
        packet_data.get("Source Port"),
        packet_data.get("Destination Port"),
        packet_data.get("Packet Length")
    ]
    return activity_data

# Main function
if __name__ == "__main__":
    path_to_monitor = "."  # Current directory
    initialize_csv(output_file)
    file_handler, observer = start_file_observer(path_to_monitor)

    print("Monitoring activities and packets. Press Ctrl+C to stop.")
    try:
        sniff(prn=lambda pkt: log_to_csv(gather_metrics(file_handler, process_packet(pkt))), store=False)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopped monitoring.")
    observer.join()
