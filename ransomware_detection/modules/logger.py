# logger.py
import csv
from datetime import datetime

def initialize_csv(file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Timestamp', ' ACK Flag Count', ' SYN Flag Count', 'FIN Flag Count', ' PSH Flag Count',
            ' RST Flag Count', ' URG Flag Count', ' Fwd Header Length.1', ' Avg Fwd Segment Size',
            ' Avg Bwd Segment Size', ' Average Packet Size', ' Min Packet Length', ' Max Packet Length',
            ' Down/Up Ratio', ' ECE Flag Count', ' CWE Flag Count', 'Fwd Packets/s'
        ])

def log_to_csv(data):
    with open('ransomware_activities.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)
