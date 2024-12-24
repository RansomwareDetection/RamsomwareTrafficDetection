# pipeline.py
from scapy.all import sniff  # Correct way to import sniff

from modules.file_activity_monitor import start_file_observer
from modules.network_traffic_monitor import gather_metrics, process_sniffed_packets
from modules.anomaly_detection import detect_anomalies
from modules.malware_detection import train_malware_detection_model
from modules.logger import initialize_csv, log_to_csv
import time

def execute_pipeline():
    # Initialize the CSV for logging ransomware activities
    initialize_csv("ransomware_activities.csv")
    
    # Step 1: Start file activity monitoring
    handler, observer = start_file_observer("C:/Users/darsh/Documents")
    
    # Step 2: Continuous monitoring and anomaly detection
    while True:
        try:
            # Capture multiple packets during sniffing
            packets = sniff(count=100, timeout=1000)  # Adjust count and timeout as necessary
            if packets:
                # Process the captured packets into a structured format
                processed_packets = process_sniffed_packets(packets)

                # Log each packet's activity to the CSV
                for packet_data in processed_packets:
                    activity_data = gather_metrics(handler, packet_data)
                    log_to_csv(activity_data)

                # Run anomaly detection after logging activities
                detect_anomalies("ransomware_activities.csv")
            else:
                print("No packets captured in this cycle.")

            # Sleep for a defined period before the next capture
            time.sleep(10)

        except Exception as e:
            print(f"An error occurred in the pipeline: {e}")

    # Step 3: Train malware detection model (optional, at the end of monitoring)
    train_malware_detection_model()

if __name__ == "__main__":
    execute_pipeline()
