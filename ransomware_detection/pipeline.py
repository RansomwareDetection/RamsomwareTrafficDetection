import time
import torch
import pandas as pd
import numpy
from scapy.all import sniff
import joblib  # For loading scaler
from modules.file_activity_monitor import start_file_observer
from modules.network_traffic_monitor import gather_metrics, process_sniffed_packets
from modules.anomaly_detection import detect_anomalies
from modules.logger import initialize_csv, log_to_csv
from modules.malware_detection import MalwareDetectionModel  # Importing model class

# Updated feature list
FEATURES = [
    ' ACK Flag Count', ' Fwd Header Length.1', ' Avg Bwd Segment Size', ' Avg Fwd Segment Size',
    ' Average Packet Size', ' Down/Up Ratio', ' ECE Flag Count', ' CWE Flag Count', ' URG Flag Count',
    ' PSH Flag Count', 'Fwd Packets/s', ' RST Flag Count', ' SYN Flag Count', 'FIN Flag Count',
    ' Max Packet Length', ' Min Packet Length'
]

def load_malware_model():
    """Load the pretrained malware detection model and scaler."""
    try:
        # Load the trained model
        model = MalwareDetectionModel()
        model.load_state_dict(torch.load("C:\KMIT\PS\Ransomware Detection\improved_model.pth"))  # Ensure model.pth exists and matches architecture
        model.eval()  # Set the model to evaluation mode

        # Load the scaler
        scaler = joblib.load("C:\KMIT\PS\Ransomware Detection\improved_scaler.pkl")

        print("Malware detection model and scaler loaded successfully.")
        return model, scaler
    except FileNotFoundError:
        print("Model or scaler file not found. Please ensure 'model.pth' and 'model_scaler.pkl' are available.")
    except Exception as e:
        print(f"Error loading malware detection model or scaler: {e}")
    return None, None

def use_model_on_anomalies(filtered_data, model, scaler):
    """Filter the anomaly data and make predictions using the malware detection model."""
    try:
        # Ensure all required features are present in the data
        if not all(feature in filtered_data.columns for feature in FEATURES):
            raise ValueError("Filtered data is missing required features for the model.")

        # Select and scale the relevant features
        filtered_data = filtered_data[FEATURES].dropna()
        scaled_features = scaler.transform(filtered_data)

        # Convert to tensor and make predictions
        input_tensor = torch.tensor(scaled_features, dtype=torch.float32)
        predictions = torch.sigmoid(model(input_tensor)).round()  # Binary predictions

        # Detach the tensor and convert it to a NumPy array
        predictions_np = predictions.detach().numpy()
        print(f"Predictions on anomalies: {predictions_np}")

        return predictions_np
    except Exception as e:
        print(f"Error using malware detection model on anomalies: {e}")
        return None

def execute_pipeline():
    """Main execution pipeline for ransomware detection."""
    # Initialize the CSV for logging ransomware activities
    initialize_csv("ransomware_activities.csv")
    # Load the malware detection model and scaler
    model, scaler = load_malware_model()
    if model is None or scaler is None:
        print("Malware detection model or scaler could not be loaded. Exiting pipeline.")
        return

    # Start file activity monitoring
    handler, observer = start_file_observer("C:\KMIT\PS\Ransomware Detection\Integration")
    
    # while True:
    try:
        # Capture network packets
        packets = sniff(count=100, timeout=1000)  # Adjust count and timeout as necessary
        if packets:
            # Process the captured packets
            processed_packets = process_sniffed_packets(packets)

            # Log metrics to the CSV
            for packet_data in processed_packets:
                activity_data = gather_metrics(handler, packet_data)
                log_to_csv(activity_data)

            # Detect anomalies
            anomaly_timestamps = detect_anomalies("ransomware_activities.csv")
            if anomaly_timestamps:
                print(f"Anomalies detected at timestamps: {anomaly_timestamps}")
                
                # Extract data for these timestamps
                anomaly_data = pd.read_csv("ransomware_activities.csv", parse_dates=["Timestamp"], index_col="Timestamp")
                filtered_anomaly_data = anomaly_data.loc[anomaly_timestamps, FEATURES].dropna()

                if not filtered_anomaly_data.empty:
                    predictions = use_model_on_anomalies(filtered_anomaly_data, model, scaler)
                    if predictions is not None:
                        print("Malware detection results processed.")
            else:
                print("No anomalies detected or anomaly detection failed.")


        else:
            print("No packets captured in this cycle.")

        # Sleep before the next iteration
        # time.sleep(10)

    except KeyboardInterrupt:
        print("Pipeline execution interrupted by user.")
    except Exception as e:
        print(f"An error occurred in the pipeline: {e}")

if __name__ == "__main__":
    execute_pipeline()
