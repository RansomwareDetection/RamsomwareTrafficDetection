import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from scipy.stats import zscore

FEATURES = [
    ' ACK Flag Count', ' Fwd Header Length.1', ' Avg Bwd Segment Size', ' Avg Fwd Segment Size',
    ' Average Packet Size', ' Down/Up Ratio', ' ECE Flag Count', ' CWE Flag Count', ' URG Flag Count',
    ' PSH Flag Count', 'Fwd Packets/s', ' RST Flag Count', ' SYN Flag Count', 'FIN Flag Count',
    ' Max Packet Length', ' Min Packet Length'
]

def detect_anomalies(data_path):
    try:
        # Load and preprocess data for anomaly detection
        data = pd.read_csv(data_path, parse_dates=["Timestamp"], index_col="Timestamp")
        print(data.columns)
        # Ensure required features are present
        missing_features = [feature for feature in FEATURES if feature not in data.columns]
        if missing_features:
            print(f"Error: Missing columns in the data: {missing_features}")
            return []  # Return an empty list if required features are missing

        # Filter the data for the selected features and drop rows with missing values
        data = data[FEATURES].dropna()

        # Scale the data using Min-Max Scaling
        scaler = MinMaxScaler(feature_range=(0, 1))
        data_scaled = scaler.fit_transform(data)
        scaled_data = pd.DataFrame(data_scaled, columns=FEATURES, index=data.index)

        # Calculate the Z-score for anomaly detection
        scaled_data["Z_Score"] = zscore(scaled_data.fillna(0).mean(axis=1))

        # Identify anomalies where Z-score exceeds threshold
        threshold = 2
        scaled_data["Anomaly"] = np.where(scaled_data["Z_Score"].abs() > threshold, 1, 0)

        # Filter data where anomalies are detected
        anomalies = scaled_data[scaled_data["Anomaly"] == 1]

        if not anomalies.empty:
            # Save anomalies to CSV
            anomalies.to_csv("anomaly_data.csv")
            print("Anomalies detected and saved to anomaly_data.csv")
            
            # Return the timestamps of detected anomalies
            return anomalies.index.tolist()
        else:
            print("No anomalies detected.")
            return []  # Return an empty list if no anomalies are detected

    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return []  # Return an empty list on failure
