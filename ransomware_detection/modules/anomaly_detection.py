import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from scipy.stats import zscore
import matplotlib.pyplot as plt

def detect_anomalies(data_path):
    # Load and preprocess data for anomaly detection
    data = pd.read_csv(data_path, parse_dates=["Timestamp"], index_col="Timestamp")
    
    # List available columns to understand the data structure
    print("Available columns in the CSV:", data.columns)
    
    # Define a list of potential features that might indicate anomalous behavior
    # Based on network traffic data
    features = ["ACK Flag Count", "SYN Flag Count", "Fwd Packets/s", "Avg Fwd Segment Size", 
                "Avg Bwd Segment Size", "Average Packet Size", "Min Packet Length", "Max Packet Length"]
    
    # Make sure these columns exist in the dataset
    for feature in features:
        if feature not in data.columns:
            print(f"Error: Column '{feature}' not found in the data.")
            return
    
    # Filter the data for selected features and drop rows with missing values
    data = data[features].dropna()

    # Scale the data using Min-Max Scaling
    scaler = MinMaxScaler(feature_range=(0, 1))
    data_scaled = scaler.fit_transform(data)
    scaled_data = pd.DataFrame(data_scaled, columns=features, index=data.index)

    # Calculate moving averages and rolling variances for each feature
    window_size = 10
    for feature in features:
        scaled_data[f"{feature}_Moving_Avg"] = scaled_data[feature].rolling(window=window_size).mean()
        scaled_data[f"{feature}_Rolling_Var"] = scaled_data[feature].rolling(window=window_size).var()

    # Calculate the Z-score for anomaly detection
    scaled_data["Z_Score"] = zscore(scaled_data.fillna(0).mean(axis=1))  # Use mean across features for Z-score

    # Identify anomalies where Z-score exceeds threshold
    threshold = 2
    scaled_data["Anomaly"] = np.where(scaled_data["Z_Score"].abs() > threshold, 1, 0)

    # Filter data where anomalies are detected
    anomalies = scaled_data[scaled_data["Anomaly"] == 1]

    # Filter data based on Z-score range from -10 to +10
    anomaly_range = anomalies[(anomalies["Z_Score"] >= -10) & (anomalies["Z_Score"] <= 10)]

    # Save anomalies to CSV
    anomaly_range.to_csv("anomaly_data.csv")

    print("Anomalies saved to anomaly_data.csv")

    # Plot the results
    plt.figure(figsize=(12, 6))
    for feature in features:
        plt.plot(scaled_data.index, scaled_data[feature], label=f"Scaled {feature}", alpha=0.7)
    plt.plot(scaled_data.index, scaled_data["Z_Score"], label="Z-Score", color="black", linestyle="--")
    plt.scatter(scaled_data.index[scaled_data["Anomaly"] == 1], scaled_data["Z_Score"][scaled_data["Anomaly"] == 1],
                color="red", label="Anomalies", zorder=5)
    plt.title("Anomaly Detection in Network Traffic Data")
    plt.xlabel("Timestamp")
    plt.ylabel("Scaled Value / Z-Score")
    plt.legend()
    plt.show()

    # Print the anomalies detected
    anomaly_ranges = anomaly_range.index
    print("Anomalies Detected at:")
    print(anomaly_ranges)

