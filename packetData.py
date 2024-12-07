import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from scipy.stats import zscore

# Load data
csv_file = "ransomware_activities.csv"
data = pd.read_csv(csv_file, parse_dates=["Timestamp"], index_col="Timestamp")

feature = "CPU Usage (%)"
data = data[[feature]].dropna()

scaler = MinMaxScaler(feature_range=(0, 1))
data_scaled = scaler.fit_transform(data)
data["Scaled"] = data_scaled

window_size = 10  
data["Moving_Avg"] = data["Scaled"].rolling(window=window_size).mean()
data["Rolling_Var"] = data["Scaled"].rolling(window=window_size).var()

data["Z_Score"] = zscore(data["Scaled"].fillna(0))

threshold = 2  
data["Anomaly"] = np.where(data["Z_Score"].abs() > threshold, 1, 0)

plt.figure(figsize=(12, 6))
plt.plot(data.index, data["Scaled"], label="Scaled Data", alpha=0.5)
plt.plot(data.index, data["Moving_Avg"], label="Moving Average", linestyle="--", color="orange")
plt.scatter(data.index[data["Anomaly"] == 1], data["Scaled"][data["Anomaly"] == 1], color="red", label="Anomalies")
plt.title(f"Trend Analysis for {feature}")
plt.xlabel("Timestamp")
plt.ylabel("Scaled Value")
plt.legend()
plt.show()

anomaly_ranges = data[data["Anomaly"] == 1].index
print("Anomaly Detected at:")
print(anomaly_ranges)

if not anomaly_ranges.empty:
    start_idx, end_idx = anomaly_ranges[0], anomaly_ranges[-1]
    plt.figure(figsize=(12, 6))
    plt.plot(data[start_idx:end_idx].index, data["Scaled"][start_idx:end_idx], label="Scaled Data")
    plt.plot(data[start_idx:end_idx].index, data["Moving_Avg"][start_idx:end_idx], label="Moving Average", linestyle="--", color="orange")
    plt.scatter(data[start_idx:end_idx].index[data["Anomaly"] == 1], data["Scaled"][start_idx:end_idx][data["Anomaly"] == 1], color="red", label="Anomalies")
    plt.title(f"Zoomed Trend Analysis ({start_idx} to {end_idx})")
    plt.xlabel("Timestamp")
    plt.ylabel("Scaled Value")
    plt.legend()
    plt.show()
else:
    print("No significant anomalies detected.")
