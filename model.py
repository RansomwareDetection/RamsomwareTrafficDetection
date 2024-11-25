import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Load the dataset
data = pd.read_csv("Android_Ransomeware.csv")

# Step 2: Select columns that are relevant to network traffic
selected_columns = [ ' ACK Flag Count', ' Fwd Header Length.1', ' Avg Bwd Segment Size', ' Avg Fwd Segment Size', ' Average Packet Size', ' Down/Up Ratio', ' ECE Flag Count', ' CWE Flag Count', ' URG Flag Count', ' PSH Flag Count', 'Fwd Packets/s', ' RST Flag Count', ' SYN Flag Count', 'FIN Flag Count', ' Packet Length Variance', ' Packet Length Std', ' Packet Length Mean', ' Max Packet Length', ' Min Packet Length', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Idle Max', ' Idle Std', 'Idle Mean', ' Active Min', ' Active Max','Active Std']

data['Label'] = data['Label'].apply(lambda x: 0 if x != 'RansomBO' else 1)


# Step 3: Select the features (X) and target (y)
X = data[selected_columns[:-1]]  # All columns except 'Label'
y = data['Label']

# Step 4: Convert all columns to numeric and handle missing values
X = X.apply(pd.to_numeric, errors='coerce')  # Convert to numeric and set invalid values to NaN
X = X.fillna(X.mean())  # Fill NaN values with column means

# Step 5: Encode the string labels into numeric values
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)  # Converts strings to integers

# Step 6: Feature Scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 7: Reshape the input data to fit CNN (batch_size, channels, height, width)
X_scaled = X_scaled.reshape(X_scaled.shape[0], 1, X_scaled.shape[1], 1)  # (N, C, H, W)

# Step 8: Split the data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42)

# Step 9: Convert the data into PyTorch tensors
X_train_tensor = torch.tensor(X_train, dtype=torch.float32)
X_test_tensor = torch.tensor(X_test, dtype=torch.float32)
y_train_tensor = torch.tensor(y_train, dtype=torch.long)
y_test_tensor = torch.tensor(y_test, dtype=torch.long)

# Step 10: Define the CNN Model
class MalwareDetectionCNN(nn.Module):
    def __init__(self):
        super(MalwareDetectionCNN, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=32, kernel_size=(3, 1))
        self.pool = nn.MaxPool2d(kernel_size=(2, 1))
        self.conv2 = nn.Conv2d(in_channels=32, out_channels=64, kernel_size=(3, 1))
        self.dropout = nn.Dropout(p=0.3)
        # self.bn1 = nn.BatchNorm2d(32)
        # self.bn2 = nn.BatchNorm2d(64)

        # Calculate the size of the flattened input after conv and pooling layers
        self.flatten_size = self._get_flatten_size(X_train_tensor)
        
        self.fc1 = nn.Linear(self.flatten_size, 64)
        self.fc2 = nn.Linear(64, len(np.unique(y_encoded)))
        self.relu = nn.ReLU()
        self.leakyrelu = nn.LeakyReLU()

    def _get_flatten_size(self, sample_input):
        with torch.no_grad():
            x = self.conv1(sample_input)
            x = self.pool(x)
            x = self.conv2(x)
            x = self.pool(x)
            x = x.view(x.size(0), -1)  # Flatten
        return x.size(1)  # Get the flattened size of a single sample

    def forward(self, x):
        x = self.leakyrelu(self.conv1(x))
        x = self.pool(x)
        x = self.leakyrelu(self.conv2(x))
        x = self.pool(x)
        x = x.view(x.size(0), -1)  # Flatten the output
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.fc2(x)
        return x

# Step 11: Initialize the neural network, define loss function and optimizer
model = MalwareDetectionCNN()
criterion = nn.CrossEntropyLoss()  # For multi-class classification
optimizer = torch.optim.Adam(model.parameters(), lr=0.0001)

# Step 12: Train the Neural Network
num_epochs = 20
for epoch in range(num_epochs):
    outputs = model(X_train_tensor)
    loss = criterion(outputs, y_train_tensor)

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    if (epoch + 1) % 2 == 0:
        print(f'Epoch [{epoch + 1}/{num_epochs}], Loss: {loss.item():.4f}')

# Step 13: Evaluate the model on the test set
with torch.no_grad():
    test_outputs = model(X_test_tensor)
    _, predicted = torch.max(test_outputs, 1)
    accuracy = (predicted == y_test_tensor).sum().item() / y_test_tensor.size(0)
    print(f'Accuracy on the test set: {accuracy * 100:.2f}%')

# Step 14: Confusion matrix
cm = confusion_matrix(y_test_tensor, predicted)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=label_encoder.classes_)
disp.plot()
plt.show()

# Step 15: Inverse transform predicted labels
predicted_labels = label_encoder.inverse_transform(predicted.numpy())
