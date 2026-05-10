import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
import tensorflow as tf

# Configure GPU memory if available to prevent crashing on low-resource machines
physical_devices = tf.config.list_physical_devices('GPU')
if physical_devices:
    try:
        for dev in physical_devices:
            tf.config.experimental.set_memory_growth(dev, True)
    except:
        pass

def generate_synthetic_awid_data(num_samples=10000):
    """
    Generates a fast, lightweight synthetic dataset mimicking AWID3 Impersonation class.
    Features: [RSSI (Signal Strength), Sequence Number Delta, Frame Control Subtype]
    """
    print("Generating synthetic AWID Evil Twin data...")
    X = []
    y = []
    
    # 85% Normal AP Beacons, 15% Evil Twin Beacons
    for i in range(num_samples):
        is_attack = np.random.rand() > 0.85
        
        if is_attack:
            # Attack: Fluctuating or much stronger/weaker RSSI, anomalous seq numbers
            rssi = np.random.uniform(-40, -10) # Rogue AP might be closer/stronger to override
            seq_delta = np.random.uniform(500, 2000) # Jump in sequence numbers
            fc_subtype = 8 # Type 0 (Mgmt), Subtype 8 (Beacon)
        else:
            # Normal: Stable RSSI, sequential seq numbers (delta ~ 1)
            rssi = np.random.uniform(-75, -65)
            seq_delta = np.random.uniform(1, 5) # Slight variations due to dropped packets
            fc_subtype = 8
            
        X.append([rssi, seq_delta, fc_subtype])
        y.append(1 if is_attack else 0)
        
    return np.array(X), np.array(y)

def build_dnn_model(input_dim):
    """Builds the Deep Neural Network architecture."""
    model = Sequential([
        Dense(64, activation='relu', input_dim=input_dim),
        BatchNormalization(),
        Dropout(0.3),
        Dense(32, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid') # Binary classification
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def main():
    # 1. Generate Data
    X, y = generate_synthetic_awid_data(num_samples=10000)
    print(f"Data generated. Shape: {X.shape}")
    
    # 2. Preprocess (Scale data)
    # StandardScaler is better for normally distributed features like RSSI
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 3. Split Dataset
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    # 4. Build and Train
    print("Building DNN model...")
    model = build_dnn_model(X_train.shape[1])
    model.summary()
    
    print("Training model...")
    # Training is extremely fast on small datasets
    model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test), verbose=1)
    
    # 5. Evaluate
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"\nModel Test Accuracy: {accuracy * 100:.2f}%")
    
    # 6. Save Model
    model_path = os.path.join(os.path.dirname(__file__), 'evil_twin_dnn_model.h5')
    model.save(model_path)
    print(f"Model saved successfully to {model_path}")

if __name__ == "__main__":
    main()
