import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
import tensorflow as tf

# Configure GPU memory if available to prevent crashing on low-resource machines
physical_devices = tf.config.list_physical_devices('GPU')
if physical_devices:
    try:
        for dev in physical_devices:
            tf.config.experimental.set_memory_growth(dev, True)
    except:
        pass

def generate_synthetic_arp_data(num_samples=10000, time_steps=5):
    """
    Generates a fast, lightweight synthetic dataset mimicking CICIDS2017 ARP Spoofing features.
    Features: [Inter-packet arrival time (ms), ARP Request/Reply Ratio, Packet Frequency]
    """
    print("Generating synthetic ARP sequence data...")
    X = []
    y = []
    
    # 80% Normal traffic, 20% Attack traffic
    for i in range(num_samples):
        is_attack = np.random.rand() > 0.8
        sequence = []
        for t in range(time_steps):
            if is_attack:
                # Attack: Very fast arrival time, heavy reply ratio, high frequency
                dt = np.random.uniform(0.1, 5.0) 
                ratio = np.random.uniform(0.0, 0.2) # Mostly replies, few requests
                freq = np.random.uniform(50, 200)
            else:
                # Normal: Normal arrival time, balanced ratio, low frequency
                dt = np.random.uniform(10.0, 100.0)
                ratio = np.random.uniform(0.8, 1.2) # Balanced
                freq = np.random.uniform(1, 10)
            
            sequence.append([dt, ratio, freq])
            
        X.append(sequence)
        y.append(1 if is_attack else 0)
        
    return np.array(X), np.array(y)

def build_lstm_model(input_shape):
    """Builds the LSTM model architecture."""
    model = Sequential([
        LSTM(32, return_sequences=True, input_shape=input_shape),
        Dropout(0.2),
        LSTM(16),
        Dropout(0.2),
        Dense(8, activation='relu'),
        Dense(1, activation='sigmoid') # Binary classification (Normal vs Attack)
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def main():
    TIME_STEPS = 5
    FEATURES = 3
    
    # 1. Generate Data
    X, y = generate_synthetic_arp_data(num_samples=5000, time_steps=TIME_STEPS)
    print(f"Data generated. Shape: {X.shape}")
    
    # 2. Preprocess (Scale the 3D data)
    # We flatten to 2D for scaling, then reshape back to 3D
    scaler = MinMaxScaler()
    X_flattened = X.reshape(-1, FEATURES)
    X_scaled = scaler.fit_transform(X_flattened)
    X_scaled = X_scaled.reshape(-1, TIME_STEPS, FEATURES)
    
    # 3. Split Dataset
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    # 4. Build and Train
    print("Building LSTM model...")
    model = build_lstm_model((TIME_STEPS, FEATURES))
    model.summary()
    
    print("Training model...")
    model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_test, y_test), verbose=1)
    
    # 5. Evaluate
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"\nModel Test Accuracy: {accuracy * 100:.2f}%")
    
    # 6. Save Model
    model_path = os.path.join(os.path.dirname(__file__), 'arp_lstm_model.h5')
    model.save(model_path)
    print(f"Model saved successfully to {model_path}")

if __name__ == "__main__":
    main()
