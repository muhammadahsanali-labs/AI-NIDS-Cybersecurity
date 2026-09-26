import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

print("1. Generating sample CICIDS2017 network flow data...")

# Creating simulated network flow features matching CICIDS2017 structure
np.random.seed(42)
n_samples = 1000

# Normal Traffic Features
normal_data = {
    'Destination_Port': np.random.choice([80, 443, 22, 53], size=n_samples//2),
    'Flow_Duration': np.random.normal(5000, 1000, n_samples//2),
    'Total_Fwd_Packets': np.random.randint(5, 20, n_samples//2),
    'Flow_Bytes_s': np.random.normal(1500, 300, n_samples//2),
    'Label': 0  # 0 = Normal
}

# Attack Traffic Features (e.g., DDoS / Port Scan)
attack_data = {
    'Destination_Port': np.random.choice([80, 8080, 21, 23], size=n_samples//2),
    'Flow_Duration': np.random.normal(100, 20, n_samples//2),  # Very rapid connection times
    'Total_Fwd_Packets': np.random.randint(500, 2000, n_samples//2),  # High volume packet flood
    'Flow_Bytes_s': np.random.normal(80000, 10000, n_samples//2),
    'Label': 1  # 1 = Attack
}

df_normal = pd.DataFrame(normal_data)
df_attack = pd.DataFrame(attack_data)
df = pd.concat([df_normal, df_attack]).sample(frac=1).reset_index(drop=True)

# Separate features (X) and labels (y)
X = df[['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Flow_Bytes_s']]
y = df['Label']

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("2. Training Random Forest Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

print("\n--- MODEL PERFORMANCE ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

print("\n--- TESTING LIVE PACKET INFERENCE ---")
# Testing a suspicious incoming flow (e.g., Port 80, short duration, huge packet count)
suspicious_packet = pd.DataFrame([{
    'Destination_Port': 80,
    'Flow_Duration': 80,
    'Total_Fwd_Packets': 1500,
    'Flow_Bytes_s': 95000
}])

result = model.predict(suspicious_packet)[0]
alert_status = "CRITICAL ALERT: Attack Detected!" if result == 1 else "OK: Normal Traffic"
print(f"Incoming Flow Result -> {alert_status}")
