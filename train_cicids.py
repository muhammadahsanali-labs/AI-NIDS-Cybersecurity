import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

print("[*] Training Phase 7 & 8: Multi-Class AI-NIDS Engine...")

np.random.seed(42)
n_samples = 5000

# 1. Normal Traffic
normal = pd.DataFrame({
    'Destination_Port': np.random.choice([80, 443, 53, 22, 123], size=n_samples),
    'Flow_Duration': np.random.uniform(100, 1000, n_samples),
    'Total_Fwd_Packets': np.random.randint(1, 40, n_samples),
    'Flow_Bytes_s': np.random.uniform(50, 10000, n_samples),
    'Label': 'Normal'
})

# 2. PortScan Attack (High port variation, quick small packets)
portscan = pd.DataFrame({
    'Destination_Port': np.random.randint(1, 65535, size=n_samples),
    'Flow_Duration': np.random.uniform(0.1, 20, n_samples),
    'Total_Fwd_Packets': np.random.randint(1, 5, n_samples),
    'Flow_Bytes_s': np.random.uniform(10, 2000, n_samples),
    'Label': 'PortScan'
})

# 3. DDoS Attack (Extreme packet count and high bandwidth usage)
ddos = pd.DataFrame({
    'Destination_Port': np.random.choice([80, 443, 8080], size=n_samples),
    'Flow_Duration': np.random.uniform(500, 2000, n_samples),
    'Total_Fwd_Packets': np.random.randint(100, 3000, n_samples),
    'Flow_Bytes_s': np.random.uniform(100000, 10000000, n_samples),
    'Label': 'DDoS'
})

df = pd.concat([normal, portscan, ddos]).sample(frac=1).reset_index(drop=True)

X = df[['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Flow_Bytes_s']]
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
clf.fit(X_train, y_train)

print("\n[+] --- MULTI-CLASS MODEL EVALUATION ---")
print(classification_report(y_test, clf.predict(X_test)))

joblib.dump(clf, 'nids_model.pkl')
print("[+] Multi-Class Model exported to 'nids_model.pkl' successfully!")
