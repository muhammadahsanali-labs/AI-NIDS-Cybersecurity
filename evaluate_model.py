import time
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

# -------------------------------------------------------------
# PHASE 13: Model Evaluation & Validation Suite
# -------------------------------------------------------------

print("[*] Loading Trained AI-NIDS Model ('nids_model.pkl')...")
model = joblib.load('nids_model.pkl')

print("[*] Generating Synthetic Validation Benchmark Dataset...")
# Generating balanced validation traffic flows representing CICIDS2017 feature ranges
np.random.seed(42)
n_samples = 300

# Normal Traffic Samples
normal_df = pd.DataFrame({
    'Destination_Port': np.random.choice([80, 443, 53, 22], n_samples),
    'Flow_Duration': np.random.uniform(10, 500, n_samples),
    'Total_Fwd_Packets': np.random.randint(1, 10, n_samples),
    'Flow_Bytes_s': np.random.uniform(100, 5000, n_samples),
    'True_Label': 'Normal'
})

# PortScan Samples (Low packets, short duration, distinct port sweeps)
portscan_df = pd.DataFrame({
    'Destination_Port': np.random.randint(1, 65535, n_samples),
    'Flow_Duration': np.random.uniform(0.1, 5, n_samples),
    'Total_Fwd_Packets': np.random.randint(1, 3, n_samples),
    'Flow_Bytes_s': np.random.uniform(10, 500, n_samples),
    'True_Label': 'PortScan'
})

# DDoS Samples (High rate, high packets, concentrated port traffic)
ddos_df = pd.DataFrame({
    'Destination_Port': np.random.choice([80, 443], n_samples),
    'Flow_Duration': np.random.uniform(500, 1000, n_samples),
    'Total_Fwd_Packets': np.random.randint(50, 500, n_samples),
    'Flow_Bytes_s': np.random.uniform(50000, 1000000, n_samples),
    'True_Label': 'DDoS'
})

test_data = pd.concat([normal_df, portscan_df, ddos_df], ignore_index=True)

X_val = test_data[['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Flow_Bytes_s']]
y_true = test_data['True_Label']

# Measure Inference Latency
start_time = time.time()
y_pred = model.predict(X_val)
end_time = time.time()

total_latency = (end_time - start_time) * 1000  # ms
avg_latency_per_sample = total_latency / len(X_val)

print("\n" + "="*60)
print("             EVALUATION & METRICS PERFORMANCE REPORT")
print("="*60)
print(f"Total Validation Samples Evaluated : {len(X_val)}")
print(f"Total Inference Time               : {total_latency:.2f} ms")
print(f"Average Latency per Packet Flow    : {avg_latency_per_sample:.4f} ms")
print("="*60 + "\n")

# Detailed Classification Report
report = classification_report(y_true, y_pred)
print(report)

# Generate & Save Confusion Matrix Plot
labels = ['Normal', 'PortScan', 'DDoS']
cm = confusion_matrix(y_true, y_pred, labels=labels)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
plt.title('AI-NIDS Random Forest Model Confusion Matrix', fontsize=14, fontweight='bold')
plt.xlabel('Predicted Label', fontsize=12)
plt.ylabel('True Label', fontsize=12)
plt.tight_layout()

plt.savefig('confusion_matrix.png', dpi=300)
print("\n[+] Success: Confusion Matrix Saved as 'confusion_matrix.png'!")
