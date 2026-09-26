import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier

st.set_page_config(page_title="AI-NIDS MVP", layout="wide")

st.title("🛡️ AI-Based Network Intrusion Detection System (AI-NIDS)")
st.caption("Proof of Concept MVP — Flow Feature Classification")

# Train Model on Load
@st.cache_resource
def train_nids_model():
    np.random.seed(42)
    n_samples = 1000
    
    normal_data = {
        'Destination_Port': np.random.choice([80, 443, 22, 53], size=n_samples//2),
        'Flow_Duration': np.random.normal(5000, 1000, n_samples//2),
        'Total_Fwd_Packets': np.random.randint(5, 20, n_samples//2),
        'Flow_Bytes_s': np.random.normal(1500, 300, n_samples//2),
        'Label': 0
    }
    
    attack_data = {
        'Destination_Port': np.random.choice([80, 8080, 21, 23], size=n_samples//2),
        'Flow_Duration': np.random.normal(100, 20, n_samples//2),
        'Total_Fwd_Packets': np.random.randint(500, 2000, n_samples//2),
        'Flow_Bytes_s': np.random.normal(80000, 10000, n_samples//2),
        'Label': 1
    }
    
    df = pd.concat([pd.DataFrame(normal_data), pd.DataFrame(attack_data)]).sample(frac=1).reset_index(drop=True)
    X = df[['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Flow_Bytes_s']]
    y = df['Label']
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf

model = train_nids_model()

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("⚙️ Simulate Network Packet Features")
    port = st.number_input("Destination Port", value=80)
    duration = st.number_input("Flow Duration (ms)", value=80.0)
    packets = st.number_input("Total Forward Packets", value=1500)
    bytes_s = st.number_input("Flow Bytes/sec", value=95000.0)

    if st.button("🔍 Analyze Traffic Flow"):
        test_df = pd.DataFrame([{
            'Destination_Port': port,
            'Flow_Duration': duration,
            'Total_Fwd_Packets': packets,
            'Flow_Bytes_s': bytes_s
        }])
        
        prediction = model.predict(test_df)[0]
        proba = model.predict_proba(test_df)[0]
        
        with col2:
            st.subheader("📊 Detection Verdict")
            if prediction == 1:
                st.error("🚨 CRITICAL ALERT: Malicious Attack Traffic Detected!")
                st.metric("Attack Confidence", f"{proba[1]*100:.1f}%")
            else:
                st.success("✅ OK: Normal Network Traffic")
                st.metric("Normal Confidence", f"{proba[0]*100:.1f}%")
