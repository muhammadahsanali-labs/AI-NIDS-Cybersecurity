import streamlit as st
import sqlite3
import pandas as pd
import time
import plotly.express as px

# -------------------------------------------------------------
# PHASE 12: Streamlit Security Operations Center (SOC) UI
# -------------------------------------------------------------

st.set_page_config(
    page_title="AI-NIDS SOC Console",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-NIDS: Real-Time Security Operations Center")
st.caption("AI-Powered Behavioral Intrusion Detection, Risk Scoring & Explainable Forensics")

def load_incidents():
    try:
        conn = sqlite3.connect('incidents.db')
        query = "SELECT * FROM incidents ORDER BY id DESC"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

placeholder = st.empty()
render_counter = 0

while True:
    df = load_incidents()
    render_counter += 1  # Unique key counter to prevent StreamlitDuplicateElementId
    
    with placeholder.container():
        if df.empty:
            st.info("ℹ️ No incidents logged yet in 'incidents.db'. Start 'sudo python3 live_nids.py' and simulate traffic to view live alerts.")
        else:
            total_events = len(df)
            medium_threats = len(df[df['risk_level'] == 'MEDIUM'])
            critical_threats = len(df[df['risk_level'] == 'CRITICAL'])
            
            kpi1, kpi2, kpi3 = st.columns(3)
            kpi1.metric("Total Logged Incidents", total_events)
            kpi2.metric("Medium Risk Alerts (PortScan)", medium_threats, delta=f"{medium_threats} alerts", delta_color="off")
            kpi3.metric("Critical Risk Alerts (DDoS)", critical_threats, delta=f"{critical_threats} alerts", delta_color="inverse")
            
            st.divider()
            
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                st.subheader("📊 Threat Distribution")
                pie_fig = px.pie(
                    df, 
                    names='attack_type', 
                    color='attack_type',
                    color_discrete_map={'Normal': '#2ecc71', 'PortScan': '#f39c12', 'DDoS': '#e74c3c'},
                    hole=0.4
                )
                pie_fig.update_layout(margin=dict(l=20, r=20, t=30, b=20))
                st.plotly_chart(pie_fig, key=f"pie_chart_{render_counter}")
                
            with col_chart2:
                st.subheader("📈 Bandwidth Spike Timeline (Bytes/sec)")
                line_fig = px.line(
                    df, 
                    x='timestamp', 
                    y='rate_bytes_sec', 
                    color='attack_type',
                    color_discrete_map={'Normal': '#2ecc71', 'PortScan': '#f39c12', 'DDoS': '#e74c3c'},
                    markers=True
                )
                line_fig.update_layout(margin=dict(l=20, r=20, t=30, b=20))
                st.plotly_chart(line_fig, key=f"line_chart_{render_counter}")
                
            st.divider()
            
            st.subheader("📋 Recent Forensic Incident Logs")
            
            st.dataframe(
                df[['id', 'timestamp', 'target_port', 'packet_count', 'rate_bytes_sec', 'attack_type', 'risk_level', 'evidence']],
                height=320
            )
            
    time.sleep(2)
