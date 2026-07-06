import pandas as pd
import joblib
import numpy as np
import streamlit as st
from scapy.all import sniff
import subprocess

# ------------------ Initialization & Model Loading ------------------
vpn_model = joblib.load("vpn_full_model.pkl")
service_model = joblib.load("service_full_model.pkl")

service_cols = ["Service_FTP", "Service_HTTP", "Service_TCP", "Service_UDP", "Service_ICMP"]
feature_cols = [
    "packet_count", "byte_count", "min_len", "max_len", "mean_len",
    "proto_tcp", "proto_udp", "proto_icmp",
    "Service_FTP", "Service_HTTP", "Service_TCP", "Service_UDP", "Service_ICMP"
]

# ایجاد حافظه پایدار موقت در استریم‌لیت
if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "live_results" not in st.session_state:
    st.session_state.live_results = []
if "flows" not in st.session_state:
    st.session_state.flows = {}
if "qos_triggered" not in st.session_state:
    st.session_state.qos_triggered = False
# حافظه جدید برای ثبت گزارش حملات بلاک شده
if "attack_logs" not in st.session_state:
    st.session_state.attack_logs = []

# ------------------ Linux Firewall (QoS) Functions ------------------
def apply_linux_qos():
    """Apply Linux Firewall Rules to suppress ICMP Ping Flooding"""
    subprocess.run("sudo iptables -A INPUT -p icmp -m limit --limit 5/sec -j ACCEPT", shell=True)
    subprocess.run("sudo iptables -A INPUT -p icmp -j DROP", shell=True)

def reset_linux_qos():
    """Clear all firewall rules and restore full network capacity"""
    subprocess.run("sudo iptables -F INPUT", shell=True)

# ------------------ Packet Processing Logic ------------------
def detect_service_live(pkt):
    """Detect network service based on active ports"""
    if pkt.haslayer("TCP"):
        ports = [pkt["TCP"].sport, pkt["TCP"].dport]
        if 21 in ports: return "FTP"
        elif 80 in ports: return "HTTP"
        elif 443 in ports: return "TCP"
        elif 5201 in ports: return "TCP"
        return "TCP"
    elif pkt.haslayer("UDP"):
        ports = [pkt["UDP"].sport, pkt["UDP"].dport]
        if 53 in ports: return "UDP"
        elif 5201 in ports: return "UDP"
        return "UDP"
    elif pkt.haslayer("ICMP"):
        return "ICMP"
    return None

def process_live_packet(packet):
    """Process incoming packets, extract features, and log mitigation details"""
    if not packet.haslayer("IP"):
        return
    
    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst
    proto = packet["IP"].proto
    key = (src_ip, dst_ip, proto)
    pkt_len = len(packet)
    
    flows = st.session_state.flows
    if key not in flows:
        flows[key] = {
            "lengths": [],
            "proto_tcp": 0, "proto_udp": 0, "proto_icmp": 0,
            "FTP": 0, "HTTP": 0, "TCP": 0, "UDP": 0, "ICMP": 0
        }
        
    f = flows[key]
    f["lengths"].append(pkt_len)
    
    if packet.haslayer("TCP"): f["proto_tcp"] += 1
    elif packet.haslayer("UDP"): f["proto_udp"] += 1
    elif packet.haslayer("ICMP"): f["proto_icmp"] += 1
    
    service_type = detect_service_live(packet)
    if service_type in f:
        f[service_type] += 1

    lengths = f["lengths"]
    
    # --- DYNAMIC SECURITY & QOS LAYER ---
    if packet.haslayer("ICMP") and len(lengths) > 50:
        if not st.session_state.qos_triggered:
            apply_linux_qos()
            st.session_state.qos_triggered = True
        
        # ثبت مشخصات حمله کننده و وضعیت دفاع موفقیت آمیز در لیست
        attack_entry = {
            "Attacker IP": src_ip,
            "Target IP": dst_ip,
            "Attempted Packets": len(lengths),
            "Defense Status": "🛡️ Successfully Throttled (Dropped via iptables)"
        }
        st.session_state.attack_logs.append(attack_entry)

    features = [
        len(lengths), sum(lengths), min(lengths), max(lengths), np.mean(lengths),
        f["proto_tcp"], f["proto_udp"], f["proto_icmp"],
        f["FTP"], f["HTTP"], f["TCP"], f["UDP"], f["ICMP"]
    ]
    
    if len(lengths) >= 5:
        X_live = pd.DataFrame([features], columns=feature_cols)
        vpn_pred = vpn_model.predict(X_live)[0]
        label = "VPN" if vpn_pred == 1 else "NonVPN"
        service_pred = service_model.predict(X_live[service_cols])[0]
        
        st.session_state.live_results.append({
            "Src IP": src_ip,
            "Dst IP": dst_ip,
            "Label": label,
            "Service": service_pred,
            "Packets Total": len(lengths)
        })

# ------------------ Streamlit User Interface (UI) ------------------
st.title("📊 Intelligent Real-Time Network Traffic Classifier")
st.markdown("### Final Monograph Project - DMVPN Layer 3 & Machine Learning Monitoring")

# Control Buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("🚀 Start Live Capture", use_container_width=True):
        st.session_state.capturing = True
        st.session_state.live_results = []  
        st.session_state.flows = {}
        st.session_state.attack_logs = [] # ریست کردن لاگ‌های حمله
        st.session_state.qos_triggered = False
        reset_linux_qos() 
        st.rerun()

with col2:
    if st.button("🛑 Stop & Final Analysis", use_container_width=True):
        st.session_state.capturing = False
        st.rerun()

# نمایش هشدار زنده در بالای صفحه
if st.session_state.qos_triggered:
    st.error("⚠️ AI ALERT: Network Flooding Detected! Dynamic Linux QoS Applied (Ping Throttled via iptables).")

status_space = st.empty()
table_space = st.empty()

# --- PHASE 1: Live Capturing Mode ---
if st.session_state.capturing:
    status_space.info("⏳ System is capturing live network packets... Click 'Stop & Final Analysis' to generate charts.")
    
    sniff(iface="ens37", prn=process_live_packet, count=150, timeout=1.0)
    
    if st.session_state.live_results:
        df_live = pd.DataFrame(st.session_state.live_results).drop_duplicates(subset=["Src IP", "Dst IP", "Service"], keep="last")
        table_space.dataframe(df_live, use_container_width=True)
        
    st.rerun()

# --- PHASE 2: Stopped Mode (Display Metrics, Graphs & Security Report) ---
elif not st.session_state.capturing and st.session_state.live_results:
    status_space.success("✅ Packet capture session stopped successfully!")
    
    df_final = pd.DataFrame(st.session_state.live_results).drop_duplicates(subset=["Src IP", "Dst IP", "Service"], keep="last")
    
    # === بخش جدید: گزارش گرافیکی حملات بلاک شده ===
    if st.session_state.attack_logs:
        st.write("---")
        st.write("## 🚨 Cyber Security & Attack Mitigation Report")
        
        # مرتب‌سازی جدول حملات بر اساس آخرین دیتای ارسالی آی‌پی مهاجم
        df_attacks = pd.DataFrame(st.session_state.attack_logs).drop_duplicates(subset=["Attacker IP"], keep="last")
        st.dataframe(df_attacks, use_container_width=True)
        
        # رسم گراف حملات دفع شده
        st.write("#### 📈 Volume of Attempted Attack Packets vs. Mitigated Status by IP")
        st.bar_chart(data=df_attacks, x="Attacker IP", y="Attempted Packets")
    
    st.write("---")
    st.write("### 📋 Final Identified Network Flows Table")
    st.dataframe(df_final, use_container_width=True)
    
    st.write("### 🔢 Key Performance Indicators & Metrics")
    total_flows = len(df_final)
    total_packets = df_final["Packets Total"].sum()
    vpn_count = len(df_final[df_final["Label"] == "VPN"])
    non_vpn_count = len(df_final[df_final["Label"] == "NonVPN"])
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Flows", total_flows)
    m2.metric("Total Packets Exchanged", total_packets)
    m3.metric("VPN Flows", vpn_count, delta="Secured", delta_color="normal")
    m4.metric("Non-VPN Flows", non_vpn_count, delta="Unencrypted", delta_color="inverse")
    
    st.write("### 📊 Network Traffic Visualization Charts")
    g1, g2 = st.columns(2)
    with g2:
        st.write("#### Traffic Volume Comparison: VPN vs Non-VPN")
        st.bar_chart(df_final["Label"].value_counts())
    with g1:
        st.write("#### Traffic Share by Identified Service Type")
        st.bar_chart(df_final["Service"].value_counts())
        
    st.write("#### 📈 Distribution Matrix: Service Traffic volume over Network Medium (VPN vs Non-VPN)")
    pivot_df = df_final.groupby(["Service", "Label"])["Packets Total"].sum().unstack().fillna(0)
    st.bar_chart(pivot_df)