# # Real-Time Network Traffic Classification with DMVPN

## 📌 Overview
This project implements **real-time network traffic classification** using machine learning models integrated with a Layer 3 DMVPN topology. The system can classify VPN/NonVPN traffic and services, while also detecting ICMP Flood attacks.

---

## ✨ Features
- Real-time packet capture and flow analysis  
- VPN/NonVPN and service classification using ML (Logistic Regression, Random Forest, SVM, XGBoost, Neural Network)  
- Integration with DMVPN Layer 3 (Hub-Spoke topology)  
- Intelligent ICMP Flood detection  
- Single-page Flask dashboard with live alerts  

---

## 🏗 Architecture
- **ML Section (Ubuntu/VMware):** Python scripts, datasets, and trained models  
- **Topology Section (EVE-NG/Windows):** DMVPN topology, router configurations, and topology screenshot  
- Communication between both sections is established via DMVPN tunnels with real traffic testing  

---

## 📂 Repository Structure
/ml-ai
*.py   ← Python scripts
*.csv  ← Datasets
*.pkl  ← Trained ML models

/topology-eve
*.txt   ← Router configurations
*.unl   ← EVE topology file
*.png   ← Topology screenshot


---

## 🚀 How to Run
1. Install Python and required libraries:
3. Load the DMVPN topology in EVE-NG and start routers  
4. Generate ICMP Flood traffic and observe alerts on the Flask dashboard  

---

## 📊 Sample Outputs
- Confusion Matrix for ML models  
- Real-time alerts in Flask dashboard  
- VPN/NonVPN and service classification results  

---

## 📸 Topology
![Topology Screenshot](topology-eve/Screenshot.png)

---

## 📜 License
MIT License
