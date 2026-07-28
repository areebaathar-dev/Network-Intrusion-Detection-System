# 🛡️ Network Intrusion Detection System (Mini IDS)

A Python-based Network Intrusion Detection System that monitors network traffic, detects suspicious activity, and provides real-time security monitoring through an interactive GUI dashboard.

![Python](https://img.shields.io/badge/Python-3670A0?style=flat&logo=python&logoColor=ffdd54)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-blue)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-lightgrey)

---

## 📖 Overview

Mini IDS is a multi-threaded intrusion detection system built for a Computer Networks course project. It captures and analyzes live network packets (or simulated/PCAP data), detects five categories of attacks in real time, and generates security logs and HTML reports through a Tkinter dashboard.

---

## ✨ Features

- Real-time packet monitoring
- Port scan detection
- SYN flood detection
- SSH/RDP brute-force detection
- Suspicious IP detection using blacklist
- Payload anomaly detection
- Live packet stream dashboard
- Threat alerts with severity classification
- Automatic IP blocking for high-severity threats
- Security log generation (TXT & CSV)
- HTML report generation
- Simulation mode, live packet capture mode, and PCAP file analysis mode

---

## 🛠️ Tech Stack

| Layer        | Technology                  |
|---------------|------------------------------|
| Language      | Python                       |
| GUI           | Tkinter                      |
| Packet capture| Scapy                        |
| Concurrency   | Threading, Queue              |
| Logging       | CSV, Datetime                |

---

## 🔍 Detection Engine

Implements five network attack detection techniques:
1. Port Scan Detection
2. SYN Flood Detection
3. SSH/RDP Brute Force Detection
4. Suspicious IP Detection (blacklist-based)
5. Payload Anomaly Detection

## 🏗️ System Architecture
GUI Dashboard → IDS Engine → Detection Engine
↓
Packet Simulator / Live Capture
↓
Security Logger → Report Generator

---

## 🚀 Getting Started

### Prerequisites
- Python 3.9+
- [Npcap](https://npcap.com/) (Windows) or libpcap (Linux/macOS) for live packet capture
- Administrator/root privileges (required for live packet sniffing)

### Installation
```bash
git clone https://github.com/areebaathar-dev/Network-Intrusion-Detection-System.git
cd Network-Intrusion-Detection-System
pip install -r requirements.txt
python main.py
```

> ⚠️ Live Packet Capture Mode requires running with administrator/root privileges. Simulation Mode and PCAP File Analysis Mode do not.

---

## 📁 Project Structure
Network-Intrusion-Detection-System/
├── main.py              # Entry point / GUI dashboard
├── detection_engine/    # Attack detection modules
├── packet_simulator/    # Simulated traffic generator
├── logger/              # Security log & CSV generation
├── reports/             # HTML report generator
└── models/              # Data models

---

## 📸 Screenshots

### Main Dashboard
<img width="100%" alt="Main Dashboard" src="https://github.com/user-attachments/assets/5c174894-be2f-4be2-8fcb-00aee0844c1a">

### Live Packet Monitoring
<img width="100%" alt="Live Packet Monitoring" src="https://github.com/user-attachments/assets/de1529c9-9be7-426b-8209-1ffe4aebbbc5">

### Threat Alerts
<img width="100%" alt="Threat Alerts" src="https://github.com/user-attachments/assets/37a51a0a-d46f-4998-9f0e-52b265ba6b04">

### Security Logs
<img width="100%" alt="Security Logs" src="https://github.com/user-attachments/assets/fcad5d91-afc2-4ba5-ad40-561b32eefa77">

### Generated HTML Report
<img width="100%" alt="HTML Report 1" src="https://github.com/user-attachments/assets/ed970849-6786-4cf6-a72b-dbd65bae16de">
<img width="100%" alt="HTML Report 2" src="https://github.com/user-attachments/assets/590425ed-0def-4a5c-8444-86d07580372a">

---

## 🔭 Future Improvements

- Machine learning-based anomaly detection
- Web-based dashboard (replace Tkinter with a browser UI)
- Email/Slack alerts for high-severity threats

---

## 📄 License

This project is licensed under the MIT License.

---

## 👩‍💻 Author

**Areeba Athar**
[LinkedIn](https://linkedin.com/in/areeba-athar) · [GitHub](https://github.com/areebaathar-dev)