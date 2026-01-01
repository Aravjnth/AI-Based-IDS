# 🛡️ CORTEX IDS - AI-Powered Active Defense System

## 🚀 Overview
Cortex IDS is a professional-grade, real-time Intrusion Detection & Prevention System (IDPS) designed for Windows environments. It leverages Machine Learning (Random Forest) to analyze network traffic patterns and distinguish between legitimate user activity and malicious cyber threats (DDoS, Port Scanning, Brute Force).

Unlike traditional signature-based firewalls, Cortex uses behavioral analysis to detect zero-day anomalies.

## ✨ Key Features
- **🧠 AI Core**: Trained Machine Learning model detects complex attack vectors.
- **⚡ Real-Time Sensor**: High-performance asynchronous packet sniffing engine.
- **🛡️ Active Defense**: Automatically updates Windows Firewall to block attackers instantly.
- **👁️ CORTEX Dashboard**: Professional "Dark Mode" UI for live threat monitoring.
- **🏳️ Smart Whitelisting**: Automated RDNS lookup to ignore tech giants (Google, Facebook, Microsoft) and trusted admin IPs.
- **☁️ Cloud-Ready**: SaaS architecture capable of reporting to a central command server.

## 🛠️ Installation

### Option 1: Standalone (Recommended)
Simply download the latest release and extract the zip file.
1. Run `Cortex_Dashboard.exe`
2. Run `Cortex_Sensor.exe` (Run as Administrator for blocking features)
3. Open `http://localhost:5000`

### Option 2: Run from Source
Requirements: Python 3.10+, Npcap (for Scapy)

```bash
git clone https://github.com/yourusername/cortex-ids.git
cd cortex-ids
pip install -r requirements.txt
python real_time_ids.py
# In a separate terminal
python dashboard/app.py
```

## 🖥️ The Dashboard
The CORTEX UI provides a war-room experience:
- **Live Incident Stream**: Watch packets as they are analyzed.
- **Threat Intensity Chart**: Real-time visualization of network stress.
- **One-Click Trust**: Manually whitelist IPs directly from the table.

## ⚙️ Configuration
Edit `config.json` to customize your defense:
```json
{
    "enable_firewall_block": true,
    "enable_desktop_notifications": true,
    "whitelist": ["192.168.1.1"]
}
```

## 🏗️ Architecture
- **Sensor**: Python + Scapy + Scikit-Learn (Compiles to .exe)
- **Backend**: Flask + SQLite
- **Frontend**: HTML5 + Vanilla JS + Chart.js

## 📜 License
MIT License. Built for the Shentinelix Sphere.
