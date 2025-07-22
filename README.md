# 🛡️ SentinelLite - Lightweight Python EDR

![EDR Banner](https://img.shields.io/badge/Project-EDR-blueviolet)  
![Python](https://img.shields.io/badge/Built%20With-Python%203.8+-blue)  
![License](https://img.shields.io/badge/License-MIT-green)

**SentinelLite** is a lightweight, open-source Endpoint Detection and Response (EDR) system built with Python. It provides real-time monitoring for suspicious file activity, process behavior, and network anomalies — perfect for learning, demos, and mini endpoint defense simulations.

---

## 🚀 Features

- 📂 **File Monitoring**  
  - Detects creation of suspicious file extensions (`.enc`, `.exe`, `.bat`, etc.)
  - Flags rapid renaming and mass deletion (possible ransomware behavior)

- 🧠 **Behavioral Process Monitoring**  
  - Tracks high CPU/memory usage
  - Detects known malicious tools like `mimikatz.exe`, `powershell.exe`
  - Identifies suspicious parent-child relationships (e.g., `winword.exe → powershell.exe`)

- 🌐 **Network Watchdog**  
  - Flags unusual outbound connections on non-standard ports

- ⚡ **Process Surge Detection**  
  - Warns when a sudden spike in process creation is observed (e.g., worms, fork bombs)

- 📝 **Logging**  
  - Logs all alerts to `edr_alerts.log` with timestamps

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/SentinelLite.git
cd SentinelLite
pip install -r requirements.txt
