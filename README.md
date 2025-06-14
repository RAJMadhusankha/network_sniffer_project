# Network Sniffer & Anomaly Detector

A simple Python tool that captures live network traffic on Linux using Scapy. It detects suspicious IP addresses sending unusually high amounts of packets, logs alerts, and helps identify possible network attacks.

## Features

- Real-time packet sniffing and analysis  
- Detection of high traffic from source IPs (possible anomalies)  
- Alert logging in `alerts.txt`  
- Manual report creation in `report.txt`  
- Optional PDF report generation  

## Requirements

- Ubuntu Linux or any Linux distro  
- Python 3.x  
- Scapy (`pip3 install scapy`)  
- (Optional) Pandoc for PDF reports  

## Usage

1. Open a terminal and navigate to the project folder:

   ```bash
   cd network_sniffer_project
2. Run the sniffer script with root privileges:
   ``` bash
   sudo python3 anomaly_sniffer.py

3.Let it run to capture network packets and detect anomalies.

4.Check alerts.txt for alerts about suspicious IPs.

5.Create or update report.txt to summarize findings manually.

network_sniffer_project/
├── anomaly_sniffer.py       # Main packet sniffing script  
├── alerts.txt               # Logs suspicious IP alerts  
├── report.txt               # Summary report (manual)  
├── report.pdf               # Optional PDF report  
└── README.md                # Project overview  

Author
Janith Madhusankha
Network & Security Enthusiast
Email: janithm2000@gmail.com

---

You can copy-paste this entire block as your README.md file — ready to add to GitHub! Let me know if you want me to help with anything else.
