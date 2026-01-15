# 🛡️ SentinelMind: Real-Time Network Threat Guardian

SentinelMind is a lightweight Network Intrusion Detection System (NIDS) designed to identify and log connections to known malicious infrastructure. It combines global threat intelligence with live packet inspection to protect your local environment.

## 🧠 System Architecture

The system is built on a "Brain and Eye" architecture:
- **The Brain (`modules/database_mgr.py`)**: A local SQLite database that stores synchronized threat indicators (IPs, domains, malware hashes).
- **The Eye (`core/eye.py`)**: A high-speed network sniffer that intercepts traffic and performs millisecond lookups against the Brain.
- **The Dashboard (`main.py`)**: A centralized command center for syncing data and monitoring alerts.



---

## ✨ Features

- **Automated Intelligence Sync**: Fetches real-time malware "pulses" from AlienVault OTX.
- **Multi-Engine Enrichment**: Cross-references threats with AbuseIPDB and VirusTotal to assign accurate risk scores.
- **Protocol Analysis**: Detects threats across TCP, UDP, and ICMP (Ping) protocols.
- **Forensic Logging**: Automatically records every detected threat to `data/alerts.log` with timestamps and port details.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- **Npcap**: [Download here](https://npcap.com/). (Required for Windows packet capture).
- **Administrator Privileges**: You must run your terminal or IDE as Administrator to access the network hardware.

### Installation
1. Clone the repository to your local machine.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   
Running the System
Initialize: Run main.py and select Option 1 to populate your local database with the latest global threats.

Monitor: Select Option 2 and enter your network interface (e.g., Wi-Fi) to begin the live guardian mode.

📁 Project Structure

SentinelMind/
├── core/               # Detection and sniffing logic
├── modules/            # Database and API management
├── data/               # Local threat DB and alert logs (Git Ignored)
├── config/             # API keys and system settings
└── main.py             # System entry point

Security & Privacy
This tool is for educational and defensive purposes only. Ensure your .gitignore is active to avoid leaking your private API keys or local alert logs.


---

### 🛠️ One Final Step: Update your `.gitignore`
Since you asked if the directory is fine, it is! But we must ensure your private data doesn't get uploaded if you ever put this on GitHub. Open your `.gitignore` file and make sure it looks like this:

```text
# Local Database and Sensitive Logs
data/threat_intel.db
data/alerts.log
data/whitelist.txt

# API Keys and Secrets
config/settings.json
.env

# Python Environment & Cache
.venv/
__pycache__/
*.pyc