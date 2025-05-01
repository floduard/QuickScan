#### QuickScan 
Python-based CLI tool designed for security analysts and sysadmins to perform various system and network assessments. It can scan for open ports, detect vulnerabilities, simulate brute-force attempts, sniff traffic, check system integrity, and more.

### 📦 Features
✅ Port Scanning (1–1000)
✅ Vulnerability Scanning (Nmap NSE scripts)
✅ Service Enumeration
✅ Network Sniffing (basic packet capture)
✅ Brute Force Attack Detection (simulation)
✅ System Integrity Check (basic file monitoring)
✅ Complete System Scan (all of the above)

✅ Pretty Console Report
✅ Automatic Accessibility Check via Ping
✅ Interactive CLI Menu

### 🚀Getting Started
#### 📋 Prerequisites
Ensure the following packages and tools are installed:

** sudo apt update **
** sudo apt install nmap python3-pip**
** pip3 install psutil scapy  **
** If python-nmap fails with externally-managed-environment, use: **


 ** pip3 install --break-system-packages python-nmap **

### 🔧 Optional Tools
** Wireshark/tshark (if extending sniffing) **

** Root/Sudo privileges (recommended for some scans) **

* 📂 Installation *

### git clone https://github.com/yourusername/QuickSystemScan.git
### cd QuickSystemScan
sudo python3 QuickScan.py

Always run with sudo to ensure full scanning access (e.g., raw sockets).

🖥️ Usage
🔘 Interactive Mode

sudo python3 QuickScan.py
You will see a menu like:

### Welcome to QuickSystemScan!
1: Port Scan
2: Vulnerability Scan
3: Service Enumeration
4: Network Sniffing
5: Brute Force Detection
6: System Integrity Check
7: Complete Scan
0: Exit

Then you’ll be asked to enter the target IP address. The tool will:

Check if the host is reachable via ping

Ask to proceed if unreachable

Run your selected scan



###🛡️ Legal Disclaimer
This tool is intended for authorized testing and educational use only. Performing scans without permission is illegal and unethical.



#### Report formatting improvements

#### OS compatibility fixes
