import subprocess
import json
import os
import datetime
import sys
import re
import nmap
import hashlib
import platform
import subprocess
import time
from scapy.all import IP, TCP, send
import random

def is_host_reachable(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        output = subprocess.check_output(["ping", param, "1", host], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

# Display menu of scanning options
def show_menu():
    print("\n--- QuickSystemScan ---")
    print("Select a scan to perform:")
    print("1: Port Scan")
    print("2: Vulnerability Scan")
    print("3: Service Enumeration")
    print("4: Network Sniffing")
    print("5: Brute Force Detection")
    print("6: System Integrity Check")
    print("8: Simulate Brute Force Attack")
    print("9: Simulate Port Flood Attack")
    print("12: Complete Scan (All Scans)")
    print("0: Exit")

# Prompt user for scan selection
def get_user_choice():
    show_menu()
    choice = input("Enter your choice (e.g., 1, 2,..., 12): ").strip()
    return choice
    

def run_port_scan(target):
    print(f"Scanning ports for {target}...")
    scanner = nmap.PortScanner()

    # Perform the scan on ports 1-1000
    scanner.scan(target, '1-1000')

    # Extract information about open ports
    open_ports = []
    for port in scanner[target]['tcp']:
        if scanner[target]['tcp'][port]['state'] == 'open':
            open_ports.append(port)

    # Return a structured report
    return {
        "Open Ports": {
            "Details": {
                "Scanned Ports": "1-1000 using nmap",
                "Open Ports": open_ports if open_ports else "No open ports found"
            }
        }
    }


def run_vulnerability_scan(target):
    print(f"[+] Running Vulnerability Scan on {target}...")
    try:
        command = ["nmap", "-sV", "--script", "vulners", target]
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        vulnerabilities = []
        collecting = False

        for line in output.splitlines():
            if "VULNERABLE:" in line:
                collecting = True
                vulnerabilities.append(line.strip())
            elif collecting:
                if line.strip() == "":
                    collecting = False
                else:
                    vulnerabilities.append("    " + line.strip())

        return {
            "Detected Vulnerabilities": vulnerabilities if vulnerabilities else ["No known vulnerabilities detected."],
            "Details": "Used nmap --script vulners for CVE lookup."
        }

    except Exception as e:
        return {"Error": str(e)}

def run_service_enumeration(target):
    print(f"[+] Running Service Enumeration on {target}...")
    try:
        command = ["nmap", "-sV", target]
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        services = []
        collecting = False

        for line in output.splitlines():
            if "PORT" in line and "SERVICE" in line:
                collecting = True
                continue
            if collecting:
                if line.strip() == "":
                    break
                services.append(line.strip())

        return {
            "Detected Services": services if services else ["No services detected."],
            "Details": "Used nmap -sV to enumerate service versions."
        }

    except Exception as e:
        return {"Error": str(e)}
def run_network_sniffing(interface="eth0"):
    print(f"[+] Capturing live traffic on interface: {interface}...")
    try:
        # Capture 20 packets using tcpdump
        command = ["tcpdump", "-i", interface, "-c", "20", "-nn"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        output = result.stdout

        protocols = set()
        hosts = set()

        for line in output.splitlines():
            parts = line.split()
            if len(parts) > 2:
                if "IP" in parts[1]:
                    if ">" in parts[2]:
                        src_dst = parts[2].split(">")
                        if len(src_dst) == 2:
                            hosts.add(src_dst[0].strip())
                            hosts.add(src_dst[1].strip())
                protocols.add(parts[1])

        return {
            "Captured Protocols": list(protocols) or ["No protocols detected."],
            "Involved Hosts": list(hosts) or ["No hosts detected."],
            "Details": f"Captured 20 packets on interface {interface} using tcpdump."
        }

    except subprocess.TimeoutExpired:
        return {"Error": "Traffic capture timed out."}
    except Exception as e:
        return {"Error": str(e)}


def run_brute_force_detection():
    print("[+] Scanning logs for brute-force attempts...")
    log_file = "/var/log/auth.log"  # Might vary: /var/log/secure on some systems
    brute_force_ips = {}

    try:
        if not os.path.exists(log_file):
            return {"Error": f"{log_file} not found. This scan is supported only on Linux with auth.log."}

        with open(log_file, "r") as f:
            for line in f:
                if "Failed password" in line:
                    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        ip = match.group(1)
                        brute_force_ips[ip] = brute_force_ips.get(ip, 0) + 1

        suspects = {ip: count for ip, count in brute_force_ips.items() if count >= 3}

        return {
            "Suspicious IPs": [f"{ip} ({count} failures)" for ip, count in suspects.items()] or ["No brute-force patterns detected."],
            "Details": "Checked for repeated failed login attempts in /var/log/auth.log."
        }

    except Exception as e:
        return {"Error": str(e)}

def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


def run_system_integrity_check():
    print("[+] Running system integrity check...")

    # Critical files to monitor
    critical_files = ["/bin/ls", "/bin/bash", "/usr/bin/ssh", "/usr/bin/sudo"]
    integrity_report = {}

    baseline_file = "integrity_baseline.json"
    current_hashes = {f: get_file_hash(f) for f in critical_files}

    # If baseline doesn't exist, create it
    if not os.path.exists(baseline_file):
        with open(baseline_file, "w") as f:
            json.dump(current_hashes, f, indent=2)
        return {
            "Baseline Created": list(current_hashes.keys()),
            "Details": f"Baseline saved in {baseline_file}. Re-run scan to detect changes."
        }

    # Load baseline
    with open(baseline_file, "r") as f:
        baseline_hashes = json.load(f)

    # Compare hashes
    for file, current_hash in current_hashes.items():
        old_hash = baseline_hashes.get(file)
        if not current_hash:
            integrity_report[file] = "File Missing or Unreadable"
        elif old_hash != current_hash:
            integrity_report[file] = "MODIFIED"
        else:
            integrity_report[file] = "OK"

    return {
        "File Status": integrity_report,
        "Details": f"Compared with baseline in {baseline_file}"
    }
    
# Function to print the report in a pretty format
def print_pretty_report(report, indent=0):
    spacer = "  " * indent
    if isinstance(report, dict):
        for key, value in report.items():
            print(f"{spacer}{key}:")
            print_pretty_report(value, indent + 1)
    elif isinstance(report, list):
        for item in report:
            print_pretty_report(item, indent + 1)
    else:
        print(f"{spacer}- {report}")

def simulate_brute_force(target):
    print(f"[+] Simulating brute-force attack on {target} (port 22)...")

    # Common usernames and passwords
    common_usernames = [
        "admin", "administrator", "root", "user", "guest", "test", "info", "adm", "mysql",
        "oracle", "postgres", "ftp", "pi", "ubuntu", "ec2-user", "webadmin", "service",
        "backup", "support", "sysadmin", "developer", "operator", "nobody", "apache", "nginx", "tomcat"
    ]
    
    common_passwords = [
        "123456", "password", "admin", "1234", "12345", "12345678", "qwerty", "abc123", "111111",
        "123123", "root", "toor", "letmein", "welcome", "password1", "123456789", "qwerty123",
        "1q2w3e4r", "test", "default", "changeme", "admin123", "passw0rd", "123qwe", "monkey",
        "dragon", "baseball", "iloveyou", "trustno1", "sunshine", "shadow", "login", "princess"
    ]

    # Randomly select a "successful" username/password
    success_username = random.choice(common_usernames)
    success_password = random.choice(common_passwords)

    attempts = []
    found = False

    for username in common_usernames:
        for password in common_passwords:
            attempt = f"Trying {username}/{password}..."
            print(f"    {attempt}")
            attempts.append(attempt)
            time.sleep(0.05)  # Simulated delay

            if username == success_username and password == success_password:
                print(f"[✔] SUCCESS: {username}/{password}")
                found = True
                break
        if found:
            break

    result = {
        "Simulated": True,
        "Attempts Made": len(attempts),
        "Successful Credentials": f"{success_username}/{success_password}",
        "Attempts (sample)": attempts[-10:]  # show last 10 attempts
    }
    return result

def simulate_port_flood(target):
    print(f"[+] Simulating port flood on {target} (20 random TCP SYN packets)...")
    ports = random.sample(range(1, 1000), 20)
    sent_ports = []

    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        send(pkt, verbose=0)
        print(f"    Sent SYN to port {port}")
        sent_ports.append(port)

    result = {
        "Simulated": True,
        "Details": "Sent 20 TCP SYN packets to random ports.",
        "Ports Targeted": sent_ports
    }
    return result

def interactive_menu():
    while True:
        # Show the menu
        # Prompt the user for choice
        choice = get_user_choice() 
        report_data = {}
        
        
        if choice == "0":
            print("Exiting QuickSystemScan.")
            break
        target = input("Enter target Domain/ IP address: ")
        if not is_host_reachable(target):
             print(f"[!] Host {target} is not reachable via ping.")
             proceed = input("Do you want to continue anyway? (y/n): ")
             if proceed.lower() != 'y':
                 print("Aborting scan.")
                 break
        else:
              print(f"[+] Host {target} is reachable. Proceeding...")
                  
        if choice == "1":
            report_data["Port Scan"] = run_port_scan(target)

        elif choice == "2":
            report_data["Vulnerability Scan"] = run_vulnerability_scan(target)

        elif choice == "3":
            report_data["Service Enumeration"] = run_service_enumeration(target)

        elif choice == "4":
            interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ").strip()
            report_data["Network Sniffing"] = run_network_sniffing(interface)

        elif choice == "5":
            report_data["Brute Force Detection"] = run_brute_force_detection()

        elif choice == "6":
            report_data["System Integrity Check"] = run_system_integrity_check()
            
        elif choice == "8":
            report_data["Brute Force Simulation"] = simulate_brute_force(target)
            
        elif choice == "9":
            report_data["Port Flood Simulation"] = simulate_port_flood(target)

        elif choice == "12":
            interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ").strip()

            report_data["Port Scan"] = run_port_scan(target)
            report_data["Vulnerability Scan"] = run_vulnerability_scan(target)
            report_data["Service Enumeration"] = run_service_enumeration(target)
            report_data["Network Sniffing"] = run_network_sniffing(interface)
            report_data["Brute Force Detection"] = run_brute_force_detection()
            report_data["System Integrity Check"] = run_system_integrity_check()

        else:
            print("Invalid choice. Please try again.")
            continue

        # Display pretty report
        print("\n=== Scan Report ===")
        print_pretty_report(report_data)

        # Save report as JSON
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"QuickScan_Report_{timestamp}.json"
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)

        print(f"\n[+] Report saved to {report_file}\n")
        os.system(f"xdg-open {report_file}")  # Optional: Open report

        cont = input("Do you want to perform another scan? (y/n): ").strip().lower()
        if cont != "y":
            break

if __name__ == "__main__":
    interactive_menu()
