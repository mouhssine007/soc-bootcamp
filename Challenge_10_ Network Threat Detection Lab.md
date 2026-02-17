# 🛡️ Network Threat Detection Lab  
## Suricata IDS + Emerging Threats + Splunk SIEM

---

## 📌 Overview

This lab demonstrates how to deploy a **Network Intrusion Detection System (NIDS)** using **Suricata** integrated with **Emerging Threats (ET) signatures** to detect malicious network activity such as reconnaissance scanning and service enumeration. Alerts are forwarded to **Splunk SIEM** for centralized monitoring, investigation, and visualization.

---

## 🎯 Objectives

- Deploy Suricata IDS on Ubuntu
- Install Emerging Threats detection rules
- Simulate attacks using Kali Linux
- Detect Nmap reconnaissance activity
- Forward IDS alerts to Splunk
- Investigate attacker behavior in SIEM

---
Kali Linux (Attacker)
192.168.80.135
│ Nmap / Recon Traffic
▼
Ubuntu Server + Suricata IDS
192.168.80.133
│ eve.json alerts
▼
Splunk SIEM Server
192.168.80.130
## 🧱 Lab Architecture


---

## 🖥️ Virtual Machines

| Machine | Role | IP Address |
|--------|------|-------------|
| Kali Linux | Attacker | 192.168.80.135 |
| Ubuntu Server | Target + Suricata Sensor | 192.168.80.133 |
| Splunk Enterprise | SIEM | 192.168.80.130 |

---


# ⚙️ Step 1 — Install Suricata (Ubuntu Sensor)

```bash
sudo apt update
sudo apt install suricata -y
Enable and start:

sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata --no-pager
🌐 Step 2 — Identify Network Interface
ip -br a
Lab result:

ens33 → 192.168.80.133
Used for packet capture.

🧩 Step 3 — Install Emerging Threats Rules
sudo apt install suricata-update -y
sudo suricata-update
Rules stored in:

/var/lib/suricata/rules/suricata.rules
No custom signatures required — ET rules load by default.

⚙️ Step 4 — Configure Suricata
Edit config:

sudo nano /etc/suricata/suricata.yaml
HOME_NET
HOME_NET: "[192.168.80.0/24]"
Interface
af-packet:
  - interface: ens33
Rule Path
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
Test Configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
Restart:

sudo systemctl restart suricata
📄 Step 5 — Verify Logs
ls /var/log/suricata/
Main alert log:

eve.json
Monitor live:

sudo tail -f /var/log/suricata/eve.json
☠️ Step 6 — Simulate Attack (Kali)
Run reconnaissance scan:

sudo nmap -sS -sV -A -T4 192.168.80.133
This triggers:

SYN scan detection

Service enumeration

SSH probing

OS fingerprinting

🔎 Step 7 — Verify Alerts Locally
```bash

sudo grep -i alert /var/log/suricata/eve.json
Example:

"signature":"ET SCAN Nmap SYN Scan"
```

📡 Step 8 — Configure Splunk Forwarder
Edit inputs:
```bash

sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
Add:

[monitor:///var/log/suricata/eve.json]
disabled = false
sourcetype = suricata:json
index = suricata
Restart forwarder:

sudo /opt/splunkforwarder/bin/splunk restart
Verify:

sudo /opt/splunkforwarder/bin/splunk list forward-server
Must show:
```

Active forwards: 192.168.80.130:9997

⚙️ Step 9 — Splunk Configuration
Create Suricata Index
Splunk Web → Settings → Indexes → New Index
```bash

Index name: suricata
Enable Receiving Port
Settings → Forwarding & Receiving → Add Port:

9997
```
🔎 Step 10 — Detection Queries
All Suricata logs
```bash

index=suricata
Alerts only
index=suricata event_type=alert
Nmap detection
index=suricata "Nmap"
SSH reconnaissance detection
index=suricata ssh.client.software_version="Nmap*"
```

Example detection:
```bash

Nmap-SSH2-Hostkey
Top attacker IPs
index=suricata event_type=alert
| stats count by src_ip
| sort -count
```
🧠 Alert Field Explanation
Field	Meaning
src_ip	Attacker IP (Kali)
dest_ip	Target server
signature	Detected attack
category	Threat classification
severity	Alert priority
# 🧭 MITRE ATT&CK Mapping

| Activity | Technique | Technique Name | MITRE ID |
|----------|------------|----------------|----------|
| Active Scanning | Reconnaissance | Active Scanning | T1595 |
| Service Enumeration | Discovery | Network Service Discovery | T1046 |
| SSH Probing | Lateral Movement | Remote Services (SSH) | T1021.004 |
| C2 Traffic Detection | Command & Control | Application Layer Protocol | T1071 |

---

# 🚨 Incident Response Actions

| Step | Action | Command / Method | Purpose |
|------|--------|------------------|---------|
| 1 | Identify attacker IP | Splunk search (`src_ip`) | Determine source of attack |
| 2 | Validate alert | Review Suricata signature | Confirm malicious activity |
| 3 | Block attacker IP | `sudo ufw deny from 192.168.80.135` | Stop further traffic |
| 4 | Check active connections | `netstat -tulnp \| grep 192.168.80.135` | Identify live sessions |
| 5 | Terminate malicious process | `sudo kill <PID>` | Disrupt attacker access |
| 6 | Review IDS logs | `/var/log/suricata/eve.json` | Investigate timeline |
| 7 | Correlate in SIEM | Splunk dashboards/search | Full visibility |
| 8 | Document incident | SOC report / case notes | Compliance & lessons learned |

---

# 🛡️ Detection → Response Flow


🚨 Incident Response Actions
Block attacker IP:

sudo ufw deny from 192.168.80.135
Check active sessions:

sudo netstat -tulnp | grep 192.168.80.135
Terminate connections if required.
