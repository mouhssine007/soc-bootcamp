🔐 SSH Brute‑Force Detection Lab
<p align="center"> <img src="https://img.shields.io/badge/SIEM-Splunk-blue?style=for-the-badge"> <img src="https://img.shields.io/badge/Attack-Hydra-red?style=for-the-badge"> <img src="https://img.shields.io/badge/OS-Ubuntu-orange?style=for-the-badge"> <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK-green?style=for-the-badge"> </p>
📌 Project Overview
This lab simulates an SSH brute‑force attack and demonstrates how a SOC analyst detects and responds using Splunk SIEM.

Logs are collected from a Linux target via Splunk Universal Forwarder, analyzed in Splunk, and mapped to MITRE ATT&CK.

🧠 Lab Architecture
Diagramme
flowchart LR
    A[Kali Attacker] -->|Hydra SSH Attack| B[Ubuntu Target]
    B -->|auth.log| C[Splunk Forwarder]
    C -->|Port 9997| D[Splunk SIEM]
    D -->|Detection & Alerts| E[SOC Analyst]
🌐 Network Configuration
Setting	Value
Network Mode	VMware NAT
Subnet	192.168.80.0/24
🖥️ Virtual Machines
VM Name	Role	IP
🧠 Ubuntu_Splunk	SIEM Server	192.168.80.130
📦 Linux_Forwarder	Log Collector	192.168.80.129
🎯 Ubuntu_Target	Victim Server	192.168.80.133
☠️ Kali_Linux	Attacker	192.168.80.135
⚙️ Splunk SIEM Setup
wget -O splunk.deb https://download.splunk.com/products/splunk/releases/9.x/linux/splunk.deb
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
Create admin:

admin / Newpassword123!
Enable receiving:

Settings → Forwarding & Receiving → Add 9997
📥 Install Splunk Forwarder (Target)
wget -O splunkforwarder.deb https://download.splunk.com/products/universalforwarder/releases/9.x/linux/splunkforwarder.deb
sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
🔗 Connect to Splunk
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.80.130:9997 -auth admin:Splunk123!
Verify:

sudo /opt/splunkforwarder/bin/splunk list forward-server
📂 Log Monitoring
[monitor:///var/log/auth.log]
disabled = false
index = security_incidents
sourcetype = linux_secure
Restart:

sudo /opt/splunkforwarder/bin/splunk restart
☠️ Attack Simulation (Kali)
Password List
nano /tmp/passlist.txt
password
123456
admin123
welcome
P@ssw0rd
letmein
qwerty
Hydra Attack
hydra -t 4 -V -l mrlazarus -P /tmp/passlist.txt ssh://192.168.80.133
🔍 Detection Queries
Failed Logins
index=security_incidents "Failed password"
Brute‑Force Detection
index=security_incidents "Failed password" earliest=-5m
| rex "from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts values(user) as users by attacker_ip
| where attempts >= 5
| sort -attempts
🚨 Splunk Alert Rule
Setting	Value
Alert Type	Scheduled
Time Range	Last 5 minutes
Run Every	1 minute
Trigger	Results > 0
Alert Name:

SSH Brute Force Detection
🧭 MITRE ATT&CK Mapping
Tactic	Technique	ID
Credential Access	Brute Force	T1110
Credential Access	Password Spraying	T1110.003
Initial Access	Valid Accounts	T1078
Discovery	Account Discovery	T1087
📊 Indicators of Compromise
IOC	Value
Attacker IP	192.168.80.135
Target IP	192.168.80.133
Service	SSH
Log Source	/var/log/auth.log
🛡️ Incident Response
sudo ufw insert 1 deny from 192.168.80.135 to any port 22 proto tcp
✅ Lab Outcomes
SSH brute‑force simulated

Logs centralized in SIEM

Detection queries built

Alerts configured

MITRE mapping completed

Attacker blocked
