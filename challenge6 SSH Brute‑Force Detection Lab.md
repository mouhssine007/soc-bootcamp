🔐 SSH Brute‑Force Detection Lab
Splunk SIEM + Ubuntu Target + Linux Forwarder + Kali Linux

📌 Objective
Simulate an SSH brute‑force attack using Kali Linux, forward authentication logs to Splunk SIEM, detect the attack, map it to MITRE ATT&CK, and perform incident response.

🧠 Lab Architecture
Kali Attacker ──────▶ Ubuntu Target ──────▶ Splunk Forwarder ──────▶ Splunk SIEM
   (Hydra)             (auth.log)            (Port 9997)              (Detection)
🌐 Network Configuration
All machines use:

VMware Adapter: NAT
Subnet: 192.168.80.0/24
🖥️ Virtual Machines & IP Mapping
VM Name	Role	IP Address
Ubuntu_Splunk	SIEM Server	192.168.80.130
Linux_Forwarder	Log Collector	192.168.80.129
Ubuntu_Target	SSH Victim	192.168.80.133
Kali_Attacker	Attacker	192.168.80.135
⚙️ Splunk SIEM Setup
Install Splunk:

wget -O splunk.deb https://download.splunk.com/products/splunk/releases/9.x/linux/splunk.deb
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
Create admin:

admin / Newpassword123!
Enable receiving:

Settings → Forwarding & Receiving → Add 9997
⚙️ Install Forwarder on Ubuntu Target
Download:

wget -O splunkforwarder.deb https://download.splunk.com/products/universalforwarder/releases/9.x/linux/splunkforwarder.deb
Install + start:

sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
🔗 Connect Target → Splunk
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.80.130:9997 -auth admin:Splunk123!
Verify:

sudo /opt/splunkforwarder/bin/splunk list forward-server
Expected:

Active forwards:
192.168.80.130:9997
📂 Monitor SSH Logs
Edit inputs:

sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
Add:

[monitor:///var/log/auth.log]
disabled = false
index = security_incidents
sourcetype = linux_secure
Restart:

sudo /opt/splunkforwarder/bin/splunk restart
🧪 Attack Simulation — Kali Linux
Create Password List
nano /tmp/passlist.txt
Example:

password
123456
admin123
welcome
P@ssw0rd
letmein
qwerty
Run Hydra Brute Force
hydra -t 4 -V -l mrlazarus -P /tmp/passlist.txt ssh://192.168.80.133
🔍 Detection in Splunk
Failed Logins
index=security_incidents "Failed password"
Brute‑Force Detection
index=security_incidents "Failed password" earliest=-5m
| rex "from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts values(user) as users by attacker_ip
| where attempts >= 5
| sort -attempts
🚨 Alert Rule
Trigger: 5 failures / 5 minutes

Schedule:

Run every 1 minute

Time range: Last 5 minutes

Trigger when results > 0

Alert title:

SSH Brute Force Detection
🛡️ Incident Response
Block attacker IP:

sudo ufw insert 1 deny from 192.168.80.135 to any port 22 proto tcp
🧭 MITRE ATT&CK Mapping
Tactic	Technique	ID
Credential Access	Brute Force	T1110
Initial Access	Valid Accounts	T1078
Discovery	Account Discovery	T1087
Credential Access	Password Spraying	T1110.003
Primary Technique Observed
T1110 — Brute Force

Hydra executed multiple password attempts against SSH.

📊 Indicators of Compromise
IOC	Value
Attacker IP	192.168.80.135
Target IP	192.168.80.133
Service	SSH
Log Source	/var/log/auth.log
Event	Failed Password
✅ Lab Outcomes
Centralized log ingestion

SSH brute‑force simulation

Detection engineering

MITRE ATT&CK mapping

SOC response workflow
