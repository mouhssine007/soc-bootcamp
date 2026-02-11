🔐 SSH Brute‑Force Detection Lab
<p align="center"> <img src="https://img.shields.io/badge/SIEM-Splunk-blue?style=for-the-badge"> <img src="https://img.shields.io/badge/Attack-Hydra-red?style=for-the-badge"> <img src="https://img.shields.io/badge/OS-Ubuntu-orange?style=for-the-badge"> <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK-green?style=for-the-badge"> </p>
🔐 SSH Brute‑Force Detection Lab
🎯 Objective
Simulate SSH brute‑force → forward logs → detect in Splunk → map to MITRE.

🖥️ Lab IP Mapping
VM	Role	IP
Splunk SIEM	Log Analysis	192.168.80.130
Ubuntu Target	Victim SSH	192.168.80.133
Kali Linux	Attacker	192.168.80.135
Network: NAT — 192.168.80.0/24

⚙️ Forwarder Config (Target)
/opt/splunkforwarder/etc/system/local/inputs.conf

[monitor:///var/log/auth.log]
disabled = false
index = security_incidents
sourcetype = linux_secure
Connect to Splunk:

splunk add forward-server 192.168.80.130:9997 -auth admin:PASS
☠️ Attack — Kali
Password list:

nano /tmp/passlist.txt
Hydra:

hydra -t 4 -V -l mrlazarus -P /tmp/passlist.txt ssh://192.168.80.133
🔍 Detection — Splunk
Failed Logins
index=security_incidents "Failed password"
Brute‑Force Detection
index=security_incidents "Failed password" earliest=-5m
| rex "from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| where count >= 5
| sort -count
🚨 Alert Settings
Setting	Value
Schedule	Every 1 min
Time range	Last 5 min
Trigger	Results > 0
🧭 MITRE ATT&CK
Technique	ID
Brute Force	T1110
Password Spray	T1110.003
Valid Accounts	T1078
🛡️ Response
sudo ufw deny from 192.168.80.135 to any port 22
