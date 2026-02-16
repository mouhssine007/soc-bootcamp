# 🛡️ File Integrity Monitoring — Auditd + Splunk + Kali SSH Attack

## 🎯 Objective
Implement File Integrity Monitoring (FIM) on a Linux server to detect unauthorized:

- File modifications
- File deletions
- Permission changes

Attack activity is simulated from a Kali Linux machine via SSH, with logs analyzed in Splunk for SOC investigation.

---

## 🧱 Lab Architecture

---

## 🌐 Lab Environment

| Machine | Role | IP |
|--------|------|----|
| Splunk SIEM | Log Analysis | 192.168.80.130 |
| Ubuntu Agent | Auditd + Forwarder | 192.168.80.133 |
| Kali Linux | Attacker | 192.168.80.135 |

---

# ⚙️ Task 1 — Install Auditd (Target)

```bash
sudo apt update
sudo apt install auditd -y
sudo systemctl start auditd
sudo systemctl enable auditd
sudo systemctl status auditd

Kali Linux (Attacker) ──SSH──> Ubuntu Agent ──Logs──> Splunk SIEM
192.168.80.135 192.168.80.133 192.168.80.130
Task 2 — Configure Monitoring Rules
Edit rules file:
```bash

sudo nano /etc/audit/rules.d/audit.rules
Add:

-w /etc/ -p wa -k file_integrity
Reload rules:

sudo service auditd restart
sudo auditctl -l

```
Task 3 — Forward Audit Logs to Splunk
Log path:

/var/log/audit/audit.log
Configure forwarder:

sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
Add:

[monitor:///var/log/audit/audit.log]
disabled = false
sourcetype = auditd
index = linux_file_integrity
Restart:

sudo /opt/splunkforwarder/bin/splunk restart
📡 Task 4 — Forward SSH Authentication Logs (Attacker IP Evidence)
[monitor:///var/log/auth.log]
disabled = false
sourcetype = linux_secure
index = linux_auth
Restart forwarder again.

🖥️ Task 5 — Splunk Setup
On Splunk server:

Enable receiving → Port 9997

Create indexes:

linux_file_integrity
linux_auth
☠️ Task 6 — Attacker Access (Kali → SSH)
From Kali:
```bash
ssh user@192.168.80.133
Successful login is logged in:

/var/log/auth.log
```
☠️ Task 7 — Simulate Unauthorized Activity
Executed on Ubuntu via SSH session.

Modify passwd file
```bash

sudo nano /etc/passwd
Add fake user → Save.
```
Delete file
```bash
sudo touch /etc/testfile
sudo rm /etc/testfile
Change permissions
sudo chmod 777 /etc/passwd
```
🔎 Task 8 — Verify Logs Locally
``` bash
sudo ausearch -k file_integrity
🧠 Audit Log Field Interpretation
Example event:
```bash
type=SYSCALL
syscall=unlink
auid=1000
uid=0
exe="/usr/bin/rm"
path="/etc/testfile"
Field	Meaning
SYSCALL	Event category
unlink	File deletion syscall
auid	Original user
uid	Effective privilege
exe	Command executed
path	Target file
Presence of unlink indicates file deletion activity.
```
📊 Task 9 — Detection in Splunk
```bash

File integrity events
index=linux_file_integrity key="file_integrity"
Detect passwd tampering
index=linux_file_integrity "/etc/passwd"
Detect deletions
index=linux_file_integrity "unlink"
🌐 Attacker IP Attribution
Search SSH logins:

index=linux_auth sshd "Accepted password"
```
Example event:

Accepted password for user from 192.168.80.135 port 54321 ssh2
This confirms attacker source IP.

🔗 Attack Correlation Timeline
(index=linux_auth sshd) OR (index=linux_file_integrity key="file_integrity")
| sort _time
Shows:

SSH login from Kali

File tampering

Auditd detection

🚨 Incident Response
Identify user:

id <auid>
Investigate modified file

Restore from backup

Re‑secure permissions:

chmod 644 /etc/passwd
chown root:root /etc/passwd
## 🧭 MITRE ATT&CK Mapping

| Activity | Technique | MITRE ID |
|----------|------------|-----------|
| File Modification | Data Manipulation | T1565 |
| File Deletion | Indicator Removal on Host | T1070 |
| Privilege Abuse | Exploitation for Privilege Escalation | T1068 |
| SSH Lateral Movement | Remote Services (SSH) | T1021 |
