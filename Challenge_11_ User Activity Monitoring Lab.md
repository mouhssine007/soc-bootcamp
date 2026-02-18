# 🛡️ User Activity Monitoring Lab  
## Sysmon for Linux + Splunk SIEM

---

## 📌 Overview

This lab demonstrates how to deploy **Sysmon for Linux** to monitor and detect unauthorized user account activities such as:

- Account creation & deletion  
- Privilege escalation  
- Suspicious command execution  
- File access & modification  
- Network connections  

Sysmon telemetry is forwarded to **Splunk SIEM** for centralized monitoring and investigation.

---

## 🎯 Objectives

- Install and configure Sysmon for Linux  
- Monitor user account activities  
- Detect privilege escalation attempts  
- Track suspicious commands  
- Forward logs to Splunk  
- Investigate user behavior in SIEM  

---

## 🧱 Lab Architecture


This lab monitors user activity on a Linux endpoint using Sysmon telemetry forwarded to Splunk SIEM.
Kali Linux (Attacker)
192.168.80.135
        │
        │ SSH / Commands / Downloads
        ▼
Ubuntu Server (Sysmon Monitored Host)
192.168.80.133
        │
        │ Sysmon Logs → /var/log/syslog
        ▼
Splunk Universal Forwarder
        │
        ▼
Splunk SIEM Server
192.168.80.130
