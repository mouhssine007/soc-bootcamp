# SOC Lab Setup — Splunk Enterprise on Ubuntu Server

## 📌 Project Overview

This lab documents the deployment of **Splunk Enterprise SIEM** on Ubuntu Server as part of a personal SOC (Security Operations Center) practice environment.

The goal is to build a realistic log monitoring platform for security analysis, detection engineering, and incident response training.

This project demonstrates real-world troubleshooting, Linux administration, and SIEM deployment skills.

---

## 🖥 Lab Environment

| Component | Details |
---------|---------
Host OS | Windows 10/11
Guest OS | Ubuntu Server 22.04 LTS
Virtualization | VMware / VirtualBox
Remote Access | SSH (PowerShell)
SIEM Platform | Splunk Enterprise 9.3.0

---

## 🌐 Network Configuration

Ubuntu Server Private IP:


SSH Connection Command:

```powershell
ssh mrlazarus@192.168.249.128
Note: Only private LAN IP addresses are used for lab isolation.
System Requirements

Minimum recommended resources:

Disk Space: 20 GB

RAM: 2 GB minimum (4 GB recommended)

CPU: 2 Cores

Stable Internet Connection

🧹 Pre-Installation Cleanup (Elastic Stack Removal)

Elastic Stack was previously installed and removed to free disk space and avoid port conflicts.

Commands executed:

sudo systemctl stop elasticsearch
sudo apt purge elasticsearch -y
sudo rm -rf /var/lib/elasticsearch
sudo rm -rf /var/log/elasticsearch
sudo apt autoremove -y
sudo apt clean


Disk verification:

df -h


Confirmed sufficient free space before proceeding.

📥 Splunk Download

Download Splunk Enterprise package:

wget https://download.splunk.com/products/splunk/releases/9.3.0/linux/splunk-9.3.0-51ccf43db5bd-linux-2.6-amd64.deb -O splunk.deb


Verify file integrity:

ls -lh splunk.deb


Expected size:

~721 MB

📦 Splunk Installation

Install Splunk package:

sudo dpkg -i splunk.deb


If dependency issues occur:

sudo apt --fix-broken install -y

▶ Splunk Initial Startup

Start Splunk and accept the license agreement:

sudo /opt/splunk/bin/splunk start --accept-license


During first launch:

Create admin username

Create strong administrator password

🌍 Web Interface Access

Access Splunk Web from the host machine browser:

http://192.168.249.128:8000


Login using the credentials created during setup.

🔐 Enable Automatic Startup

Enable Splunk service to start at boot:

sudo /opt/splunk/bin/splunk enable boot-start

🔥 Firewall Configuration

Allow Splunk and SSH traffic:

sudo ufw allow 8000
sudo ufw allow 22
sudo ufw reload

✅ Installation Verification

Check Splunk service status:

sudo /opt/splunk/bin/splunk status


Expected output:

splunkd is running
