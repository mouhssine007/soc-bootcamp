# 🔐 Fail2Ban + Splunk: SSH Brute-Force Detection & Auto-Blocking (Lab)

## Overview
This lab demonstrates an end-to-end workflow:
**Attack → Detection → Automated Response → SIEM Visibility**.

- **Fail2Ban** detects repeated SSH authentication failures and bans the attacker IP.
- **Splunk Universal Forwarder** ships `/var/log/fail2ban.log` to Splunk.
- **Splunk SIEM** provides search/investigation visibility.

## Lab IPs
| Machine | Role | IP |
|---|---|---|
| Splunk SIEM | Splunk Enterprise | 192.168.80.130 |
| Ubuntu Agent | SSH + Fail2Ban + Splunk Forwarder | 192.168.80.133 |
| Kali Linux | Attacker (Hydra) | 192.168.80.135 |

## Attack Simulation (Kali)
```bash
hydra -t 4 -V -l admin -P passwords.txt ssh://192.168.80.133
