# Lesson — DNS Record Types and DNS Analysis Using Splunk

## Objective

This lesson explains the main DNS record types used in network communication and demonstrates how to analyze DNS activity using Splunk. The goal is to understand DNS behavior and apply SPL queries to detect suspicious patterns.

---

## Part 1 — DNS Record Types Overview

DNS records define how domain names and IP addresses are resolved. Understanding them is essential for SOC analysis and network monitoring.

---

### A Record (IPv4 Address Record)

The A record maps a domain name to an IPv4 address.

Example:

example.com → 93.184.216.34


Usage:

- Website access
- Server communication
- Application connectivity

Security relevance:

- Used to identify the IP behind suspicious domains
- Helps track malicious infrastructure

---

### AAAA Record (IPv6 Address Record)

The AAAA record maps a domain name to an IPv6 address.

Example:



example.com → 2001:db8::1


Usage:

- IPv6 network communication
- Modern cloud infrastructure

Security relevance:

- Detect IPv6-based threats
- Prevent monitoring blind spots in dual-stack networks

---

### CNAME Record (Canonical Name Record)

The CNAME record creates an alias that points one domain name to another domain name.

Example:



www.example.com
 → example.com


Usage:

- Domain redirection
- Load balancing
- CDN integration

Security relevance:

- Detect phishing redirections
- Identify malicious domain chaining

---

### PTR Record (Pointer Record)

The PTR record performs reverse DNS lookup by mapping an IP address to a domain name.

Example:



93.184.216.34 → example.com


Usage:

- Reverse DNS resolution
- Email server validation
- Network troubleshooting

Security relevance:

- Identify unknown IP addresses
- Validate server identity
- Detect spoofed infrastructure

---

## DNS Record Summary

| Record Type | Purpose |
------------|---------
A | Domain to IPv4 address  
AAAA | Domain to IPv6 address  
CNAME | Domain alias mapping  
PTR | IP address to domain name  

---

## Part 2 — DNS Log Analysis Using Splunk

DNS logs provide visibility into network activity and client behavior. In this lab, Zeek-style DNS logs stored in JSON format are analyzed using Splunk.

---

## Dataset Fields Used

Important DNS fields:

- query — Domain name requested  
- id.orig_h — Source IP (client)  
- id.resp_h — DNS server IP  
- qtype — DNS record type  
- rcode — DNS response code  
- rtt — Query response time  

---

## Query 1 — Identify Most Frequently Queried Domains

### SPL Query

```spl
index=dns_lab sourcetype="json"
| stats count by query
| sort -count

Explanation

This query performs the following actions:

Searches DNS logs stored in the dns_lab index

Groups events by domain name (query field)

Counts how many times each domain appears

Sorts the results in descending order

Purpose

This analysis is used to:

Identify popular destinations

Detect abnormal DNS traffic

Find suspicious high-frequency domains

Detect possible malware beaconing

Example suspicious behavior:

randomdomain123.xyz → 5000 queries


This may indicate automated malicious communication.

Query 2 — Identify Most Active Source IP Addresses
SPL Query
index=dns_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count

Explanation

This query identifies clients generating the highest DNS traffic.

It helps analysts:

Detect compromised hosts

Identify abnormal DNS usage

Investigate internal network behavior

Query 3 — DNS Record Type Distribution
SPL Query
index=dns_lab sourcetype="json"
| stats count by qtype

Explanation

This query shows how DNS traffic is distributed by record type such as:

A

AAAA

CNAME

PTR

It helps detect:

Abnormal query behavior

Excessive reverse lookups

Suspicious record usage patterns

SOC Analyst Perspective

DNS analysis using Splunk allows analysts to:

Detect command-and-control communication

Monitor user browsing behavior

Identify suspicious infrastructure

Investigate malware activity

Correlate DNS with network and endpoint logs

Conclusion

Understanding DNS record types combined with Splunk-based DNS analysis provides strong visibility into network activity. These skills are essential for SOC monitoring, threat hunting, and incident investigation.

Key Takeaways

DNS records control how names and IPs are resolved

A, AAAA, CNAME, and PTR serve different roles

Splunk SPL queries allow DNS traffic analysis

High-frequency domains and abnormal clients may indicate threats
