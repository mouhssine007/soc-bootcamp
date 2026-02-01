
 Cloudflare HTTP Log Analysis Using Splunk (WAF & Threat Detection)

## Objective

The objective of this project is to ingest Cloudflare HTTP request logs into Splunk and analyze them using field-aware SPL queries in order to detect common web attacks and suspicious behavior.

By completing this project, the following security objectives are achieved:

- Detect brute force login attempts  
- Identify SQL Injection (SQLi) attacks  
- Detect Cross-Site Scripting (XSS) attempts  
- Identify Local File Inclusion (LFI) and directory traversal  
- Detect reconnaissance and admin path scanning  
- Interpret Cloudflare WAF and HTTP response behavior  
- Practice parsing embedded JSON using structured SPL filtering  

This project simulates real SOC web security monitoring workflows.

---

## Dataset Information

The dataset used in this lab contains Cloudflare HTTP request logs in JSONL format.

File name:

cloudflare_http_requests_with_raw.jsonl


Key fields available in the dataset include:

- ClientIP — Source IP address  
- URI — Requested resource path  
- Status — HTTP response status code  
- UserAgent — Client software identifier  
- WAFAction — Cloudflare security action (block, log, challenge)  
- CacheStatus — Cloudflare caching behavior  
- Timestamp fields  

---

## Lab Preparation

### Data Ingestion

1. Open Splunk Web  
2. Navigate to:

Settings → Add Data → Upload


3. Upload file:

cloudflare_http_requests_with_raw.jsonl


4. Configure ingestion:

- Sourcetype: `_json`  
- Index: `cloudflare_lab`  

5. Complete upload

---
![Image Alt](https://github.com/mouhssine007/soc-bootcamp/blob/9ea1e8c1baba82545afb06f674326ad180bb48af/brute_force.png).
### Validation

Verify successful ingestion:

```spl
index=cloudflare_lab | head 5
If events appear, data ingestion is successful.

Detection Tasks
Task 1 — Brute Force Login Attempts Detection
Repeated login attempts to endpoints such as /login.php, /wp-login.php, and /admin/login often indicate brute force attacks. These attempts commonly return HTTP status codes 401 or 403.

SPL Query
index=cloudflare_lab (URI="/login.php" OR URI="/wp-login.php" OR URI="/admin/login") (Status=401 OR Status=403)
| stats count AS attempts by ClientIP, URI, UserAgent
| sort -attempts
Purpose
Identify attackers targeting login pages

Detect failed authentication patterns


Prioritize IP addresses performing brute force attempts
