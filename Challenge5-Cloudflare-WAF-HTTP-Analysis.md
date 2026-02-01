
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
```
index=cloudflare_lab (URI="*' OR '1'='1*" OR URI="*UNION SELECT*")
| stats count AS hits by ClientIP, URI, UserAgent, WAFAction
| sort -hits
Purpose
Detect SQL injection attempts in HTTP requests

Identify attack sources

Analyze Cloudflare WAF mitigation behavior
---
![Image Alt](https://github.com/mouhssine007/soc-bootcamp/blob/9aaddc55e903c32c52a21c5cca4834b28b8e6306/brute_force1.png).

Task 3 — Cross-Site Scripting (XSS) Detection

XSS attacks frequently include JavaScript injection patterns such as <script> or encoded variants.

SPL Query
index=cloudflare_lab (URI="*<script>*" OR URI="*%3Cscript%3E*")
| stats count AS hits by ClientIP, URI, UserAgent, Status
| sort -hits

Purpose

Identify JavaScript injection attempts

Detect malicious payload distribution attempts

Analyze server response behavior
![Image Alt](https://github.com/mouhssine007/soc-bootcamp/blob/97a70bc7028cbcb9e0e0274351d3d14ce5e940a5/brute_force3.png).

Task 4 — Local File Inclusion (LFI) and Directory Traversal Detection

Attackers attempt to read sensitive system files or traverse directories using patterns such as:

/etc/passwd

../

..%2F

SPL Query
index=cloudflare_lab (URI="*/etc/passwd*" OR URI="*../*" OR URI="*..%2F*")
| stats count AS attempts by ClientIP, URI, Status
| sort -attempts


![Image Alt](https://github.com/mouhssine007/soc-bootcamp/blob/c3b12ddf504b21b6f0d0fbe527f133809cfd86c3/brute_force4.png).

Purpose

Detect file disclosure attempts

Identify directory traversal behavior

Monitor access to sensitive resources

Task 5 — Recon & Admin Path Scanning
Enumeration of admin interfaces or internal utilities.

index=cloudflare_lab (URI="/admin" OR URI="/phpmyadmin" OR URI="/wp-admin" OR URI="/.git/HEAD" OR URI="/server-status")
| stats count AS hits by ClientIP, URI, Status
| sort -hits
Here

URI targets common admin interfaces.
Status shows whether attempts were blocked, missing, or (worse) allowed.

![Image Alt](https://github.com/mouhssine007/soc-bootcamp/blob/0f9310fa4cc8570006d2cfd1c6895600a5bfdff2/brute_force5.png).
Security Analysis Observations

During this lab, multiple attack behaviors were simulated:

Login brute force attempts targeting CMS authentication endpoints

SQL injection payload testing against dynamic web pages

JavaScript injection attempts for XSS exploitation

File system access attempts using LFI patterns

Reconnaissance scans against administrative interfaces

Cloudflare WAF action fields provide visibility into whether malicious traffic was:

Blocked

Logged

Challenged

This enables correlation between security enforcement and HTTP activity.

SOC Analyst Skills Practiced

This project strengthens the following SOC skills:

SIEM log ingestion and validation

SPL query construction

Pattern-based attack detection

HTTP threat analysis

Web attack classification

Cloud WAF signal interpretation

Data filtering and aggregation

Attack source prioritization

Conclusion

This project demonstrates how Cloudflare HTTP logs can be analyzed using Splunk to detect multiple categories of web-based attacks. By combining URI pattern matching, HTTP status analysis, and WAF action correlation, analysts gain visibility into attacker behavior and security control effectiveness.

The techniques used in this lab reflect real-world SOC workflows for monitoring public-facing web applications and cloud-protected services.

Key Takeaways

SPL pipelines enable efficient security analysis

Proper use of logical operators and filtering improves detection accuracy

Cloudflare WAF signals enhance threat visibility

Web log analysis is a core SOC responsibility

Combining multiple detection techniques provides stronger security coverage
