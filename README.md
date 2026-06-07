# Network Analysis Lab

Hands-on network traffic analysis lab using Suricata IDS and Zeek NSM to detect web application attacks in real-time.

## Stack

- **Suricata 8.0.4** - IDS/IPS, signature-based alert engine
- **Zeek 7.x** - Network Security Monitor, protocol analysis and logging
- **DVWA** - Damn Vulnerable Web Application (attack target)
- **Docker Compose** - deployment
- **WSL2 Ubuntu 24.04** - lab environment

## Architecture
[attacker container] --> [network-lab: 172.23.0.0/24] --> [DVWA 172.23.0.2:80]
|
[br-d5305e450180 bridge interface]
/                    
[Suricata IDS]              [Zeek NSM]
signature alerts            protocol logs
alerts/fast.log            logs/http.log
alerts/eve.json            logs/conn.log

## Methodology

1. Create isolated Docker network (172.23.0.0/24)
2. Deploy Suricata in host network mode, monitor bridge interface
3. Deploy Zeek in host network mode, monitor same interface
4. Launch attacks from attacker container against DVWA
5. Collect and analyze Suricata alerts and Zeek logs

## Attack Scenarios & Detection

### Attack Matrix

| Attack Type | Tool | Suricata Rule | Alert |
|-------------|------|---------------|-------|
| SQL Injection (UNION SELECT) | curl | sid:1000001,1000002 | ET WEB_SPECIFIC SQL Injection |
| XSS (script tag) | curl | sid:1000003 | ET WEB_SPECIFIC XSS Attempt |
| Directory Traversal | curl | sid:1000004,1000005 | ET WEB_SPECIFIC Directory Traversal |
| Command Injection | curl | sid:1000006 | ET WEB_SPECIFIC Command Injection |
| Brute Force Login | curl loop | sid:1000007 | ET WEB_SPECIFIC Brute Force Login |

### Suricata Alert Sample (fast.log)
06/07/2026-10:16:34.032118  [] [1:1000001:2] ET WEB_SPECIFIC SQL Injection - UNION SELECT [] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.23.0.3:32790 -> 172.23.0.2:80
06/07/2026-10:16:34.048041  [] [1:1000003:2] ET WEB_SPECIFIC XSS Attempt - script tag [] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.23.0.3:32802 -> 172.23.0.2:80
06/07/2026-10:16:34.055554  [] [1:1000004:2] ET WEB_SPECIFIC Directory Traversal ../ [] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.23.0.3:32818 -> 172.23.0.2:80
06/07/2026-10:16:34.063893  [] [1:1000006:2] ET WEB_SPECIFIC Command Injection passwd [] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.23.0.3:32822 -> 172.23.0.2:80
06/07/2026-10:16:34.122916  [] [1:1000007:2] ET WEB_SPECIFIC Brute Force Login POST [] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 172.23.0.3:32872 -> 172.23.0.2:80

### Zeek HTTP Log Sample (http.log)
ts              uid                 src_ip      src_port  dst_ip      dst_port  method  uri
1780827350.37   CFY2HR2v5xERckN9bc  172.23.0.3  35348     172.23.0.2  80        GET     /vulnerabilities/sqli/?id=1+union+select+1,2--&Submit=Submit

## Custom Suricata Rules

Rules are located in `suricata/rules/local.rules`. All rules use `any any -> any any` to capture intra-network traffic:

- SQL Injection detection via `union`+`select` keywords in URI
- XSS detection via `script` keyword in URI
- Directory Traversal via `../` and `etc/passwd` patterns
- Command Injection via `passwd` in request body
- Brute Force via POST to login.php threshold (3 requests / 10 seconds)

## Zeek Configuration

Zeek logs all HTTP requests including full URI, method, response code, and user agent. Configured with `-C` flag to ignore TCP checksum offloading in virtualized environment.

Loaded base protocols: HTTP, DNS, FTP, Notice framework.

## Key Skills Demonstrated

- Network IDS deployment and configuration (Suricata 8.0.4)
- Custom Snort-compatible rule authoring (7 rules, 5 attack classes)
- Network Security Monitoring with Zeek (HTTP/DNS/conn logging)
- Web attack pattern recognition (SQLi, XSS, LFI, CMDi, BruteForce)
- Docker network architecture for isolated lab environments
- Alert triage and log correlation (Suricata eve.json + Zeek http.log)
