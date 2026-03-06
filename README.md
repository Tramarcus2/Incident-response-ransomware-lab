# Incident Response Simulation Lab

## RDP Brute Force & Ransomware Investigation (Sentinel + Defender + Wireshark)

**Author:** Tramarcus Gipson

---

# Project Overview

This lab simulates a **real-world cyber attack scenario** in which an attacker performs a **Remote Desktop Protocol (RDP) brute-force attack** against a Windows system and successfully gains access. After gaining access, the attacker executes a script that simulates **ransomware behavior through mass file encryption**.

The attack is detected and investigated using:

* Microsoft Sentinel (SIEM)
* Microsoft Defender for Endpoint (EDR)
* Windows Event Logs
* Wireshark Network Traffic Analysis

The investigation follows the **NIST SP 800-61 Incident Response Framework** and maps attacker behavior to **MITRE ATT&CK techniques**.

This project demonstrates skills relevant to:

* SOC Analyst
* Incident Response Analyst
* Cybersecurity Analyst
* Threat Detection Engineer

---

# Lab Architecture

```

https://chatgpt.com/s/m_69aa1f48c94881919a1fc877a1cbf473


    
```

---

# Attack Simulation Scenario

1. The attacker performs an **RDP brute-force attack** using Hydra.
2. The attacker successfully logs into the victim machine.
3. The attacker executes a **PowerShell script that simulates ransomware encryption**.
4. Defender and Sentinel detect suspicious behavior.
5. The SOC investigates the attack and performs containment actions.

---

# MITRE ATT&CK Mapping

| Attack Stage   | Technique                 | ID    |
| -------------- | ------------------------- | ----- |
| Initial Access | Brute Force               | T1110 |
| Initial Access | Remote Services (RDP)     | T1021 |
| Persistence    | Valid Accounts            | T1078 |
| Execution      | PowerShell                | T1059 |
| Impact         | Data Encrypted for Impact | T1486 |

---

# Repository Structure

```
incident-response-ransomware-lab
│
├── README.md
│
├── architecture
│   └── lab-architecture.png
│
├── attack-simulation
│   └── hydra-bruteforce-command.txt
│
├── detection-rules
│   ├── brute-force-detection.kql
│   ├── suspicious-powershell.kql
│
├── threat-hunting
│   ├── rdp-login-hunt.kql
│   └── powershell-activity-hunt.kql
│
├── playbooks
│   └── sentinel-soar-playbook.md
│
├── evidence
│   ├── windows-event-logs
│   ├── defender-alerts
│   ├── sentinel-alerts
│   └── wireshark-capture
│
├── screenshots
│   ├── sentinel-dashboard.png
│   ├── defender-alert.png
│   ├── wireshark-traffic.png
│   └── event-viewer-logs.png
│
└── incident-report
    └── ransomware-incident-report.md
```

---

# Lab Setup

## Step 1 — Create Victim Machine

Create a Windows 10 or Windows 11 VM.

Enable Remote Desktop:

Settings → System → Remote Desktop → Enable

Create test user:

```
Username: testadmin
Password: Password123
```

---

# Step 2 — Enable Windows Security Logging

Run PowerShell as administrator.

```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Important logs generated:

| Event ID | Description      |
| -------- | ---------------- |
| 4625     | Failed login     |
| 4624     | Successful login |
| 4688     | Process creation |

---

# Step 3 — Install Microsoft Defender for Endpoint

Onboard the Windows VM into Defender.

Steps:

1. Open Microsoft Defender Security Portal
2. Navigate to **Endpoints → Device Management**
3. Download onboarding script
4. Execute script on Windows VM

This enables:

* Process telemetry
* File activity monitoring
* Authentication monitoring

---

# Step 4 — Deploy Microsoft Sentinel

1. Create Azure Log Analytics Workspace
2. Enable Microsoft Sentinel
3. Connect data sources:

* Windows Security Events
* Microsoft Defender for Endpoint

This allows centralized SIEM monitoring.

---

# Attack Execution

## RDP Brute Force Attack

Install Hydra on Kali:

```
sudo apt install hydra
```

Run attack:

```
hydra -l testadmin -P /usr/share/wordlists/rockyou.txt rdp://<victim-ip>
```

This generates hundreds of failed login attempts.

Evidence generated:

Event ID 4625

---

# Successful Login

The attacker eventually logs in via RDP.

Evidence generated:

Event ID 4624
Logon Type 10

---

# Ransomware Simulation

Execute the following command:

```
for /r C:\Users\Public %i in (*) do ren "%i" "%i.encrypted"
```

This simulates ransomware behavior.

Defender should detect suspicious file modification activity.

---

# Detection Queries

## Detect RDP Brute Force

```
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts > 20
```

---

# Detect Successful RDP Login

```
SecurityEvent
| where EventID == 4624
| where LogonType == 10
```

---

# Threat Hunting

## Detect Suspicious PowerShell Activity

```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "rename"
```

---

# Network Traffic Analysis

Capture traffic using Wireshark.

Filter:

```
tcp.port == 3389
```

Evidence identified:

* Multiple RDP authentication attempts
* Repeated connection attempts from attacker IP

---

# Attack Timeline

| Time  | Event                                     |
| ----- | ----------------------------------------- |
| 10:02 | Brute force attack begins                 |
| 10:07 | Multiple authentication failures detected |
| 10:10 | Successful RDP login                      |
| 10:11 | Suspicious PowerShell execution           |
| 10:12 | Mass file encryption simulation           |
| 10:13 | Defender alert generated                  |

---

# Incident Response (NIST 800-61)

## Preparation

Security monitoring tools deployed:

* Sentinel
* Defender
* Centralized logging

---

# Detection & Analysis

Indicators detected:

* Excessive failed login attempts
* Suspicious PowerShell activity
* Mass file renaming behavior

---

# Containment

Actions performed:

* Disabled compromised account
* Isolated endpoint
* Blocked attacker IP

---

# Eradication

Actions performed:

* Removed malicious scripts
* Verified no persistence mechanisms remained

---

# Recovery

Actions performed:

* Restored system functionality
* Verified system integrity

---

# Lessons Learned

Security improvements recommended:

* Enforce MFA
* Disable external RDP
* Implement account lockout policies
* Deploy continuous monitoring

---

# Security Automation (SOAR)

A Sentinel playbook can automate response actions.

Example workflow:

```
Sentinel Alert
      ↓
Logic App Triggered
      ↓
Block Attacker IP
      ↓
Notify Security Team
      ↓
Isolate Endpoint
```

---

# Purple Team Exercise

This lab simulates both offensive and defensive operations.

### Red Team

Simulated attacks:

* Hydra RDP brute force
* Credential compromise
* Ransomware simulation

### Blue Team

Detection and response using:

* Sentinel SIEM
* Defender EDR
* Windows Event Logs
* Wireshark network analysis

---

# Evidence Collected

Artifacts included:

* Sentinel alerts
* Defender alerts
* Windows event logs
* Wireshark packet capture
* Detection queries

---

# Skills Demonstrated

* Incident Response
* SIEM Investigation
* Endpoint Detection and Response
* Threat Hunting
* Detection Engineering
* Network Traffic Analysis
* MITRE ATT&CK Mapping
* Security Monitoring

---

# Conclusion

This lab demonstrates a full attack lifecycle from initial compromise through ransomware execution. Using Microsoft Sentinel, Defender for Endpoint, and Wireshark, the attack was detected, investigated, and contained using SOC investigation methodologies and incident response best practices.

