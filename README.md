# Incident-response-ransomware-lab
Simulated ransomware incident response using Microsoft Sentinel, Defender for Endpoint, and Wireshark to investigate an RDP brute-force compromise.

# Incident Response Lab

## RDP Brute Force & Ransomware Investigation (Sentinel + Defender + Wireshark)

**Author:** Tramarcus Gipson

---

# Project Overview

This project simulates a real-world cyber attack in which an attacker performs an **RDP brute-force attack** against a Windows system and executes a **ransomware-style payload** after gaining access.

The attack is detected and investigated using:

* Microsoft Sentinel (SIEM)
* Microsoft Defender for Endpoint (EDR)
* Windows Event Logs
* Wireshark network analysis

The investigation follows the **NIST 800-61 Incident Response lifecycle** and maps attacker behavior to **MITRE ATT&CK techniques**.

---

# Lab Architecture

```
Attacker Machine
(Kali Linux + Hydra)
        |
        |  RDP Brute Force Attack
        |
Victim Machine
(Windows 10 / Server VM)
        |
        |  Endpoint Telemetry
        |
Microsoft Defender
(EDR Detection)
        |
        |  Log Forwarding
        |
Azure Log Analytics
        |
        |
Microsoft Sentinel
(SIEM Investigation)
        |
        |
SOC Analyst Investigation
        |
        |
Wireshark Network Analysis
```

---

# Technologies Used

| Technology             | Purpose                        |
| ---------------------- | ------------------------------ |
| Microsoft Sentinel     | SIEM detection & investigation |
| Microsoft Defender     | Endpoint detection             |
| Wireshark              | Network traffic analysis       |
| Kali Linux             | Attacker machine               |
| Hydra                  | Brute force attack tool        |
| PowerShell             | Ransomware simulation          |
| Azure Virtual Machines | Lab environment                |

---

# Attack Scenario

The simulated attacker performs the following actions:

1. Launch RDP brute-force attack
2. Successfully authenticate using compromised credentials
3. Execute ransomware-style file encryption
4. SOC detects suspicious activity
5. Incident response actions contain the attack

---

# MITRE ATT&CK Mapping

| Technique                 | ID    |
| ------------------------- | ----- |
| Brute Force               | T1110 |
| Remote Services (RDP)     | T1021 |
| Valid Accounts            | T1078 |
| PowerShell Execution      | T1059 |
| Data Encrypted for Impact | T1486 |

---

# Attack Simulation

## Step 1: Launch Brute Force Attack

From the Kali Linux attacker machine:

```
hydra -l testadmin -P /usr/share/wordlists/rockyou.txt rdp://<victim-ip>
```

This generates multiple failed authentication attempts.

Evidence generated:

Event ID 4625 — Failed login attempts

---

# Step 2: Successful Login

Eventually the attacker successfully logs in via RDP.

Evidence generated:

Event ID 4624
Logon Type 10 — Remote Desktop login

---

# Step 3: Ransomware Simulation

A PowerShell command simulates ransomware encryption by renaming files.

```
for /r C:\Users\Public %i in (*) do ren "%i" "%i.encrypted"
```

This generates abnormal file modification activity detected by Defender.

---

# Detection and Investigation

## Sentinel Query — Brute Force Detection

```
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| where FailedAttempts > 20
```

This query identifies excessive authentication failures indicating brute-force activity.

---

# Threat Hunting Query

Detect suspicious PowerShell execution.

```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "rename"
```

---

# Network Traffic Analysis

Traffic was captured using Wireshark.

Filter used:

```
tcp.port == 3389
```

Observed activity:

* Repeated RDP connection attempts
* High authentication traffic volume
* Suspicious source IP address

---

# Incident Response Actions

Following the **NIST 800-61 Incident Response Framework**.

### Containment

Actions performed:

* Disabled compromised account
* Isolated infected endpoint
* Blocked attacker IP

### Eradication

* Removed malicious scripts
* Verified system integrity

### Recovery

* Restored files from backup
* Re-enabled system access

---

# Incident Timeline

| Time  | Event                             |
| ----- | --------------------------------- |
| 10:02 | Brute-force attack begins         |
| 10:07 | Excessive login failures detected |
| 10:10 | Successful RDP login              |
| 10:11 | Suspicious PowerShell execution   |
| 10:12 | Mass file renaming                |
| 10:13 | Defender alert generated          |
| 10:15 | Endpoint isolated                 |

---

# Evidence Collected

Artifacts included in this repository:

* Sentinel detection screenshots
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
* Network Traffic Analysis
* MITRE ATT&CK Mapping
* Security Monitoring

---

# Key Takeaways

This lab demonstrates how security teams detect and respond to a ransomware attack initiated through credential compromise.

Using Microsoft Sentinel, Defender for Endpoint, and network traffic analysis tools, the SOC successfully identified the attack, investigated attacker behavior, and contained the threat.
