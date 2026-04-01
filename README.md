# Incident Response Lab – RDP Brute Force Detection (Microsoft Sentinel)

## 📌 Overview
This project simulates a brute-force attack against a Windows Server hosted in Microsoft Azure and demonstrates detection, investigation, and response using Microsoft Sentinel (SIEM).

The goal of this lab was to replicate a real-world SOC (Security Operations Center) scenario involving unauthorized login attempts and apply incident response procedures aligned with the NIST 800-61 framework.

---

## 🏗️ Lab Architecture

<img width="2048" height="1365" alt="image" src="https://github.com/user-attachments/assets/937fdc22-0ae7-4bd1-97c9-d4f479dfbc95" />

---

## ⚔️ Attack Simulation

A brute-force attack was simulated by generating repeated failed login attempts against the target Windows Server.

> Note: Hydra was initially used for attack simulation, but due to RDP negotiation limitations in Azure environments, failed login attempts were generated directly to simulate realistic attack telemetry.

---

## 🔍 Detection in Microsoft Sentinel

The attack was detected using Windows Security Event logs. Below shows failed logons in Window's Event Viewer

<img width="780" height="407" alt="Window-Event-Viewer-4625-logs" src="https://github.com/user-attachments/assets/86181aa6-afcb-496e-9a6d-5b925a4e6385" />


---


## Failed Login Detection Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress
| order by FailedAttempts desc
```

Key Detection Indicators
-High volume of failed login attempts
-Repeated authentication failures from a single source
-Targeting of a specific user account

<img width="1554" height="796" alt="Sentinel Brute Force Detection" src="https://github.com/user-attachments/assets/5b0ea438-8191-491a-9a9b-5ece548cb87f" />

---

## 🧠 Investigation
Timeline Analysis

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 5m)
```
This revealed a spike in login attempts within a short timeframe, indicating a brute-force attack.

<img width="1558" height="807" alt="Sentinel Attack timeline" src="https://github.com/user-attachments/assets/1a833768-326e-4ab2-b8e0-130227fdcdc9" />


## Targeted Account Identification

---

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by Account
```
Findings:
- Targeted account: testadmin

<img width="1554" height="760" alt="Sentinel Target Account" src="https://github.com/user-attachments/assets/bf42519e-e7ae-45cf-a606-acb2b0816557" />

---

 ## 🔓 Simulated Account Compromise

To simulate a successful breach, a login event was generated.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
```
Event ID 4624 confirms a successful RDP login.

<img width="1551" height="808" alt="Sentinel Successful Logon" src="https://github.com/user-attachments/assets/0a29e30d-22f0-4238-85fb-4dd2f5ed0259" />


---

## 🚨 Incident Response
Containment Actions
- Identified compromised account: testadmin
- Disabled account to prevent further unauthorized access
- Verified containment through system logs

---

## Account Disable Verification

```kql
SecurityEvent
| where EventID == 4725
```
Event ID 4725 confirms the account was disabled.

<img width="1552" height="822" alt="image" src="https://github.com/user-attachments/assets/29e47f14-8839-46b2-8fff-8f00854f378c" />


---

## 🛡️ Incident Response Lifecycle

This lab follows the NIST 800-61 Incident Response Framework:

1. Detection & Analysis
- Identified abnormal login activity (4625 events)
2. Containment
- Disabled compromised account
3. Eradication
- Prevented further access
4. Recovery
- Verified system stability
5. Lessons Learned
- Identified need for account lockout policies

---

## 📊 Key Windows Event IDs

Event ID	               Description
 4625	             Failed login attempt
 4624	               Successful login
 4725	               Account disabled

---

## 📸 Screenshots

- Sentinel Log Ingestion
- Failed Login Events (Event Viewer)
- Brute Force Detection Query
- Attack Timeline Visualization
- Targeted Account Identification
- Successful Login Detection
- Account Disabled (Containment)

---

## 🧰 Skills Demonstrated
- SIEM Monitoring (Microsoft Sentinel)
- Log Analysis (Windows Security Logs)
- Threat Detection (Brute Force Attacks)
- Incident Investigation
- Incident Response & Containment
- Azure Cloud Security
- KQL (Kusto Query Language)

---

## 🎯 Key Takeaways
Brute-force attacks can be effectively detected using authentication logs
SIEM tools enable centralized monitoring and investigation
Rapid containment is critical to preventing further compromise
Cloud-based environments require proper logging and monitoring configurations

---

## 📁 Project Structure

```
incident-response-sentinel-lab
│
├── README.md
│
├── screenshots
│   ├── sentinel-detection.png
│   ├── eventviewer-4625.png
│   ├── attack-timeline.png
│   ├── targeted-account.png
│   └── account-disabled.png
│
├── queries
│   └── sentinel-kql-queries.md
│
└── incident-report
    └── incident-report.md
```

---

## ✅ Conclusion

This project demonstrates the ability to detect, analyze, and respond to a brute-force attack using Microsoft Sentinel in a cloud environment. The lab simulates real-world SOC operations and highlights key cybersecurity skills required for an entry-level security analyst role.


