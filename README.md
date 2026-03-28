# Incident Response Lab – RDP Brute Force Detection (Microsoft Sentinel)

## 📌 Overview
This project simulates a brute-force attack against a Windows Server hosted in Microsoft Azure and demonstrates detection, investigation, and response using Microsoft Sentinel (SIEM).

The goal of this lab was to replicate a real-world SOC (Security Operations Center) scenario involving unauthorized login attempts and apply incident response procedures aligned with the NIST 800-61 framework.

---

## 🏗️ Lab Architecture

- **Cloud Platform:** Microsoft Azure
- **Attacker Machine:** Kali Linux VM
- **Target Machine:** Windows Server VM
- **Monitoring Tools:**
  - Azure Monitor Agent (AMA)
  - Log Analytics Workspace
  - Microsoft Sentinel (SIEM)

### Data Flow

Kali Linux (Attacker)
↓ 

RDP Authentication Attempts
↓

Windows Security Logs (Event Viewer)
↓

Azure Monitor Agent
↓

Log Analytics Workspace
↓

Microsoft Sentinel
↓

SOC Investigation and Response


---

## ⚔️ Attack Simulation

A brute-force attack was simulated by generating repeated failed login attempts against the target Windows Server.

> Note: Hydra was initially used for attack simulation, but due to RDP negotiation limitations in Azure environments, failed login attempts were generated directly to simulate realistic attack telemetry.

---

## 🔍 Detection in Microsoft Sentinel

The attack was detected using Windows Security Event logs.

### Failed Login Detection Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress
| order by FailedAttempts desc

Key Detection Indicators
-High volume of failed login attempts
-Repeated authentication failures from a single source
-Targeting of a specific user account

---

🧠 Investigation
Timeline Analysis

SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 5m)

This revealed a spike in login attempts within a short timeframe, indicating a brute-force attack.

Targeted Account Identification

SecurityEvent
| where EventID == 4625
| summarize count() by Account

Findings:
- Targeted account: testadmin

🔓 Simulated Account Compromise

To simulate a successful breach, a login event was generated.

SecurityEvent
| where EventID == 4624
| where LogonType == 10

Event ID 4624 confirms a successful RDP login.


🚨 Incident Response
Containment Actions
- Identified compromised account: testadmin
- Disabled account to prevent further unauthorized access
- Verified containment through system logs

Account Disable Verification

SecurityEvent
| where EventID == 4725

Event ID 4725 confirms the account was disabled.


🛡️ Incident Response Lifecycle

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


📊 Key Windows Event IDs

Event ID	               Description
 4625	             Failed login attempt
 4624	               Successful login
 4725	               Account disabled


📸 Screenshots

- Sentinel Log Ingestion
- Failed Login Events (Event Viewer)
- Brute Force Detection Query
- Attack Timeline Visualization
- Targeted Account Identification
- Successful Login Detection
- Account Disabled (Containment)


🧰 Skills Demonstrated
- SIEM Monitoring (Microsoft Sentinel)
- Log Analysis (Windows Security Logs)
- Threat Detection (Brute Force Attacks)
- Incident Investigation
- Incident Response & Containment
- Azure Cloud Security
- KQL (Kusto Query Language)


🎯 Key Takeaways
Brute-force attacks can be effectively detected using authentication logs
SIEM tools enable centralized monitoring and investigation
Rapid containment is critical to preventing further compromise
Cloud-based environments require proper logging and monitoring configurations


📁 Project Structure

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


✅ Conclusion

This project demonstrates the ability to detect, analyze, and respond to a brute-force attack using Microsoft Sentinel in a cloud environment. The lab simulates real-world SOC operations and highlights key cybersecurity skills required for an entry-level security analyst role.


