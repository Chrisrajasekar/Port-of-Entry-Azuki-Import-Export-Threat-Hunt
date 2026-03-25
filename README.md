# Port-of-Entry-Azuki-Import-Export-Threat-Hunt

INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社SITUATION: Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums. COMPANY: Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia COMPROMISED SYSTEMS: AZUKI-SL (IT admin workstation)

# 🕵️‍♂️ Incident Response Case Study: Project Azuki_Threat Hunt

| Incident ID | Severity | Analyst | Status |
| :--- | :--- | :--- | :--- |
| **INC-2025-1119-001** | 🔴 HIGH | Christopher Rajasekar | **Eradicated** |

## 📝 Executive Summary
This repository contains a comprehensive investigation into the compromise of a virtual machine at **Azuki Import/Export Trading Co.** [cite: 62]. The attack, attributed to the threat group **JADE SPIDER**, involved a multi-stage intrusion resulting in the theft of sensitive supplier contracts and pricing data.

The impact was significant: a competitor used the exfiltrated data to undercut Azuki's shipping contract by exactly 3%, leading to the loss of a 6-year business agreement.

---

## 📅 Investigation Timeline (2025-11-19)
The entire attack chain was automated via a PowerShell script (`Wupdate.ps1`) and executed within a single day:

* **Initial Access:** RDP brute-force/credential abuse from external IP `88.97.178.12` using the `kenji.sato` (IT Admin) account.
* **Reconnaissance:** Execution of `ARP.EXE -a` to enumerate internal network neighbors.
* **Staging:** Creation of a hidden/system directory `C:\ProgramData\WindowsCache`.
* **Persistence:** Registration of a scheduled task 'Windows Update Check' and creation of a hidden local admin account 'Support'.
* **Exfiltration:** Data archived as `export-data.zip` and uploaded to a **Discord webhook** via `curl.exe`.
* **Anti-Forensics:** Windows Security, System, and Application logs were cleared using `wevtutil.exe`.

---

## 🔍 KQL Hunting Queries (Microsoft Defender for Endpoint)

### 1. Identify Initial RDP Entry
```kusto
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType, AccountName
| sort by Timestamp asc
```
**Result:** Confirmed RDP connection from `88.97.178.12` using account `kenji.sato`.

### 2. Detection of Staging & Persistence
```kusto
DeviceProcessEvents
| where ProcessCommandLine has "WindowsCache"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
**Result:** Identified directory hiding via `attrib.exe` and malicious scheduled task creation.

### 3. Exfiltration via Web Service (Discord)
```kusto
DeviceProcessEvents
| where FileName == "curl.exe"
| project Timestamp, DeviceName, ProcessCommandLine
| sort by Timestamp asc
```
**Result:** Captured the `curl.exe` POST command uploading `export-data.zip` to a Discord API webhook.

---

## 🏷️ MITRE ATT&CK Mapping
| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts | T1078 | Compromised `kenji.sato` creds  |
| **Execution** | PowerShell | T1059.001 | `Wupdate.ps1` automation. |
| **Persistence** | Scheduled Task | T1053.005 | 'Windows Update Check' task. |
| **Defense Evasion** | Indicator Removal | T1070.001 | Cleared event logs (`wevtutil`). |
| **Credential Access** | LSASS Memory | T1003.001 | `mm.exe` (Mimikatz) execution. |
| **Exfiltration** | Over Web Service | T1567 | `curl.exe` to Discord webhook. |

---

## 🛑 Indicators of Compromise (IOCs)
* **Attacker IPs:** `88.97.178.12` (Source), `78.141.196.6` (C2).
* **Malicious Files:** `svchost.exe` (Beacon), `mm.exe` (Mimikatz), `Wupdate.ps1` .
* **Persistence:** Scheduled Task: `Windows Update Check`; Local Account: `Support` .

---

## 🛡️ Remediation & Recommendations
* **Immediate:** Isolate compromised hosts (`AZUKI-SL` and `10.1.0.188`) and block malicious IPs at the perimeter [.
* **Short-Term:** Enforce MFA on all RDP-accessible accounts and restrict access to known-good IP ranges/VPN .
* **Long-Term:** Deploy EDR with LSASS protection and implement network segmentation to prevent lateral movement.

---
Incident Report :[IR_Report_Azuki.pdf](https://github.com/user-attachments/files/26247609/IR_Report_Azuki.pdf)

ThurtHunt investigation:[Port of Entry_Threat Hunt_Detailed Report.pdf](https://github.com/user-attachments/files/26247603/Port.of.Entry_Threat.Hunt_Detailed.Report.pdf)
