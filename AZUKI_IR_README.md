# 🕵️‍♂️ Incident Response Case Study: Project Azuki_Threat Hunt

| Incident ID | Severity | Analyst | Status |
| :--- | :--- | :--- | :--- |
| **INC-2025-1119-001** | 🔴 HIGH | Christopher Rajasekar | **Eradicated** |

## 📝 Executive Summary
This repository contains a comprehensive investigation into the compromise of a virtual machine at **Azuki Import/Export Trading Co.** [cite: 62]. The attack, attributed to the threat group **JADE SPIDER**, involved a multi-stage intrusion resulting in the theft of sensitive supplier contracts and pricing data [cite: 67, 72, 76].

The impact was significant: a competitor used the exfiltrated data to undercut Azuki's shipping contract by exactly 3%, leading to the loss of a 6-year business agreement [cite: 97, 114].

---

## 📅 Investigation Timeline (2025-11-19)
The entire attack chain was automated via a PowerShell script (`Wupdate.ps1`) and executed within a single day [cite: 70, 93]:

* **Initial Access:** RDP brute-force/credential abuse from external IP `88.97.178.12` using the `kenji.sato` (IT Admin) account [cite: 67, 76, 79].
* **Reconnaissance:** Execution of `ARP.EXE -a` to enumerate internal network neighbors [cite: 80, 101].
* **Staging:** Creation of a hidden/system directory `C:\ProgramData\WindowsCache` [cite: 81, 102].
* **Persistence:** Registration of a scheduled task 'Windows Update Check' and creation of a hidden local admin account 'Support' [cite: 73, 84, 90, 105].
* **Exfiltration:** Data archived as `export-data.zip` and uploaded to a **Discord webhook** via `curl.exe` [cite: 72, 88, 109].
* **Anti-Forensics:** Windows Security, System, and Application logs were cleared using `wevtutil.exe` [cite: 91, 112].

---

## 🔍 KQL Hunting Queries (Microsoft Defender for Endpoint)

### 1. Identify Initial RDP Entry
```kusto
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType, AccountName
| sort by Timestamp asc
```
**Result:** Confirmed RDP connection from `88.97.178.12` using account `kenji.sato` [cite: 161, 162].

### 2. Detection of Staging & Persistence
```kusto
DeviceProcessEvents
| where ProcessCommandLine has "WindowsCache"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
```
**Result:** Identified directory hiding via `attrib.exe` and malicious scheduled task creation [cite: 164, 165].

### 3. Exfiltration via Web Service (Discord)
```kusto
DeviceProcessEvents
| where FileName == "curl.exe"
| project Timestamp, DeviceName, ProcessCommandLine
| sort by Timestamp asc
```
**Result:** Captured the `curl.exe` POST command uploading `export-data.zip` to a Discord API webhook [cite: 167, 168].

---

## 🏷️ MITRE ATT&CK Mapping
| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts | T1078 | Compromised `kenji.sato` creds [cite: 143]. |
| **Execution** | PowerShell | T1059.001 | `Wupdate.ps1` automation [cite: 143]. |
| **Persistence** | Scheduled Task | T1053.005 | 'Windows Update Check' task [cite: 143]. |
| **Defense Evasion** | Indicator Removal | T1070.001 | Cleared event logs (`wevtutil`) [cite: 143]. |
| **Credential Access** | LSASS Memory | T1003.001 | `mm.exe` (Mimikatz) execution [cite: 143]. |
| **Exfiltration** | Over Web Service | T1567 | `curl.exe` to Discord webhook [cite: 143]. |

---

## 🛑 Indicators of Compromise (IOCs)
* **Attacker IPs:** `88.97.178.12` (Source), `78.141.196.6` (C2) [cite: 141].
* **Malicious Files:** `svchost.exe` (Beacon), `mm.exe` (Mimikatz), `Wupdate.ps1` [cite: 141].
* **Persistence:** Scheduled Task: `Windows Update Check`; Local Account: `Support` [cite: 141].

---

## 🛡️ Remediation & Recommendations
* **Immediate:** Isolate compromised hosts (`AZUKI-SL` and `10.1.0.188`) and block malicious IPs at the perimeter [cite: 117, 118, 123].
* **Short-Term:** Enforce MFA on all RDP-accessible accounts and restrict access to known-good IP ranges/VPN [cite: 126, 127].
* **Long-Term:** Deploy EDR with LSASS protection and implement network segmentation to prevent lateral movement [cite: 134, 135].

---
Incident Report :[IR_Report_Azuki.pdf](https://github.com/user-attachments/files/26247609/IR_Report_Azuki.pdf)

ThurtHunt investigation:[Port of Entry_Threat Hunt_Detailed Report.pdf](https://github.com/user-attachments/files/26247603/Port.of.Entry_Threat.Hunt_Detailed.Report.pdf)
