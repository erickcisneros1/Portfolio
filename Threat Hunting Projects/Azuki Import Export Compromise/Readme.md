# 🚨 Incident Report: Azuki Import/Export Compromise

**Report ID:** INC-2025-XXXX
**Date:** November 23, 2025 🗓️
**Analyst:** Erick Cisneros Ruballos 👨‍💻
**Incident Date:** November 19, 2025 📅
**Status:** Contained 🔒

---

## 1. Executive Summary 📝

**Situation:** Azuki Import/Export Trading Co. experienced a **targeted intrusion** where a competitor undercut a shipping contract by exactly 3%. 📉

**Assessment:** An external attacker compromised the IT admin workstation (`AZUKI-SL` - 🖥️) via **Remote Desktop Protocol (RDP)**. The attacker established **persistence**, harvested **credentials**, and **exfiltrated** sensitive data using **Discord**.

**Impact:** High - Supplier contracts and pricing data appeared on underground forums. 💰

**Impact Level:** High
**Status:** Contained 🛑

---

## 2. Incident Timeline & Attack Chain 🔗

The investigation reconstructed the following attack chain based on Microsoft Defender for Endpoint (MDE) logs.

### Timeline 🕰️

- **First Malicious Activity:** 2025-11-19T18:36:18.503997Z (UTC)
- **Last Observed Activity:** [To be determined]
- **Total Duration:** [To be determined]

### Attack Overview 🗺️

- **Initial Access Method:** Remote Access (RDP)
- **Compromised Account:** `kenji.sato` 👤
- **Affected System:** `azuki-sl` 💻
- **Attacker IP Address:** `88.97.178.12` 🌍

### Phase 1: Initial Access (TA0001) 🚪

The attacker gained access to the environment through an external RDP connection.

- **Source IP:** `88.97.178.12`
- **Compromised Account:** `kenji.sato`
- **Method:** Brute-force/Credential compromise via RDP

### Phase 2: Discovery (TA0007) 🔎

Immediately post-compromise, the attacker performed network reconnaissance to identify local network devices.

- **Command Used:** `"ARP.EXE" -a`

### Phase 3: Execution & Defense Evasion (TA0002, TA0005) 🔪

The attacker created a staging directory to hide malicious tools and modified Windows Defender settings to avoid detection.

- **Staging Directory:** `C:\ProgramData\WindowsCache` 📁
- **Malware Download:** Used `certutil.exe` (Living off the Land) to download malicious files
- **Defender Tampering:**
    - Added **3** file extension exclusions 🚫
    - Excluded the temporary path: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- **Automation:** Executed a PowerShell script named `wupdate.ps1` to automate the attack chain
- **Anti-Forensics:** Cleared the **Security** event log using `wevtutil` to cover tracks 👻

### Phase 4: Persistence (TA0003) 🔄

To maintain access across reboots, the attacker created a scheduled task designed to look like a legitimate system process.

- **Task Name:** `Windows Update Check` ⏱️
- **Target Payload:** `C:\ProgramData\WindowsCache\svchost.exe`
- **Backdoor Account:** A local administrator account named `support` was created

### Phase 5: Credential Access (TA0006) 🔑

The attacker utilized a renamed version of Mimikatz to dump credentials from memory.

- **Tool Name:** `mm.exe`
- **Command:** `sekurlsa::logonpasswords`

### Phase 6: Command & Control (TA0011) 📡

The malware established a connection to an external Command and Control (C2) server.

- **C2 IP:** `78.141.196.6`
- **Port:** `443` (HTTPS)

### Phase 7: Exfiltration (TA0010) 📤

Sensitive data was compressed and exfiltrated using a common messaging application.

- **Archive Name:** `export-data.zip` 📦
- **Exfiltration Channel:** **Discord** 💬

### Phase 8: Lateral Movement (TA0008) ➡️

The attacker attempted to pivot to other systems in the network.

- **Tool:** `mstsc.exe` (Remote Desktop Client)
- **Target IP:** `10.1.0.188`

---

## 3. Indicators of Compromise (IOCs) 🛑

| Type | Value | Context |
| :--- | :--- | :--- |
| **IP Address** 🌐 | `88.97.178.12` | Attacker Source / Initial Access |
| **IP Address** 🌐 | `78.141.196.6` | Command & Control (C2) |
| **IP Address** 🌐 | `10.1.0.188` | Lateral Movement Target |
| **User Account** 👤 | `kenji.sato` | Compromised Domain User |
| **User Account** 👤 | `support` | Backdoor Admin Account Created |
| **File Path** 📁 | `C:\ProgramData\WindowsCache` | Malware Staging Folder |
| **File Name** ⚙️ | `mm.exe` | Credential Dumping Tool (Mimikatz) |
| **File Name** ⚙️ | `wupdate.ps1` | Malicious PowerShell Script |
| **File Name** 📦 | `export-data.zip` | Stolen Data Archive |
| **File Name** ⚙️ | `svchost.exe` | Persistence Payload (in staging directory) |

---

## 4. MITRE ATT&CK Mapping 🛡️

| Tactic | Technique ID | Technique Name | Evidence |
| :--- | :--- | :--- | :--- |
| Initial Access 🚪 | T1078 | Valid Accounts | RDP compromise via `kenji.sato` account |
| Execution 🚀 | T1059.001 | PowerShell | `wupdate.ps1` script execution |
| Persistence ⏰ | T1053.005 | Scheduled Task | `Windows Update Check` scheduled task |
| Defense Evasion 👻 | T1562.001 | Disable or Modify Tools | Windows Defender exclusions added |
| Defense Evasion 👻 | T1070.001 | Clear Windows Event Logs | Security event log cleared via `wevtutil` |
| Discovery 🔎 | T1018 | Remote System Discovery | `ARP.EXE -a` command |
| Credential Access 🔑 | T1003.001 | LSASS Memory | Mimikatz (`mm.exe`) credential dumping |
| Lateral Movement ➡️ | T1021.001 | Remote Desktop Protocol | `mstsc.exe` connection to `10.1.0.188` |
| Command & Control 📞 | T1071.001 | Web Protocols | HTTPS connection to `78.141.196.6:443` |
| Exfiltration 📤 | T1041 | Exfiltration Over C2 Channel | Data exfiltrated via Discord |

---

## 5. Key Findings 🎯

### Primary IOCs

- **Malicious IPs:** 🌐
    - `88.97.178.12` (Initial Access)
    - `78.141.196.6` (C2 Server)
- **Malicious Files:** ⚙️
    - `mm.exe` (Mimikatz)
    - `wupdate.ps1` (PowerShell script)
    - `export-data.zip` (Exfiltrated data)
    - `C:\ProgramData\WindowsCache\svchost.exe` (Persistence payload)
- **Compromised Accounts:** 👤
    - `kenji.sato` (Initial compromise)
    - `support` (Backdoor account)
- **C2 Infrastructure:** 📡
    - `78.141.196.6:443` (HTTPS)

---

## 6. Recommendations ✅

### Immediate Actions (Do Now) ⚡

1. Reset all credentials for compromised accounts (`kenji.sato`, `support`) 🔑
2. Disable RDP access from external IPs or implement MFA 🛡️
3. Remove the scheduled task `Windows Update Check` 🗑️
4. Delete the staging directory `C:\ProgramData\WindowsCache` and its contents ❌
5. Restore Windows Defender exclusions to default settings
6. Block outbound connections to `78.141.196.6` 🛑
7. Review and restore Security event logs from backup if available

### Short-term (1-30 days) 🗓️

1. Implement network segmentation to limit lateral movement 🧱
2. Deploy endpoint detection and response (EDR) solutions across all systems 🔬
3. Conduct a full security audit of all user accounts and permissions
4. Implement application whitelisting to prevent execution of unauthorized tools 📃
5. Enhance logging and monitoring for RDP connections 📈

### Long-term (Security Improvements) ⭐

1. Implement multi-factor authentication (MFA) for all remote access
2. Deploy network monitoring and intrusion detection systems 🚧
3. Establish a security awareness training program 🧑‍🏫
4. Implement a zero-trust network architecture
5. Regular security assessments and penetration testing 🩺
6. Develop and maintain an incident response playbook 📘

---

## 7. Technical Appendix: KQL Queries 📊

The following KQL queries were used to validate the findings in Microsoft Defender for Endpoint.

### F. Flags (Initial Access & Discovery)

**Flag # 1 =** `88.97.178.12`
**Flag # 2 =** `kenji.sato`

```kusto
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "LogonSuccess"
| where RemoteIPType has "Public"
```

**Flag # 3 =** `"ARP.EXE" -a`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("arp.exe", "ipconfig.exe", "route.exe", "nbtstat.exe", "net.exe")
    or ProcessCommandLine contains "ping"
| project Timestamp, DeviceName, AccountDomain, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp desc
```

**Flag # 4 =** `C:\ProgramData\WindowsCache`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where (FileName in~ ("cmd.exe", "powershell.exe") and ProcessCommandLine has_any ("mkdir", "md", "New-Item"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath
```

### Defender Tampering

**Flag # 5 =** `3`
**Flag # 6 =** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

```kusto
DeviceRegistryEvents
| where RegistryKey has @"Windows Defender\Exclusions\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| summarize UniqueExtensions = dcount(RegistryValueName)
```

### Execution & Persistence

**Flag # 7 =** `certutil.exe`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where ProcessCommandLine has "http"
| project DeviceName, ActionType, FileName
| summarize count()by FileName
```

**Flag # 8 =** `Windows Update Check`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project AccountName, FileName, ProcessCommandLine
```

**Flag # 9 =** `C:\ProgramData\WindowsCache\svchost.exe`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/tr"
| project AccountName, FileName, ProcessCommandLine
```

### Command & Control (C2)

**Flag # 10 =** `78.141.196.6`

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where InitiatingProcessCommandLine has @"C:\ProgramData\WindowsCache\svchost.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

**Flag # 11 =** `443`

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| project RemotePort
```

### Credential Access

**Flag # 12 =** `mm.exe`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "dump"
| where DeviceName has "azuki"
```

**Flag # 13 =** `sekurlsa::logonpasswords`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "::"
|where FileName has "mm.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| where DeviceName has "azuki"
```

### Exfiltration

**Flag # 14 =** `export-data.zip`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "zip"
| where DeviceName has "azuki-sl"
```

**Flag # 15 =** `discord`

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki-sl"
| where InitiatingProcessFileName == "curl.exe"
```

### Defense Evasion & Persistence

**Flag # 16 =** `Security`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "wevtutil"
| where DeviceName has "azuki"
```

**Flag # 17 =** `support`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has @"/add"
| where DeviceName has "azuki"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Flag # 18 =** `wupdate.ps1`

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has ".ps1"
| where DeviceName has "azuki-sl"
| where InitiatingProcessCommandLine contains ".ps1"
| project Timestamp, DeviceName, InitiatingProcessCommandLine
```

### Lateral Movement

**Flag # 19 =** `10.1.0.188`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("mstsc.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("mstsc", "/v:", "-v")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**Flag # 20 =** `mstsc.exe`

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "mstsc.exe"
| extend TargetIP = extract(@'(\d{1,3}(?:\.\d{1,3}){3})', 0, ProcessCommandLine)
| where isnotempty(TargetIP)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, TargetIP
| order by Timestamp asc
```

---

## 8. Investigation Flags Reference 🚩

| Flag # | Value | Description |
| :--- | :--- | :--- |
| 1 | `88.97.178.12` | Attacker Source IP 🌐 |
| 2 | `kenji.sato` | Compromised Account 👤 |
| 3 | `"ARP.EXE" -a` | Discovery Command 🔎 |
| 4 | `C:\ProgramData\WindowsCache` | Staging Directory 📁 |
| 5 | `3` | Defender Exclusions Count 🚫 |
| 6 | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` | Excluded Temp Path |
| 7 | `certutil.exe` | Download Tool ⬇️ |
| 8 | `Windows Update Check` | Scheduled Task Name ⏱️ |
| 9 | `C:\ProgramData\WindowsCache\svchost.exe` | Persistence Payload 📦 |
| 10 | `78.141.196.6` | C2 IP Address 📞 |
| 11 | `443` | C2 Port |
| 12 | `mm.exe` | Credential Dumping Tool 🔑 |
| 13 | `sekurlsa::logonpasswords` | Mimikatz Command 🤫 |
| 14 | `export-data.zip` | Exfiltrated Archive 🤐 |
| 15 | `discord` | Exfiltration Channel 💬 |
| 16 | `Security` | Cleared Event Log 🧹 |
| 17 | `support` | Backdoor Account 👤 |
| 18 | `wupdate.ps1` | PowerShell Script 💻 |
| 19 | `10.1.0.188` | Lateral Movement Target ➡️ |
| 20 | `mstsc.exe` | Remote Desktop Client 🖥️ |

---

## 9. Supporting Evidence Checklist ✔️

- [✅] All screenshots attached
- [✅] Full query results attached
- [✅] Network logs reviewed
- [✅] File hashes documented

---

**Report Completed By:** Erick Cisneros Ruballos 
**Date:** November 23, 2025 
**Reviewed By:** [To be completed]
