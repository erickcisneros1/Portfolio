# Incident Report: Azuki Import/Export Compromise

**Report ID:** INC-2025-XXXX  
**Date:** November 23, 2025  
**Analyst:** Erick Cisneros Ruballos  
**Incident Date:** November 19, 2025  
**Status:** Contained  

---

## 1. Executive Summary

**Situation:** Azuki Import/Export Trading Co. experienced a targeted intrusion where a competitor undercut a shipping contract by exactly 3%.  

**Assessment:** An external attacker compromised the IT admin workstation (<code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">AZUKI-SL</code>) via Remote Desktop Protocol (RDP). The attacker established persistence, harvested credentials, and exfiltrated sensitive data using Discord.  

**Impact:** High - Supplier contracts and pricing data appeared on underground forums.

**Impact Level:** High  
**Status:** Contained

---

## 2. Incident Timeline & Attack Chain

The investigation reconstructed the following attack chain based on Microsoft Defender for Endpoint (MDE) logs.

### Timeline

- **First Malicious Activity:** 2025-11-19T18:36:18.503997Z (UTC)
- **Last Observed Activity:** [To be determined]
- **Total Duration:** [To be determined]

### Attack Overview

- **Initial Access Method:** Remote Access (RDP)
- **Compromised Account:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code>
- **Affected System:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">azuki-sl</code>
- **Attacker IP Address:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code>

### Phase 1: Initial Access (TA0001)

The attacker gained access to the environment through an external RDP connection.

- **Source IP:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code>
- **Compromised Account:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code>
- **Method:** Brute-force/Credential compromise via RDP

### Phase 2: Discovery (TA0007)

Immediately post-compromise, the attacker performed network reconnaissance to identify local network devices.

- **Command Used:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">"ARP.EXE" -a</code>

### Phase 3: Execution & Defense Evasion (TA0002, TA0005)

The attacker created a staging directory to hide malicious tools and modified Windows Defender settings to avoid detection.

- **Staging Directory:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache</code>
- **Malware Download:** Used <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">certutil.exe</code> (Living off the Land) to download malicious files
- **Defender Tampering:**
    - Added **3** file extension exclusions
    - Excluded the temporary path: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\Users\KENJI~1.SAT\AppData\Local\Temp</code>
- **Automation:** Executed a PowerShell script named <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code> to automate the attack chain
- **Anti-Forensics:** Cleared the **Security** event log using <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wevtutil</code> to cover tracks

### Phase 4: Persistence (TA0003)

To maintain access across reboots, the attacker created a scheduled task designed to look like a legitimate system process.

- **Task Name:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Windows Update Check</code>
- **Target Payload:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache\svchost.exe</code>
- **Backdoor Account:** A local administrator account named <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code> was created

### Phase 5: Credential Access (TA0006)

The attacker utilized a renamed version of Mimikatz to dump credentials from memory.

- **Tool Name:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code>
- **Command:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">sekurlsa::logonpasswords</code>

### Phase 6: Command & Control (TA0011)

The malware established a connection to an external Command and Control (C2) server.

- **C2 IP:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code>
- **Port:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">443</code> (HTTPS)

### Phase 7: Exfiltration (TA0010)

Sensitive data was compressed and exfiltrated using a common messaging application.

- **Archive Name:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">export-data.zip</code>
- **Exfiltration Channel:** **Discord**

### Phase 8: Lateral Movement (TA0008)

The attacker attempted to pivot to other systems in the network.

- **Tool:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mstsc.exe</code> (Remote Desktop Client)
- **Target IP:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">10.1.0.188</code>

---

## 3. Indicators of Compromise (IOCs)

| Type | Value | Context |
| :--- | :--- | :--- |
| **IP Address** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code> | Attacker Source / Initial Access |
| **IP Address** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code> | Command & Control (C2) |
| **IP Address** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">10.1.0.188</code> | Lateral Movement Target |
| **User Account** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code> | Compromised Domain User |
| **User Account** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code> | Backdoor Admin Account Created |
| **File Path** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache</code> | Malware Staging Folder |
| **File Name** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code> | Credential Dumping Tool (Mimikatz) |
| **File Name** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code> | Malicious PowerShell Script |
| **File Name** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">export-data.zip</code> | Stolen Data Archive |
| **File Name** | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">svchost.exe</code> | Persistence Payload (in staging directory) |

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
| :--- | :--- | :--- | :--- |
| Initial Access | T1078 | Valid Accounts | RDP compromise via <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code> account |
| Execution | T1059.001 | PowerShell | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code> script execution |
| Persistence | T1053.005 | Scheduled Task | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Windows Update Check</code> scheduled task |
| Defense Evasion | T1562.001 | Disable or Modify Tools | Windows Defender exclusions added |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | Security event log cleared via <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wevtutil</code> |
| Discovery | T1018 | Remote System Discovery | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">ARP.EXE -a</code> command |
| Credential Access | T1003.001 | LSASS Memory | Mimikatz (<code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code>) credential dumping |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mstsc.exe</code> connection to <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">10.1.0.188</code> |
| Command & Control | T1071.001 | Web Protocols | HTTPS connection to <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6:443</code> |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data exfiltrated via Discord |

---

## 5. Key Findings

### Primary IOCs

- **Malicious IPs:** 
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code> (Initial Access)
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code> (C2 Server)
- **Malicious Files:** 
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code> (Mimikatz)
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code> (PowerShell script)
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">export-data.zip</code> (Exfiltrated data)
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache\svchost.exe</code> (Persistence payload)
- **Compromised Accounts:** 
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code> (Initial compromise)
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code> (Backdoor account)
- **C2 Infrastructure:** 
    - <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6:443</code> (HTTPS)

---

## 6. Recommendations

### Immediate Actions (Do Now)

1. Reset all credentials for compromised accounts (<code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code>, <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code>)
2. Disable RDP access from external IPs or implement MFA
3. Remove the scheduled task <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Windows Update Check</code>
4. Delete the staging directory <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache</code> and its contents
5. Restore Windows Defender exclusions to default settings
6. Block outbound connections to <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code>
7. Review and restore Security event logs from backup if available

### Short-term (1-30 days)

1. Implement network segmentation to limit lateral movement
2. Deploy endpoint detection and response (EDR) solutions across all systems
3. Conduct a full security audit of all user accounts and permissions
4. Implement application whitelisting to prevent execution of unauthorized tools
5. Enhance logging and monitoring for RDP connections

### Long-term (Security Improvements)

1. Implement multi-factor authentication (MFA) for all remote access
2. Deploy network monitoring and intrusion detection systems
3. Establish a security awareness training program
4. Implement a zero-trust network architecture
5. Regular security assessments and penetration testing
6. Develop and maintain an incident response playbook

---

## 7. Technical Appendix: KQL Queries

The following KQL queries were used to validate the findings in Microsoft Defender for Endpoint.

### Query 1: Initial Access (RDP Source)

```kusto
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "LogonSuccess"
| where RemoteIPType has "Public"
```

**Results:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code>

### Query 2: Discovery Activity

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("arp.exe", "ipconfig.exe", "route.exe", "nbtstat.exe", "net.exe")
    or ProcessCommandLine contains "ping"
| project Timestamp, DeviceName, AccountDomain, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Query 3: Persistence Detection

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where (FileName in~ ("cmd.exe", "powershell.exe") and ProcessCommandLine has_any ("mkdir", "md", "New-Item"))
     or (FileName =~ "attrib.exe" and ProcessCommandLine contains "+h")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by Timestamp desc
```

### Query 4: Windows Defender Exclusions

```kusto
DeviceRegistryEvents
| where RegistryKey has @"Windows Defender\Exclusions\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| summarize UniqueExtensions = dcount(RegistryValueName)
```

**Results:** 3 file extension exclusions added

### Query 5: Certutil Download Activity

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where ProcessCommandLine has "http"
| project DeviceName, ActionType, FileName
| summarize count() by FileName
```

**Results:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">certutil.exe</code> used for downloads

### Query 6: Scheduled Task Creation

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project AccountName, FileName, ProcessCommandLine
```

**Results:** Task name: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Windows Update Check</code>

### Query 7: Scheduled Task Payload

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/tr"
| project AccountName, FileName, ProcessCommandLine
```

**Results:** Payload: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache\svchost.exe</code>

### Query 8: Command & Control Connection

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki"
| where InitiatingProcessCommandLine has @"C:\ProgramData\WindowsCache\svchost.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

**Results:** C2 IP: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code>, Port: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">443</code>

### Query 9: Credential Dumping Tool

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "dump"
| where DeviceName has "azuki"
```

**Results:** Tool: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code>

### Query 10: Mimikatz Command

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "::"
| where FileName has "mm.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| where DeviceName has "azuki"
```

**Results:** Command: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">sekurlsa::logonpasswords</code>

### Query 11: Data Exfiltration Archive

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "zip"
| where DeviceName has "azuki-sl"
```

**Results:** Archive: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">export-data.zip</code>

### Query 12: Discord Exfiltration

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName has "azuki-sl"
| where InitiatingProcessFileName == "curl.exe"
```

**Results:** Discord exfiltration detected

### Query 13: Event Log Clearing

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "wevtutil"
| where DeviceName has "azuki"
```

**Results:** Security event log cleared

### Query 14: Backdoor Account Creation

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has @"/add"
| where DeviceName has "azuki"
| project Timestamp, DeviceName, ProcessCommandLine
```

**Results:** Account <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code> created

### Query 15: PowerShell Script Execution

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has ".ps1"
| where DeviceName has "azuki-sl"
| where InitiatingProcessCommandLine contains ".ps1"
| project Timestamp, DeviceName, InitiatingProcessCommandLine
```

**Results:** Script: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code>

### Query 16: Lateral Movement Target

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("mstsc.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("mstsc", "/v:", "-v")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**Results:** Target IP: <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">10.1.0.188</code>

### Query 17: Remote Desktop Client Usage

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "mstsc.exe"
| extend TargetIP = extract(@'(\d{1,3}(?:\.\d{1,3}){3})', 0, ProcessCommandLine)
| where isnotempty(TargetIP)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, TargetIP
| order by Timestamp asc
```

**Results:** <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mstsc.exe</code> used for lateral movement

---

## 8. Investigation Flags Reference

| Flag # | Value | Description |
| :--- | :--- | :--- |
| 1 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">88.97.178.12</code> | Attacker Source IP |
| 2 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">kenji.sato</code> | Compromised Account |
| 3 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">"ARP.EXE" -a</code> | Discovery Command |
| 4 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache</code> | Staging Directory |
| 5 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">3</code> | Defender Exclusions Count |
| 6 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\Users\KENJI~1.SAT\AppData\Local\Temp</code> | Excluded Temp Path |
| 7 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">certutil.exe</code> | Download Tool |
| 8 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Windows Update Check</code> | Scheduled Task Name |
| 9 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">C:\ProgramData\WindowsCache\svchost.exe</code> | Persistence Payload |
| 10 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">78.141.196.6</code> | C2 IP Address |
| 11 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">443</code> | C2 Port |
| 12 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mm.exe</code> | Credential Dumping Tool |
| 13 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">sekurlsa::logonpasswords</code> | Mimikatz Command |
| 14 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">export-data.zip</code> | Exfiltrated Archive |
| 15 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">discord</code> | Exfiltration Channel |
| 16 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">Security</code> | Cleared Event Log |
| 17 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">support</code> | Backdoor Account |
| 18 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">wupdate.ps1</code> | PowerShell Script |
| 19 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">10.1.0.188</code> | Lateral Movement Target |
| 20 | <code style="background-color: rgb(0, 120, 215); color: white; padding: 2px 4px; border-radius: 3px;">mstsc.exe</code> | Remote Desktop Client |

---

## 9. Supporting Evidence Checklist

- [✅] All screenshots attached
- [✅] Full query results attached
- [✅] Network logs reviewed
- [✅] File hashes documented

---

**Report Completed By:** Erick Cisneros Ruballos  
**Date:** November 23, 2025  
**Reviewed By:** [To be completed]
