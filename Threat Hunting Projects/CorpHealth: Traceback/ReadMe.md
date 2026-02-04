# Incident Response Report: CorpHealth Operations Intrusion

**Date:** December 05, 2025  
**Investigation Status:** Closed / Complete  
**Classification:** High Severity  
**Analyst:** Erick Cisneros Ruballos  
**Subject:** Compromise of Asset ch-ops-wks02 via Compromised Credentials and PowerShell Tooling

---

## 1. Executive Summary

During a routine operational review between November 21, 2025, and December 3, 2025, anomalous activity was detected on workstation `ch-ops-wks02`. The investigation confirmed that a threat actor gained unauthorized access using valid credentials (`chadmin`), performed local reconnaissance, escalated privileges via token manipulation, and established persistence using scheduled tasks and startup folders.

The attacker successfully staged internal data for exfiltration and deployed a reverse shell (`revshell.exe`) downloaded via an external ngrok tunnel. The threat actor originated from an external IP geolocated to Vietnam and utilized an internal pivot point to reach the target.

---

## 2. Investigation Scope & Methodology

- **Target Asset:** `ch-ops-wks02`
- **Time Window:** Nov 21, 2025 – Dec 03, 2025
- **Data Sources:** Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceLogonEvents)
- **Investigation Triggers:**
  - Script execution outside standard maintenance windows
  - Suspicious outbound beaconing patterns
  - Creation of files in diagnostic directories

---

## 3. Incident Narrative & Timeline

The following timeline reconstructs the attack chain based on telemetry analysis.

### Phase 1: Initial Access & Reconnaissance

- **Earliest Logon:** `2025-11-23T03:08:31.1849379Z`
- **Vector:** The attacker logged in using the account `chadmin` from external IP `104.164.168.17` (Vietnam)
- **Immediate Action:** The attacker executed `explorer.exe` followed by accessing a sensitive file: `CH-OPS-WKS02 user-pass.txt`
- **Recon:** Executed `ipconfig.exe` to map network interfaces

### Phase 2: Execution & Staging

- **Malicious Script:** Execution of `MaintenanceRunner_Distributed.ps1`
- **Beaconing:** The script attempted to beacon to `127.0.0.1:8080`, successfully connecting at `2025-11-30T01:03:17.6985973Z`

#### Data Staging:

- **Primary Artifact:** Created `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
- **Secondary Artifact:** Created a modified copy at `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`
- **Note:** The hashes of these two files differed, indicating modification/tampering during staging

### Phase 3: Persistence & Privilege Escalation

- **Registry Modification:** Tampering with `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
- **Scheduled Task:** Created task `CorpHealth_A65E64` to maintain access
- **Run Key:** Added `MaintenanceRunner` to the Registry Run keys, then deleted it (Ephemeral Persistence)
- **Token Manipulation:** A process (PID `4888`) modified the token privileges for user SID `S-1-5-21-1605642021-30596605-784192815-1000` to escalate privileges (Event: `ProcessPrimaryTokenModified`)
- **Defense Evasion:** Attempted to add `C:\ProgramData\Corp\Ops\staging` to Windows Defender exclusions using `Add-MpPreference`

### Phase 4: Command & Control (C2)

- **Ingress:** Used `curl.exe` to download a payload from `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
- **Payload Execution:** `revshell.exe` was executed by `explorer.exe`
- **Egress:** The binary attempted to connect to `13.228.171.119` on port `11746`
- **Additional Persistence:** `revshell.exe` was copied to `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` for execution on reboot

---

## 4. Technical Findings & Evidence

### 4.1. Compromised Accounts

| Account Name | Context |
|-------------|---------|
| `chadmin` | Used for initial access and recon |
| `ops.maintenance` | Accessed immediately following initial enumeration |

### 4.2. Network Indicators

- **Attacker Origin IP:** `104.164.168.17` (Geo: Vietnam)
- **Internal Pivot IP:** `10.168.0.7` (Azure VNet pivot)
- **Remote Session Metadata:**
  - **Device Name:** "对手" (Chinese for "Adversary" or "Opponent")
  - **Remote Session IP:** `100.64.100.6` (Likely CGNAT or VPN)
- **C2 Destination:** `13.228.171.119:11746`
- **Payload Source:** `*.ngrok-free.dev` (Dynamic tunneling service)

### 4.3. Malicious Files & Hashes

| Filename | Path |
|----------|------|
| `MaintenanceRunner_Distributed.ps1` | Various |
| `inventory_6ECFD4DF.csv` | `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\` |
| `revshell.exe` | User Profile & Startup Folder |

---

## 5. Investigation Traceback (Detailed Narrative & Queries)

The following section details the step-by-step threat hunt, presented as a narrative of discovery. Each step includes the specific indicator found and the KQL query used to uncover it.

### Phase 1: Identifying the Anomaly

The investigation began by scoping a specific device that showed signs of anomalous behavior during a maintenance window. Using process events, we isolated the primary workstation involved in the incident.

#### Flag 0: Identify the Device

- **Question:** Identify the primary device in the initial sweep
- **Answer:** `ch-ops-wks02`
- **KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-01-20 00:00:00) .. datetime(2025-01-20 10:00:00))
| where DeviceName has "ch-"
| distinct TimeGenerated, DeviceName, DeviceId, AccountName
```

Once the device was identified, we looked for suspicious files. A specific PowerShell script was found distributed across the environment, which appeared to be the primary vessel for the malicious activity.

#### Flag 1: Identify the Script/File

- **Question:** Identify the suspicious PowerShell script
- **Answer:** `MaintenanceRunner_Distributed.ps1`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10 00:00:00))
| where FileName has ".ps1"
| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName)
```

#### Flag 2: Script Execution Timestamp

- **Question:** The script's command line should appear inside `InitiatingProcessCommandLine`
- **Answer:** `2025-11-23T03:46:08.400686Z`

### Phase 2: Analyzing Network Beacons

With the script identified, we analyzed its network behavior. It was observed attempting to "beacon" or connect to a local listener, suggesting a setup for internal command and control.

#### Flag 3: Beacon Destination

- **Question:** What Remote IP and port did CH-OPS-WKS02 attempt to connect to during the beacon event?
- **Answer:** `127.0.0.1:8080`
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName has "CH-OPS-WKS02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, Protocol, Action
| order by TimeGenerated asc
```

#### Flag 4: Successful Connection

- **Question:** What timestamp shows the successful connection to the beacon destination?
- **Answer:** `2025-11-30T01:03:17.6985973Z`
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName = "CH-OPS-WKS02"
| where RemoteIP == "127.0.0.1" and RemotePort == 8080
| where ActionType == "ConnectionSuccess"
| project TimeGenerated
```

### Phase 3: Data Staging Analysis

The attacker created multiple files in diagnostic directories, suggesting data staging for exfiltration.

#### Flag 5: Primary Staging File

- **Question:** What is the full path of the primary staging file created in the diagnostics directory?
- **Answer:** `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where FolderPath contains "Diagnostics"
| where ActionType == "FileCreated"
| project FolderPath, FileName
```

#### Flag 6: Secondary Staging File

- **Question:** What is the path of the modified copy created in the temp directory?
- **Answer:** `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where FolderPath contains "Temp" and FileName contains "inventory"
| project FolderPath, FileName
```

### Phase 4: Persistence Mechanisms

Multiple persistence mechanisms were identified, indicating the attacker's intent to maintain long-term access.

#### Flag 7: Registry Tampering

- **Question:** Which registry key was tampered with?
- **Answer:** `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
- **KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains "CorpHealthAgent"
| project RegistryKey, RegistryValueName
```

#### Flag 8: Scheduled Task

- **Question:** What is the name of the scheduled task created for persistence?
- **Answer:** `CorpHealth_A65E64`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields contains "CorpHealth"
| project AdditionalFields
```

#### Flag 9: Registry Run Key (Ephemeral)

- **Question:** What value was added to the Registry Run keys before being deleted?
- **Answer:** `MaintenanceRunner`
- **KQL Query:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where RegistryKey contains "Run" and ActionType == "RegistryValueSet"
| project RegistryValueName
```

#### Flag 10: Defense Evasion Attempt

- **Question:** What path was attempted to be added to Windows Defender exclusions?
- **Answer:** `C:\ProgramData\Corp\Ops\staging`
- **KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has "staging"
| project ProcessCommandLine
```

### Phase 5: Privilege Escalation

The attacker used token manipulation to escalate privileges, a sophisticated technique to gain elevated access.

#### Flag 11: Token Manipulation Event

- **Question:** What event type indicates token privilege modification?
- **Answer:** `ProcessPrimaryTokenModified`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ProcessPrimaryTokenModified"
| project ActionType, TimeGenerated
```

#### Flag 12: Process ID Responsible

- **Question:** What is the Process ID (PID) of the process that modified token privileges?
- **Answer:** `4888`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ProcessPrimaryTokenModified"
| project InitiatingProcessId
```

A PowerShell command executed with `-EncodedCommand` was captured. Decoding it revealed the attacker handling a specific token.

#### Flag 13: Encoded Command Execution

- **Question:** What decoded PowerShell command was executed first?
- **Answer:** `Write-Output 'token-6D5E4EE08227'`
- **KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName =~ "CH-OPS-WKS02"
| where ProcessCommandLine has "-EncodedCommand"
| extend EncodedBlob = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend DecodedCommand = base64_decode_tostring(EncodedBlob)
| project DecodedCommand
```

This command was part of a broader token manipulation attack. We identified the exact process ID responsible for modifying the privileges.

#### Flag 14: Privilege Token Modification (Process)

- **Question:** What is the "InitiatingProcessId" of the process whose token privileges were modified?
- **Answer:** `4888`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName =~ "CH-OPS-WKS02"
| where AdditionalFields has_any ("tokenChangesDescription", "Privileges")
| where InitiatingProcessCommandLine contains "powershell"
| project InitiatingProcessId
```

We then extracted the Security Identifier (SID) of the user whose token was modified, confirming the target account.

#### Flag 15: Whose Token Was Modified?

- **Question:** Which security identifier (SID) did the modified token belong to?
- **Answer:** `S-1-5-21-1605642021-30596605-784192815-1000`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where AdditionalFields contains "tokenChangeDescription"
| where InitiatingProcessId == 4888
| extend SID = extract(@"S-\d+-\d+-\d+-\d+-\d+-\d+-\d+", 0, AdditionalFields)
| project SID
```

### Phase 6: External Tooling & Reverse Shell

The attacker shifted from living-off-the-land to bringing in external tools. A new executable was written to disk following a curl request.

#### Flag 16: Ingress Tool Transfer

- **Question:** What is the name of the executable that was written to disk after the outbound request?
- **Answer:** `revshell.exe`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where ActionType has "FileCreated"
| where InitiatingProcessCommandLine contains "curl.exe"
| project FileName, FolderPath
```

#### Flag 17: External Download Source

- **Question:** What URL did the workstation connect to when retrieving the file?
- **Answer:** `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName == "curl.exe"
| project RemoteUrl
```

The downloaded tool was executed immediately.

#### Flag 18: Execution of Unsigned Binary

- **Question:** Which process executed the downloaded binary on CH-OPS-WKS02?
- **Answer:** `explorer.exe`
- **Note:** Identified by correlating the file write timestamp with subsequent process creation events

Upon execution, the binary reached out to an external command-and-control IP.

#### Flag 19: C2 Connection

- **Question:** What external IP address did the executable attempt to contact after execution?
- **Answer:** `13.228.171.119`
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where RemotePort == 11746
| project RemoteIP
```

Finally, to ensure this reverse shell ran every time the user logged in, it was copied to the Startup folder.

#### Flag 20: Startup Persistence

- **Question:** Which folder path did the attacker use to establish persistence for the executable?
- **Answer:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where FolderPath has @"c:\programdata\Microsoft\Windows\Start"
| project FolderPath, FileName
```

### Phase 7: Attribution & Origin Traceback

We traced the activity back to its source. The metadata for the remote session revealed a specific device name used by the attacker.

#### Flag 21: Remote Session Device Name

- **Question:** What is the remote session device name associated with the attacker's activity?
- **Answer:** `对手` (Chinese for "Adversary")
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where RemotePort == 11746
| project InitiatingProcessRemoteSessionDeviceName
```

The session metadata also contained the IP address of the attacker's machine.

#### Flag 22: Remote Session IP

- **Question:** What IP address appears as the source of the remote session?
- **Answer:** `100.64.100.6`
- **KQL Query:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where RemotePort == 11746
| project InitiatingProcessRemoteSessionIP
```

However, another IP was present in the logs, indicating the attacker pivoted through an internal Azure host.

#### Flag 23: Internal Pivot Host

- **Question:** Which internal IP address (non-100.64.x.x) appears as part of the attacker's remote session metadata?
- **Answer:** `10.168.0.7`
- **KQL Query:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-10))
| where DeviceName == "ch-ops-wks02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| extend RemoteIP = InitiatingProcessRemoteSessionIP
| where RemoteIP startswith "10."
| distinct RemoteIP
```

### Phase 8: Reconstructing the Start (Root Cause)

With the attribution data in hand, we found the absolute first suspicious logon event to mark the start of the intrusion.

#### Flag 24: First Suspicious Logon Timestamp

- **Question:** What is the earliest timestamp showing a suspicious logon to CH-OPS-WKS02?
- **Answer:** `2025-11-23T03:08:31.1849379Z`
- **KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| sort by TimeGenerated asc
| take 1
| project TimeGenerated
```

#### Flag 25: First Suspicious Logon IP

- **Question:** What IP address is associated with the earliest suspicious logon timestamp?
- **Answer:** `104.164.168.17`
- **KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| sort by TimeGenerated asc
| take 1
| project RemoteIP
```

#### Flag 26: Compromised Account

- **Question:** Which account name appears in the earliest suspicious logon event?
- **Answer:** `chadmin`
- **KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| sort by TimeGenerated asc
| take 1
| project AccountName
```

#### Flag 27: Determine the Attacker's Geographic Region

The suspicious remote device authenticated into CH-OPS-WKS02 using several public IPs within a range. To understand where the attacker was operating from, analysts often enrich these IPs with geolocation data. Microsoft's `geo_info_from_ip_address()` function allows you to derive country, region, and city information directly from KQL—no external OSINT tools required. Your task is to determine the attacker's geographic origin using this enriched data.

- **Question:** According to Defender geolocation enrichment, what country or region do the attacker's IPs originate from?
- **Answer:** `Vietnam`
- **Hints:**
  - Use the suspicious IPs from the previous flag
  - Use `geo_info_from_ip_address(RemoteIP)` to reveal country data
  - All suspicious IPs belong to the same network range and should map to the same geographic region
- **KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where RemoteIP == "104.164.168.17"
| extend GeoInfo = geo_info_from_ip_address(RemoteIP)
| project RemoteIP, GeoInfo.country
```

#### Flag 28: First Process Launched After the Attacker Logged In

After establishing the attacker's first login timestamp and origin IP, the next step is determining what they did immediately after gaining access. Defender records each new process execution along with its associated logon session, allowing analysts to trace the attacker's first action on the system. This reveals whether the adversary began with exploration, privilege escalation, or immediate deployment of tools.

- **Question:** What was the first process launched by the attacker immediately after logging in?
- **Answer:** `explorer.exe`
- **Hints:**
  - Use the timestamp from the earliest suspicious logon
  - Search `DeviceProcessEvents` for processes whose `AccountName` matches that session
  - Sort by timestamp ascending and pick the first process executed after the login time (Remember to reference `AccountName` and `InitiatingProcessAccountName` in your query)
  - The earliest processes are often things like `cmd.exe`, `sethc.exe`, `mstsc.exe`, shell access used by remote tools or it could be something as simple as viewing a file
- **KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-11-23T03:08:31.1849379Z)
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin" or InitiatingProcessAccountName == "chadmin"
| sort by TimeGenerated asc
| take 1
| project ProcessFileName, TimeGenerated
```

#### Flag 29: Identify the First File the Attacker Accessed

Once the attacker authenticated into the system, their very first action can reveal their priorities and objectives. Early file access is often a strong indicator of what the attacker was searching for — credentials, configuration data, operational details, or system weaknesses. By examining the earliest file opened within the session, you can identify exactly what they were after.

- **Question:** What file did the attacker open first after the previous flag?
- **Answer:** `CH-OPS-WKS02 user-pass.txt`
- **Hints:**
  - Use the earliest suspicious logon timestamp as your anchor point
  - Look at `DeviceProcessEvents` for processes with arguments referencing files in the command line
  - The attacker opened the file using a GUI application rather than a command-line tool
  - Reference the previous flag's ProcessID to find this flag's `InitiatingProcessID`
- **KQL Query:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-23T03:08:31.1849379Z)
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessAccountName == "chadmin"
| where ActionType == "FileOpened"
| sort by TimeGenerated asc
| take 1
| project FileName, FolderPath
```

#### Flag 30: Determine the Attacker's Next Action After Reading the File

After viewing the file, the attacker moved on to their next step in the intrusion chain. Early post-logon behavior often reveals operational intent — whether they used stolen credentials, attempted lateral movement, escalated privileges, or launched additional tooling. By examining process execution following the previous activity, analysts can determine how the attacker leveraged the information found in the file.

- **Question:** What did the attacker do next after reading the file?
- **Answer:** `ipconfig.exe`
- **Hints:**
  - Use the timestamp of the previous activity as an anchor
  - Search for the next process timestamps immediately after the file was opened
  - The next action may be:
    - launching a command shell
    - attempting another logon
    - executing recon commands
    - initiating lateral movement
- **KQL Query:**

```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-11-23T03:08:31.1849379Z)
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin" or InitiatingProcessAccountName == "chadmin"
| sort by TimeGenerated asc
| where ProcessFileName != "explorer.exe"
| take 1
| project ProcessFileName, TimeGenerated
```

#### Flag 31: Identify the Next Account Accessed After Recon

Following the attacker's first round of local reconnaissance, the intrusion shifted from information-gathering to account-level interaction. This transition often marks the moment an adversary tests stolen credentials, pivots to a higher-value user profile, or begins lateral preparation. By analyzing logon activity immediately after the enumeration window, defenders can pinpoint which account the attacker chose to access next — a critical step in reconstructing intent and privilege escalation paths.

- **Question:** Which user account did the attacker access immediately after their initial enumeration activity?
- **Answer:** `ops.maintenance`
- **Hints:**
  - Anchor your time window to the moment enumeration completed
  - Look in `DeviceLogonEvents` for the next successful logon event after that timestamp
  - Filter by the suspicious remote session device name or IP (the same one identified earlier)
  - You're looking for the next account used, not the next process
- **KQL Query:**

```kql
DeviceLogonEvents
| where TimeGenerated > datetime(2025-11-23T03:08:31.1849379Z)
| where DeviceName == "ch-ops-wks02"
| where RemoteIP == "104.164.168.17"
| sort by TimeGenerated asc
| take 1
| project AccountName, TimeGenerated
```

---

## Hunt Closure & Analyst Synthesis

After working backward through the attacker's activity — from persistence artifacts to reconnaissance actions, then retracing their initial access — the full intrusion chain becomes clear. Each flag guided the analyst through identifying how the adversary entered the system, which accounts they leveraged, how they enumerated the host, and how they established outbound control via a reverse shell delivered through an ngrok tunnel.

By rebuilding the timeline from the inside out, the investigation not only surfaced the attacker's tooling and behavior, but clarified intent: credential harvesting, situational awareness, and staging for remote command-and-control. Indicators such as remote session IPs, logon patterns, suspicious processes, and persistence paths provided the necessary context to confirm deliberate malicious access rather than benign administrative activity.

### Logical Flow & Analyst Reasoning

**0 → 1** 🔍  
A suspicious activity window is identified on CH-OPS-WKS02. Analysts anchor the starting point by validating host identity and establishing the timeframe of abnormal behavior.

**1 → 2** 🔍  
Unusual maintenance activity and script execution stand out. Analysts question whether this was legitimate IT work or the beginning of attacker tooling.

**2 → 3** 🔍  
Outbound connectivity attempts expose a nonstandard external destination. This raises concern that the script is beaconing rather than performing diagnostics.

**3 → 4** 🔍  
Successful outbound traffic confirms a live connection. Analysts pivot to identify the destination and whether this aligns with corporate endpoints — it does not.

**4 → 5** 🔍  
Disk activity follows shortly after beaconing. A new file appears, suggesting staging or tool transfer. Analysts catalog file properties and hashes.

**5 → 6** 🔍  
Hash mismatch comparisons reveal differing versions of staged files. This raises suspicion of modification or deception during upload.

**6 → 7** 🔍  
Additional staging artifacts appear in multiple directories. The attacker seems to be preparing the environment for future operations.

**7 → 8** 🔍  
Registry queries indicate that the attacker is exploring credential or privilege-related keys. Analysts question whether escalation is being attempted.

**8 → 9** 🔍  
Privilege manipulation events, including token modifications, confirm the attacker probed escalation pathways. This validates the earlier registry activity.

**9 → 10** 🔍  
Shortly after escalation attempts, the attacker reaches out externally to download a new payload. This establishes the transition from recon to tool deployment.

**10 → 11** 🔍  
Execution of the downloaded file marks a significant shift. Analysts inspect command-line arguments to determine purpose.

**11 → 12** 🔍  
Network events reveal that the binary establishes outbound connectivity via an ngrok TCP tunnel. This confirms external control infrastructure.

**12 → 13** 🔍  
Persistence emerges: the file is placed in the Startup folder. This ensures automatic execution on future logons and confirms foothold intent.

**13 → 14** 🔍  
Analysts backtrack the origin of execution. Remote session metadata identifies the suspicious device name used for initial access.

**14 → 15** 🔍  
That device name is tied to several internal IPs, hinting at pivoting or multiple session attempts. Analysts extract all related IPs for correlation.

**15 → 16** 🔍  
Sorting by timestamp reveals which internal IP connected first. This establishes the earliest footprint inside the network.

**16 → 17** 🔍  
Pivoting to logon events, analysts identify the earliest suspicious logon timestamp linked to the malicious device or IP.

**17 → 18** 🔍  
The RemoteIP associated with the first logon reveals the attacker's initial entry vector.

**18 → 19** 🔍  
The corresponding account used during this logon surfaces the credentials the attacker leveraged to enter the environment.

**19 → 20** 🔍  
Analysts correlate all accounts used across the attacker's activity. This helps identify lateral movement or credential testing.

**20 → 21** 🔍  
The first process launched immediately after logon exposes the attacker's priority — reconnaissance, validation, or environment orientation.

**21 → 22** 🔍  
Following that, the attacker opens a file containing credentials. Analysts understand this as targeted harvesting behavior.

**22 → 23** 🔍  
The subsequent action reveals whether the attacker attempted to use those credentials or continued recon — showcasing tactical decision-making.

**23 → 24** 🔍  
Events around remote IP geolocation help determine the attacker's likely region or hosting provider, adding intelligence context.

**24 → 25** 🔍  
Outbound HTTP/TCP attempts show whether the attacker established control channels beyond the ngrok tunnel.

**25 → 26** 🔍  
Analysts review session lifecycles to identify active persistence channels and whether any were redundant or contingency mechanisms.

**26 → 27** 🔍  
Registry-based Run keys or startup file placements point toward deliberate re-entry capability — the attacker prepared for repeated access.

**27 → 28** 🔍  
Subtle cleanup behaviors appear. Analysts determine whether the attacker attempted to blend into system logs or overwrite artifacts.

**28 → 29** 🔍  
File modification timestamps and process sequences help analysts reconstruct staging order and validate whether exfiltration occurred.

**29 → 30** 🔍  
Outbound DNS or HTTP queries reveal whether the attacker validated external reachability for future exfil movements.

**30 → 31** 🔍  
Analysts confirm whether compression or aggregation behavior occurred — attackers often bundle evidence before exfil attempts.

**31 → 32** 🔍  
Finally, analysts correlate all elements — recon, credential access, payload deployment, persistence, and outbound C2 — closing out the narrative and reconstructing the full attack chain.

---

## Summary

This incident demonstrates a sophisticated attack chain involving:

1. **Initial Access:** Compromised credentials (`chadmin`) from Vietnam
2. **Reconnaissance:** Local enumeration and network mapping
3. **Execution:** PowerShell script execution and data staging
4. **Persistence:** Multiple mechanisms (scheduled tasks, registry keys, startup folder)
5. **Privilege Escalation:** Token manipulation techniques
6. **Command & Control:** External reverse shell via ngrok tunnel
7. **Data Exfiltration:** Staging of sensitive data files

The investigation utilized Microsoft Defender for Endpoint telemetry and KQL queries to trace the complete attack lifecycle from initial access through attribution.

---

## Recommendations

1. **Credential Security:** Implement multi-factor authentication (MFA) for all administrative accounts
2. **Network Monitoring:** Enhance detection for suspicious outbound connections and ngrok tunnel usage
3. **Endpoint Protection:** Review and harden Windows Defender exclusion policies
4. **Privilege Management:** Implement least privilege principles and monitor token manipulation events
5. **Threat Hunting:** Establish regular threat hunting exercises using similar KQL queries
6. **Incident Response:** Document and automate detection rules based on identified IOCs

---

## Indicators of Compromise (IOCs)

### IP Addresses
- `104.164.168.17` (Vietnam - Attacker Origin)
- `13.228.171.119:11746` (C2 Server)
- `10.168.0.7` (Internal Pivot)
- `100.64.100.6` (Remote Session IP)

### File Hashes
- `MaintenanceRunner_Distributed.ps1`
- `inventory_6ECFD4DF.csv`
- `revshell.exe`

### Registry Keys
- `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
- Registry Run keys (temporary)

### File Paths
- `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\`
- `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`

### Domains
- `*.ngrok-free.dev`

---

*Report Generated: December 05, 2025*
