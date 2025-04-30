# ⏲️ Set Interactive Logon Inactivity Timeout

This PowerShell script sets the inactivity timeout for interactive logons, enforcing the configuration outlined in [STIG ID: WN10-SO-000070](https://public.cyber.mil/stigs/).

---

## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/f951c0c1-910d-4646-9553-5ccc89a7ce6a)

**After**

![Image](https://github.com/user-attachments/assets/75b016ba-76ed-40d6-b92c-d6e00eca5917)

> Use screenshots of the registry key before and after running the script.

---

## 🔒 Compliance Info

- **STIG ID**: WN10-SO-000070  
- **Description**: The interactive logon inactivity timeout must be configured to automatically log off users after a specified period of inactivity.  
- **Fix**: This script sets the `InactiveThreshold` value under the `Lsa` key and `InactivityTimeoutSecs` under the `Winlogon` key to 900 seconds (15 minutes).  
- **Impact**: Medium

---

## 🧠 Synopsis

This script sets the inactivity timeout for interactive logons to 900 seconds (15 minutes) by modifying the Windows registry under both `Lsa` and `Winlogon` paths.

---

## 📜 Script

```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Erick Cisneros Ruballos
    LinkedIn        : https://www.linkedin.com/in/erickcr1/
    GitHub          : https://github.com/erickcisneros1
    Date Created    : 2025-04-27
    Last Modified   : 2025-04-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000070

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-SO-000070.ps1 
#>


# Define primary registry path and value
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaValueName = "InactiveThreshold"
$desiredTimeout = 900

# Create the key if it doesn't exist
if (-not (Test-Path $lsaPath)) {
    New-Item -Path $lsaPath -Force | Out-Null
}

# Set the inactivity timeout
Set-ItemProperty -Path $lsaPath -Name $lsaValueName -Value $desiredTimeout -Type DWord

# Also set InactivityTimeoutSecs under Winlogon if applicable (used on some builds)
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$winlogonValue = "InactivityTimeoutSecs"

if (-not (Test-Path $winlogonPath)) {
    New-Item -Path $winlogonPath -Force | Out-Null
}

Set-ItemProperty -Path $winlogonPath -Name $winlogonValue -Value $desiredTimeout -Type DWord

Write-Host "'Interactive logon: Machine inactivity limit' successfully set to 900 seconds (15 minutes)."
