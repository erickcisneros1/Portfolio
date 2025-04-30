# 🚫 Enable PowerShell Script Block Logging

This PowerShell script enables PowerShell Script Block Logging, enforcing the configuration outlined in [STIG ID: WN10-CC-000326](https://www.tenable.com/audits/items/DISA_STIG_Windows_10_v2r1.audit:e5e27010881fae4e82bdf4715db5c87c).

---

## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/e0b3aa75-64f6-4e59-abae-f2250ad4d684)

**After**

![Image](https://github.com/user-attachments/assets/3a9ed4ae-f6d3-4853-9854-4a3f5f52b158)

> Use screenshots of the registry key before and after running the script.

---

## 🔒 Compliance Info

- **STIG ID**: WN10-CC-000326  
- **Description**: PowerShell Script Block Logging must be enabled to capture potentially harmful or unauthorized script activity.  
- **Fix**: This script sets the registry value `EnableScriptBlockLogging` to `1` under the appropriate policy key.  
- **Impact**: Medium

---

## 🧠 Synopsis

This script enables PowerShell Script Block Logging by modifying the Windows registry to ensure that PowerShell blocks are logged for auditing and monitoring purposes.

---

## 📜 Script

```powershell
<#
.SYNOPSIS
    This script enables PowerShell Script Block Logging by modifying the Windows registry to ensure that PowerShell blocks are logged for auditing and monitoring purposes.

.NOTES
    Author          : Erick Cisneros Ruballos
    LinkedIn        : https://www.linkedin.com/in/erickcr1/
    GitHub          : https://github.com/erickcisneros1
    Date Created    : 2025-04-27
    Last Modified   : 2025-04-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000326

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000326.ps1 
#>


# Define registry path and values
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$regName = "EnableScriptBlockLogging"
$regValue = 1

# Create the registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the policy value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

Write-Host "'Turn on PowerShell Script Block Logging' policy set to 'Enabled.'"
