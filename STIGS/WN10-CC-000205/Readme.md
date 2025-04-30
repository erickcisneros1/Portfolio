# Configure Windows Telemetry Level

This PowerShell script enforces a compliant Windows telemetry level by modifying registry settings in accordance with [STIG ID: WN10-CC-000205](https://public.cyber.mil/stigs/).

---

## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/e2013faa-bf63-4106-9f20-40ddd8383e06)

**After**

![Image](https://github.com/user-attachments/assets/e94b99c0-5112-4e9d-a9e0-abefe30e61b5)

> Use screenshots of registry values before and after applying the script.

---

## 🔒 Compliance Info

- **STIG ID**: WN10-CC-000205  
- **Description**: Windows 10/11 systems must limit telemetry to the minimum level (Security, Basic, or Enhanced).  
- **Fix**: This script configures the `AllowTelemetry` registry setting.  
- **Impact**: Medium

---

## 🧠 Synopsis

This script ensures that telemetry data sent to Microsoft is limited by setting the `AllowTelemetry` registry key. The default value here is `1` (Basic), but can be adjusted for stricter compliance (`0` for Security).

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
    STIG-ID         : WN10-CC-000205

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000205.ps1 
#>

# Set telemetry level (change to 0 or 2 as needed)
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
$regName = "AllowTelemetry"
$regValue = 1  # Change to 0 (Security) or 2 (Enhanced) if appropriate

# Create the registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Apply the policy setting
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

Write-Host "'Allow Telemetry' successfully set to $regValue (`Basic`, changeable to `Security` or `Enhanced`)."
