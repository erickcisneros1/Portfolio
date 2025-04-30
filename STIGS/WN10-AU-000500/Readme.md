# Set Maximum Size of Windows Application Event Log

This PowerShell script ensures that the **maximum size of the Windows Application event log** is set to **32,768 KB (32 MB)** to comply with [STIG-ID: WN10-AU-000500](https://public.cyber.mil/stigs/). It modifies the Windows Registry accordingly.

---

## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/4f858b8c-0f0b-40bd-90ce-50d39d2bff91)

**After**

![Image](https://github.com/user-attachments/assets/4ff8db4b-4752-4b13-9512-920123899e6f)

> Replace these image placeholders with screenshots of the registry setting before and after applying the script.

---

## 🔒 Compliance Info

- **STIG ID**: WN10-AU-000500  
- **Description**: The Windows Application event log size must be configured to at least 32768 KB.  
- **Fix**: This script sets the registry value using PowerShell.  
- **Impact**: Medium

---

## 🧠 Synopsis

This script sets the **MaxSize** value for the **Application Event Log** to 32 MB via the Windows Registry to ensure sufficient log retention.

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
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AU-000500.ps1 
#>

# Define the registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 0x8000  # Hex 0x8000 = Decimal 32768

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value
New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWord -Force
