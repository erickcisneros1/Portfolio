# 🚫 Disable User Control Over Installs

This PowerShell script disables user control over Windows Installer installs, enforcing the configuration outlined in [STIG ID: WN10-CC-000310](https://public.cyber.mil/stigs/).

---

## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/7292e314-14d2-4440-a35f-0cfc31ca7277)

**After**

![Image](https://github.com/user-attachments/assets/ada3ab48-d27f-4a5e-ba56-f27be21f82ae)

> Use screenshots of the registry key before and after running the script.

---

## 🔒 Compliance Info

- **STIG ID**: WN10-CC-000310  
- **Description**: User control over Windows Installer installs must be disabled to prevent unauthorized software installations.  
- **Fix**: This script sets the registry value `EnableUserControl` to `0` under the appropriate policy key.  
- **Impact**: Medium

---

## 🧠 Synopsis

This script configures the Windows Installer policy to disallow users from changing install behavior or overriding admin restrictions by modifying a specific registry value.

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
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000310.ps1 
#>

# Define registry path and values
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "EnableUserControl"
$valueData = 0

# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value to disable user control over installs
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Output "Policy 'Allow user control over installs' set to 'Disabled'."
