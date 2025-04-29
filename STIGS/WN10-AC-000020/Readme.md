# Enforce Password History Policy - PowerShell Script

This PowerShell script ensures that the **"Enforce password history"** setting is configured to **24** previous passwords. This helps meet compliance requirements such as [STIG-ID: WN10-AC-000020](https://public.cyber.mil/stigs/).

---

## 🔒 Compliance Info

- **STIG ID**: WN10-AC-000020
- **Description**: Enforce password history must be configured to at least 24 passwords.
- **Fix**: This script sets the correct value automatically using the built-in `secedit` utility.
- **Impact**: Medium


## 📸 Before & After

**Before**

![Image](https://github.com/user-attachments/assets/b0749f41-f3ee-452b-bc15-db9b8b606f9a)

**After**

![Image](https://github.com/user-attachments/assets/4a83bb08-c2fe-4e0a-a653-1d30b9ec7ffc)

> Replace these placeholders with actual screenshots showing the policy before and after script execution.

---

## 🧠 Synopsis

This script configures the local security policy to retain the last 24 passwords using `secedit` and a temporary configuration export.

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
    STIG-ID         : WN10-AC-000020

    COMPLIANCE INFO
    ----------------
    STIG ID       : WN10-AC-000020
    Description   : Enforce password history must be configured to at least 24 passwords.
    Impact        : Medium
    Fix Text      : Configure the policy value for Computer Configuration ->
                    Windows Settings -> Security Settings -> Account Policies ->
                    Password Policy -> Enforce password history to 24 or more passwords remembered.

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-AC-000020.ps1 
#>


# Export current security policy to a temp file
$cfgFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $cfgFile

# Read file and replace or add the Enforce password history setting
$content = Get-Content $cfgFile

if ($content -match "PasswordHistorySize") {
    $content = $content -replace "PasswordHistorySize\s*=\s*\d+", "PasswordHistorySize = 24"
} else {
    $content += "`nPasswordHistorySize = 24"
}

# Save the modified config back
$content | Set-Content $cfgFile

# Apply the updated policy
secedit /configure /db secedit.sdb /cfg $cfgFile /areas SECURITYPOLICY

# Clean up
Remove-Item $cfgFile -Force

Write-Host "'Enforce password history' successfully set to 24."
