
# Enforce Password History Policy - PowerShell Script

This PowerShell script ensures that the "Enforce password history" security policy is set to retain the last **24 passwords** on Windows systems. It uses `secedit` to export and modify the local security policy, then re-applies the updated settings.

---

## 📸 Before & After

**Before**

![Before](images/before.png)

**After**

![After](images/after.png)

---

## 🧠 Synopsis

Ensures that the **Enforce password history** setting in Windows is configured to **24**, which aligns with [STIG-ID: WN10-AC-000020](https://public.cyber.mil/stigs/) requirements.

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
