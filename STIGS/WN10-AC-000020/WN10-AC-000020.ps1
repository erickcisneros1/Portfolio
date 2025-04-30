<#
.SYNOPSIS
    This script configures the local security policy to retain the last 24 passwords using secedit and a temporary configuration export.

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
