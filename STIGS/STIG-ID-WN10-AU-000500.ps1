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
