<#
.SYNOPSIS
    This script ensures that telemetry data sent to Microsoft is limited by setting the AllowTelemetry registry key. The default value here is 1 (Basic), but can be adjusted for stricter compliance (0 for Security).

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
