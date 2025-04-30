<#
.SYNOPSIS
    Disabling IP source routing helps prevent spoofing and packet redirection attacks. This script enforces the highest protection (value: 2) for IPv6 routing.

.NOTES
    Author          : Erick Cisneros Ruballos
    LinkedIn        : https://www.linkedin.com/in/erickcr1/
    GitHub          : https://github.com/erickcisneros1
    Date Created    : 2025-04-27
    Last Modified   : 2025-04-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000020.ps1 
#>


# Check for MSS-Legacy ADMX/ADML presence (informational only)
$admx = "$env:SystemRoot\PolicyDefinitions\MSS-Legacy.admx"
$adml = "$env:SystemRoot\PolicyDefinitions\en-US\MSS-Legacy.adml"

if (!(Test-Path $admx) -or !(Test-Path $adml)) {
    Write-Warning "MSS-Legacy templates not found. These are only required for GPO UI visibility, not for registry-based enforcement."
}

# Registry configuration
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$regName = "DisableIPSourceRouting"
$regValue = 2  # 2 = Highest protection (completely disabled)

# Create key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Apply the setting
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord

Write-Host "'DisableIPSourceRouting (IPv6)' set to 2 (Highest protection) as per STIG requirements."
