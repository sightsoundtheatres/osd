<#PSScriptInfo
.GUID 9670c013-d1b1-4f5d-9bd0-0fa185b9f203
.AUTHOR David Segura @SeguraOSD
.AUTHOR Matthew Miles 
.COMPANYNAME osdcloud.com 
.COPYRIGHT (c) 2023 David Segura osdcloud.com. All rights reserved.
.TAGS OSDeploy OSDCloud WinPE OOBE Windows AutoPilot
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/OSD
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
Script should be executed in a Command Prompt using the following command
powershell Invoke-Expression -Command (Invoke-RestMethod -Uri osd.sight-sound.dev)
This is abbreviated as
powershell iex (irm osd.sight-sound.dev)
#>
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerShell Script which supports the OSDCloud environment
.DESCRIPTION
    PowerShell Script which supports the OSDCloud environment
.LINK
    https://raw.githubusercontent.com/sightsoundtheatres/osd/main/subdomains/osd.sight-sound.dev.ps1
.EXAMPLE
    powershell iex (irm osd.sight-sound.dev)
#>
[CmdletBinding()]
param()
$ScriptName = 'osd.sight-sound.dev'
$ScriptVersion = '24.1.26.1'

#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore

if ($env:SystemDrive -eq 'X:') {
    $WindowsPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') {$WindowsPhase = 'OOBE'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') {$WindowsPhase = 'Specialize'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') {$WindowsPhase = 'AuditMode'}
    else {$WindowsPhase = 'Windows'}
}

Write-Host -ForegroundColor Green "[+] $ScriptName $ScriptVersion ($WindowsPhase Phase)"
Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/OSD/master/cloud/functions.ps1)
Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/oobeFunctions.ps1)
#endregion

#region Admin Elevation
$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($isElevated) {
    Write-Host -ForegroundColor Green "[+] Running as $whoiam (Admin Elevated)"
}
else {
    Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
    Break
}
#endregion

#region Transport Layer Security (TLS) 1.2
Write-Host -ForegroundColor Green "[+] Transport Layer Security (TLS) 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    #Process OSDCloud startup and load Azure KeyVault dependencies
    osdcloud-StartWinPE -OSDCloud -KeyVault
    Write-Host -ForegroundColor Cyan "To start a new PowerShell session, type 'start powershell' and press enter"
    Write-Host -ForegroundColor Cyan "Start-OSDCloud, Start-OSDCloudGUI, or Start-OSDCloudAzure, can be run in the new PowerShell window"
    
    #Stop the startup Transcript.  OSDCloud will create its own
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region OOBE
if ($WindowsPhase -eq 'OOBE') {
    #Load everything needed to setup a new computer and register to AutoPilot
    osdcloud-StartOOBE -InstallWinGet -WinGetUpgrade 
    Step-installCiscoRootCert
    Step-InstallM365Apps
    Step-oobeDellDCU
    Step-oobeUpdateDrivers
    Step-oobeUpdateWindows
    Step-RestartConfirmation
    Step-oobeRemoveAppxPackage
    Step-oobeSetUserRegSettings
    Step-oobeSetDeviceRegSettings
    Step-desktopWallpaper
    Step-oobeCreateLocalUser
    Step-oobeSetDateTime
    Step-oobeRegisterAutopilot    
    Step-oobeRestartComputer

    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    #Load OSD and Azure stuff
    $null = Stop-Transcript -ErrorAction Ignore
    Write-Host "[-] This script is not intended to run in Windows phase at this time" -ForegroundColor Red
}

#endregion