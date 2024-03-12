<#PSScriptInfo
.GUID 9670c013-d1b1-4f5d-9bd0-0fa185b9f203
.AUTHOR David Segura @SeguraOSD
.EDITS Matthew Miles 
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
$ScriptVersion = '24.3.12.1'

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
    
    # Define the certificate URL and file
    $certUrl = "https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer"
    $certFile = "X:\OSDCloud\Cisco_Umbrella_Root_CA.cer"

    # Check if the certificate is already installed by the issuer name
    $certExists = Get-ChildItem -Path 'Cert:\LocalMachine\Root\' | Where-Object {$_.Issuer -like "*Cisco Umbrella*"}

    if ($certExists) {
        # Do nothing
        Write-Host -ForegroundColor Green "[+] Cisco Umbrella root certificate installed"
    }
    else {
        # Download and install the certificate
        Write-Host -ForegroundColor Yellow "[-] Installing Cisco Umbrella root certificate"
        Invoke-WebRequest -Uri $certUrl -OutFile $certFile

        # Load the certificate and add it to the root store
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $Cert.Import($certFile)
        $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $Store.Open("ReadWrite")
        $Store.Add($Cert)
        $Store.Close()

        # Delete the downloaded file
        Remove-Item $certFile -Force
        Write-Host -ForegroundColor Green "[+] Cisco Umbrella root certificate installed"
    }

    osdcloud-StartWinPE -OSDCloud

    Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/Win11.ps1)
    
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
    Step-installCiscoRootCert
    step-InstallWinGet
    step-WinGetUpdate    
    osdcloud-StartOOBE 
    Step-InstallM365Apps
    Step-oobeHotFix #fix for Autopilot failing
    Step-installSTCACert    
    #Step-oobeDellDCU
    #Start-WindowsUpdate #from OSDCloud
    #Start-WindowsUpdateDriver # from OSDCloud
    #Step-RestartConfirmation
    Set-TimeZoneFromIP #from OSDCloud
    Step-oobeSetDateTime
    Step-oobeRegisterAutopilot 
    Step-oobeRemoveAppxPackageAllUsers
    Step-oobeSetUserRegSettings
    Step-oobeSetDeviceRegSettings
    Step-desktopWallpaper
    Step-oobeCreateLocalUser    
    Step-oobeRestartComputer

    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    #Load OSD and Azure stuff
    $null = Stop-Transcript -ErrorAction Ignore
    # Write-Host "[-] This script is not intended to run in Windows phase at this time" -ForegroundColor Red
    Invoke-Expression (Invoke-RestMethod scripts.sight-sound.dev)
}

#endregion