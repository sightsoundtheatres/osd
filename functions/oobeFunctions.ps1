[CmdletBinding()]
param()
$ScriptName = 'oobeFunctions.sight-sound.dev'
$ScriptVersion = '24.1.7.1'

#region Initialize
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
#endregion


$AutopilotOOBEJson = @'
{
    "GroupTag": "",
    "GroupTagOptions":  [
                            "Development",
                            "Enterprise"
                        ],   
    "AddToGroup": "",
    "AddToGroupOptions": [
                              "Autopilot_Devices-GeneralUsers",
                              "Autopilot_Devices-Box_CC",
                              "Autopilot_Devices-CenterStageKiosk",
                              "Autopilot_Devices-SharedDevice_IT"
                         ],
    "AssignedComputerName": "",                     
    "AssignedComputerNameExample": "XXWIN-EID-XXXX",
    "Assign": {
                "IsPresent": true
              },
    "Hidden": [
                "PostAction",
                "Assign",
                "Docs"
              ],    
    "PostAction": "Quit",
    "Run": "WindowsSettings",
    "Title": "Sight & Sound Autopilot Registration"
}
'@

#=================================================
#   oobeFunctions
#=================================================

$Global:oobeCloud = @{
    oobeRemoveAppxPackageName = 'Microsoft.BingNews',
                                'Microsoft.BingWeather',
                                'Microsoft.GamingApp',
                                'Microsoft.GetHelp',
                                'Microsoft.Getstarted',
                                'Microsoft.MicrosoftSolitaireCollection',
                                'Microsoft.People',
                                'microsoft.windowscommunicationsapps',
                                'Microsoft.WindowsFeedbackHub',
                                'Microsoft.WindowsMaps',
                                'Microsoft.Xbox.TCUI',
                                'Microsoft.XboxGameOverlay',
                                'Microsoft.XboxGamingOverlay',
                                'Microsoft.XboxIdentityProvider',
                                'Microsoft.XboxSpeechToTextOverlay',
                                'Microsoft.ZuneMusic',
                                'Microsoft.ZuneVideo',
                                'Clipchamp.Clipchamp',
                                'Microsoft.YourPhone',
                                'MicrosoftTeams'    
}


function Step-installCiscoRootCert {
    
        # Define the certificate URL and file
        $certUrl = "https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer"
        $certFile = "C:\OSDCloud\Temp\Cisco_Umbrella_Root_CA.cer"

        # Check if the certificate is already installed by the issuer name
        $certExists = Get-ChildItem -Path 'Cert:\LocalMachine\Root\' | Where-Object {$_.Issuer -like "*Cisco Umbrella*"}

        if ($certExists) {
            # Do nothing
            Write-Host -ForegroundColor Green "[+] Cisco Umbrella certificate root installed"
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
        }
    }


function Step-oobeInstallModuleAutopilotOOBE {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        $Requirement = Import-Module AutopilotOOBE -PassThru -ErrorAction Ignore

        Write-Host -ForegroundColor Green "[+] Creating AutoPilot configuration .json file ..."
           
        $outputPath = "$env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json"
        
        if (-not (Test-Path (Split-Path $outputPath))) {
            New-Item -Path (Split-Path $outputPath) -ItemType Directory -Force
        }

        $AutopilotOOBEJson | Out-File -FilePath "$env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json" -Encoding UTF8

        if (-not $Requirement)
        {       
            Write-Host -ForegroundColor Green "[+] Install-Module AutopilotOOBE"
            Install-Module -Name AutopilotOOBE -Force
            Import-Module AutopilotOOBE -Force
            Start-AutopilotOOBE
        }
        else {
            Import-Module AutopilotOOBE -Force
            Start-AutopilotOOBE
        }
    }
}
function Step-oobeRegisterAutopilot {
    [CmdletBinding()]
    param (
        [System.String]
        $Command
    )
    
        # Display a pop-up asking for user confirmation
        $caption = "Register Device with Autopilot?"
        $message = "Would you like to register this device with Autopilot?"
        $options = [System.Windows.Forms.MessageBoxButtons]::YesNo
        $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $options, [System.Windows.Forms.MessageBoxIcon]::Question)
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Write-Host -ForegroundColor Green "[+] Registering Device in Autopilot using AutopilotOOBE"
            Step-oobeInstallModuleAutopilotOOBE
        }
        else {
            Write-Host -ForegroundColor Yellow "[-] Device registration with Autopilot skipped."
        }
    }

function Step-oobeRemoveAppxPackage {
    
        Write-Host -ForegroundColor Green "[+] Removing Appx Packages"
        foreach ($Item in $Global:oobeCloud.oobeRemoveAppxPackageName) {
            if (Get-Command Get-AppxProvisionedPackage) {
                Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -Match $Item} | ForEach-Object {
                    Write-Host -ForegroundColor DarkGray $_.DisplayName
                    if ((Get-Command Remove-AppxProvisionedPackage).Parameters.ContainsKey('AllUsers')) {
                        Try
                        {
                            $null = Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $_.PackageName
                        }
                        Catch
                        {
                            Write-Warning "AllUsers Appx Provisioned Package $($_.PackageName) did not remove successfully"
                        }
                    }
                    else {
                        Try
                        {
                            $null = Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName
                        }
                        Catch
                        {
                            Write-Warning "Appx Provisioned Package $($_.PackageName) did not remove successfully"
                        }
                    }
                }
            }
        }
    }

function Step-oobeUpdateDrivers {
    [CmdletBinding()]
    param ()    
        Write-Host -ForegroundColor Green "[+] Updating Windows Drivers"
        if (!(Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore)) {
            try {
                Install-Module PSWindowsUpdate -Force
                Import-Module PSWindowsUpdate -Force
            }
            catch {
                Write-Warning 'Unable to install PSWindowsUpdate Driver Updates'
            }
        }
        if (Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore) {
            Start-Process PowerShell.exe -ArgumentList "-Command Install-WindowsUpdate -UpdateType Driver -AcceptAll -IgnoreReboot" -Wait
        }
    }

function Step-oobeUpdateWindows {
    [CmdletBinding()]
    param ()    
        Write-Host -ForegroundColor Green "[+] Running Windows Update"
        if (!(Get-Module PSWindowsUpdate -ListAvailable)) {
            try {
                Install-Module PSWindowsUpdate -Force
                Import-Module PSWindowsUpdate -Force
            }
            catch {
                Write-Warning 'Unable to install PSWindowsUpdate Windows Updates'
            }
        }
        if (Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore) {
            #Write-Host -ForegroundColor DarkCyan 'Add-WUServiceManager -MicrosoftUpdate -Confirm:$false'
            Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
            #Write-Host -ForegroundColor DarkCyan 'Install-WindowsUpdate -UpdateType Software -AcceptAll -IgnoreReboot'
            #Install-WindowsUpdate -UpdateType Software -AcceptAll -IgnoreReboot -NotTitle 'Malicious'
            #Write-Host -ForegroundColor DarkCyan 'Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot'
            Start-Process PowerShell.exe -ArgumentList "-Command Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Preview' -NotKBArticleID 'KB890830','KB5005463','KB4481252'" -Wait
        }
    }

function Step-RestartConfirmation {
    [CmdletBinding()]
    param ()
      
    Add-Type -AssemblyName System.Windows.Forms
    $caption = "Restart Computer?"
    $message = "Were Windows Updates ran that would require a restart?  If so please click YES to restart now and then start this script over.  Otherwise, please click NO to continue"
    $options = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $options, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Restart-Computer -Force
    } else {
        Write-Host -ForegroundColor Yellow "[+] Continuing script execution..."
    }
  }

function Step-oobeSetUserRegSettings {
    [CmdletBinding()]
    param ()
    
    # Load Default User Profile hive (ntuser.dat)
    Write-host -ForegroundColor Green "[+] Setting default users registry settings ..."
    $DefaultUserProfilePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
    REG LOAD "HKU\Default" $DefaultUserProfilePath

    # Changes to Default User Registry

    Write-host -ForegroundColor DarkGray "[+] Show known file extensions" 
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[+] Change default Explorer view to This PC"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[+] Show User Folder shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f | Out-Null
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[+] Show This PC shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f | Out-Null
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[+] Show item checkboxes"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 1 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[+] Disable Chat on Taskbar"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f | Out-Null   
    
    Write-host -ForegroundColor DarkGray "[+] Disable Windows Spotlight on lockscreen"
    REG ADD "HKU\Default\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor DarkGray "[+] Unloading the default user registry hive"
    REG UNLOAD "HKU\Default"
    }

function Step-oobeSetDeviceRegSettings {
    [CmdletBinding()]
    param ()
    
    Write-host -ForegroundColor Green "[+] Setting default machine registry settings ..."

    Write-host -ForegroundColor DarkGray "[+] Disable IPv6 on all adapters"

        Set-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Enabled $false -ErrorAction SilentlyContinue

    Write-host -ForegroundColor DarkGray "[+] Disable firstlogon animation"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue

    Write-host -ForegroundColor DarkGray "[+] Autoset time zone"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Value "Allow" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name start -Value "3" -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor DarkGray "[+] Setting start menu items"
        
        if (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start")) {
            New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Force -ErrorAction SilentlyContinue
        }        
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDocuments" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDocuments_ProviderSet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDownloads" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDownloads_ProviderSet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPictures" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPictures_ProviderSet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderFileExplorer" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderFileExplorer_ProviderSet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderSettings" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderSettings_ProviderSet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    }

function Step-oobeCreateLocalUser {
    [CmdletBinding()]
    param ()
    
        Write-Host -ForegroundColor Green "[+] Creating local user - ssLocalAdmin"
        # Generate a random password of 16 characters
        function Generate-RandomPassword {
            $validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
            $passwordLength = 64
            $random = New-Object System.Random
            $password = 1..$passwordLength | ForEach-Object { $validCharacters[$random.Next(0, $validCharacters.Length)] }
            return $password -join ''
        }
            $Username = "ssLocalAdmin"
            $Password = Generate-RandomPassword
            $NeverExpire = $true
            $UserParams = @{
                "Name"                  = $Username
                "Password"              = (ConvertTo-SecureString -AsPlainText $Password -Force)
                "UserMayNotChangePassword" = $true
                "PasswordNeverExpires"  = $NeverExpire
            }
            New-LocalUser @UserParams
            Write-Output -ForegroundColor DaryGray "User '$Username' has been created with password: $Password"
            Add-LocalGroupMember -Group "Administrators" -Member $Username
    }

function Step-windowsWallpaper {
    [CmdletBinding()]
    param ()
    
        Write-Host -ForegroundColor Green "[+] Replacing default wallpaper and lockscreen images..."
        # Download the script
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/set-WindowsDesktopWallpaper.ps1 -OutFile C:\OSDCloud\Scripts\set-WindowsDesktopWallpaper.ps1
        # Execute the script
        & C:\OSDCloud\Scripts\set-WindowsDesktopWallpaper.ps1 -ErrorAction SilentlyContinue
        # Remove script
        Remove-Item -Path C:\OSDCloud\Scripts\set-WindowsDesktopWallpaper.ps1
    }


function Step-oobeRestartComputer {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeRestartComputer -eq $true)) {
        Write-Host -ForegroundColor Cyan 'Build Complete!'
        Write-Host -ForegroundColor Cyan 'Cleaning up... Removing c:\OSDCloud and c:\Drivers directory'
        # Remove-Item -LiteralPath "c:\osdcloud" -Force -Recurse
        # Remove-Item -LiteralPath "c:\Drivers" -Force -Recurse
        Write-Warning 'Device will restart in 30 seconds.  Press Ctrl + C to cancel'
        Stop-Transcript
        Start-Sleep -Seconds 30
        Restart-Computer
    }
}

function Step-oobeDellDCU {
    [CmdletBinding()]
    param ()
    $ProcessPath = ""

# Check if DCU is installed
if (Test-Path -Path 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe') {
    $ProcessPath = 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe'
    Write-Host -ForegroundColor Green "[+] Dell Command Update installed"
    osdcloud-RunDCU
} elseif (Test-Path -Path 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe') {
    $ProcessPath = 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe'
    Write-Host -ForegroundColor Green "[+] Dell Command Update installed"
    osdcloud-RunDCU
} else {
    # DCU is not installed, perform installation
    if ($DellEnterprise -eq $true) {
        Write-Host -ForegroundColor Yellow "[-] System = Dell - Installing Dell Command Update"        
        osdcloud-InstallDCU
        osdcloud-RunDCU
        Write-Host -ForegroundColor Green "[+] Dell Command Update installed successfully"
        $ProcessPath = 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe'
    } else {
        Write-Host -ForegroundColor Cyan "[-] System not = Dell - DCU not supported"
    }
}
}

function Step-oobeSetDateTime {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetDateTime -eq $true)) {
        Write-Host -ForegroundColor Yellow 'Verify the Date and Time is set properly including the Time Zone'
        Write-Host -ForegroundColor Yellow 'If this is not configured properly, Certificates and Autopilot may fail'
        Start-Process 'ms-settings:dateandtime' | Out-Null
        $ProcessId = (Get-Process -Name 'SystemSettings').Id
        if ($ProcessId) {
            Wait-Process $ProcessId
        }
    }
}


