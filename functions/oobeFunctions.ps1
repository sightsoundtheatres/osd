[CmdletBinding()]
param()
$ScriptName = 'oobeFunctions.sight-sound.dev'
$ScriptVersion = '24.2.28.1'

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
                                'MicrosoftTeams',
                                'MicrosoftCorporationII.QuickAssist' 
}

#=================================================
#   oobeFunctions
#=================================================

function Step-installCiscoRootCert {
    
        # Define the certificate URL and file
        $certUrl = "https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer"
        $certFile = "C:\OSDCloud\Temp\Cisco_Umbrella_Root_CA.cer"

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
    }

    function Step-installSTCACert {
    
        # Define the certificate URL and file
        $certUrl = "https://ssintunedata.blob.core.windows.net/cert/24-st-ca.cer"
        $certFile = "C:\OSDCloud\Temp\24-ST-CA.cer"

        # Check if the certificate is already installed by the issuer name
        $certExists = Get-ChildItem -Path 'Cert:\LocalMachine\Root\' | Where-Object {$_.Issuer -like "*ST-CA*"}

        if ($certExists) {
            # Do nothing
            Write-Host -ForegroundColor Green "[+] ST-CA root certificate installed"
        }
        else {
            # Download and install the certificate
            Write-Host -ForegroundColor Yellow "[-] Installing ST-CA root certificate"
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
            Write-Host -ForegroundColor Green "[+] ST-CA root certificate installed"
        }
    }


function Step-oobeInstallModuleAutopilotOOBE {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        $Requirement = Import-Module AutopilotOOBE -PassThru -ErrorAction Ignore

        Write-Host -ForegroundColor Yellow "[-] Creating AutoPilot configuration .json file ..."
           
        $outputPath = "$env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json"
        
        if (-not (Test-Path (Split-Path $outputPath))) {
            New-Item -Path (Split-Path $outputPath) -ItemType Directory -Force | Out-Null
        }

        $AutopilotOOBEJson | Out-File -FilePath "$env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json" -Encoding UTF8
        Write-Host -ForegroundColor Green "[+] AutoPilot configuration .json file Created"

        if (-not $Requirement)
        {       
            Write-Host -ForegroundColor Yellow "[-] Install-Module AutopilotOOBE"
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

function Step-oobeInstallModuleGetWindowsAutopilotInfoCommunity {
    [CmdletBinding()]
    param ()
        # Install the get-windowsautopilotcommunity.ps1 script
        install-script get-windowsautopilotinfocommunity -Force

        # Define the options for the GroupTag parameter
        $GroupTagOptions = @("Development", "Enterprise")

        # Display the menu for the GroupTag parameter
        Write-Host "Select a GroupTag:"
        for ($i = 0; $i -lt $GroupTagOptions.Count; $i++) {
            Write-Host "$($i + 1): $($GroupTagOptions[$i])"
        }
        $GroupTagChoice = Read-Host "Enter your choice"
        $GroupTag = $GroupTagOptions[$GroupTagChoice - 1]

        # Prompt the user to enter a value for the AssignedComputerName parameter
        do {
            $AssignedComputerName = Read-Host "Enter the AssignedComputerName ex XXWIN-EID-XXXX (15 characters or less)"
            if ($AssignedComputerName.Length -gt 15) {
                Write-Warning "AssignedComputerName must be 15 characters or less"
            }
        } while ($AssignedComputerName.Length -gt 15)

        # Define the options for the AddToGroup parameter
        $AddToGroupOptions = @( "Autopilot_Devices-GeneralUsers",
                                "Autopilot_Devices-Box_CC",
                                "AutoPilot_Devices-Retail",
                                "Autopilot_Devices-CenterStageKiosk",
                                "Autopilot_Devices-SharedDevice_IT")

        # Display the menu for the AddToGroup parameter
        Write-Host "Select an AddToGroup option:"
        for ($i = 0; $i -lt $AddToGroupOptions.Count; $i++) {
            Write-Host "$($i + 1): $($AddToGroupOptions[$i])"
        }
        $AddToGroupChoice = Read-Host "Enter your choice"
        $AddToGroup = $AddToGroupOptions[$AddToGroupChoice - 1]

        # Call the get-windowsautopilotinfo.ps1 script with the specified parameters
        get-windowsautopilotinfocommunity.ps1 -Assign -GroupTag $GroupTag -AssignedComputerName $AssignedComputerName -AddToGroup $AddToGroup -online
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
            Write-Host -ForegroundColor Yellow "[-] Registering Device in Autopilot using AutopilotOOBE"
            #Step-oobeInstallModuleAutopilotOOBE
            Step-oobeInstallModuleGetWindowsAutopilotInfoCommunity
        }
        else {
            Write-Host -ForegroundColor Cyan "[!] Device registration with Autopilot skipped."
            return
        }
    }

function Step-oobeRemoveAppxPackage {
    
        Write-Host -ForegroundColor Yellow "[-] Removing Appx Packages"
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
function Step-oobeRemoveAppxPackageAllUsers {

    Write-Host -ForegroundColor Yellow "[-] Removing Appx Packages"
    foreach ($Item in $Global:oobeCloud.oobeRemoveAppxPackageName) {
        if (Get-Command Get-AppxProvisionedPackage) {
            Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -Match $Item} | ForEach-Object {
                Write-Host -ForegroundColor DarkGray $_.DisplayName
                Try
                {
                    $null = Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $_.PackageName
                }
                Catch
                {
                    Write-Warning "AllUsers Appx Provisioned Package $($_.PackageName) did not remove successfully"
                }
            }
        }
    }
}

function Step-oobeUpdateDrivers {
    [CmdletBinding()]
    param ()    
        Write-Host -ForegroundColor Yellow "[-] Updating Windows Drivers"
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
        Write-Host -ForegroundColor Yellow "[-] Running Windows Update"
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
            Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
            Start-Process PowerShell.exe -ArgumentList "-Command Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Preview' -NotKBArticleID 'KB890830','KB5005463','KB4481252'" -Wait
        }
    }

    function Step-RestartConfirmation {
        [CmdletBinding()]
        param ()
          
        $file = "C:\OSDCloud\Scripts\WURanOnce.txt"
        if (!(Test-Path $file)) {
            $caption = "Restart Computer?"
            Add-Type -AssemblyName System.Windows.Forms
            $message = "Were Windows Updates ran that would require a restart?  If so please click YES to restart now and then start this script over.  Otherwise, please click NO to continue"
            $options = [System.Windows.Forms.MessageBoxButtons]::YesNo
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 1000 * 30 # 30 seconds
            $timer.Enabled = $true
            $timer.add_Tick({
                $timer.Stop()
                $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
                $form.Close()
            })
            $form = New-Object System.Windows.Forms.Form
            $form.Text = $caption
            $form.Width = 400
            $form.Height = 200
            $form.StartPosition = "CenterScreen"
            
            $textBox = New-Object System.Windows.Forms.TextBox
            $textBox.Multiline = $true
            $textBox.Text = $message
            $textBox.ScrollBars = "Vertical"
            $textBox.Location = New-Object System.Drawing.Point(10, 20)
            $textBox.Size = New-Object System.Drawing.Size(360, 60)
            $textBox.ReadOnly = $true
            $form.Controls.Add($textBox)
            
            $yesButton = New-Object System.Windows.Forms.Button
            $yesButton.Location = New-Object System.Drawing.Point(50, 100)
            $yesButton.Size = New-Object System.Drawing.Size(75, 23)
            $yesButton.Text = "Yes (30s)"
            $yesButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
            $yesButton.Add_Click({
                $form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
                $form.Close()
            })
            $form.Controls.Add($yesButton)
            
            $noButton = New-Object System.Windows.Forms.Button
            $noButton.Location = New-Object System.Drawing.Point(150, 100)
            $noButton.Size = New-Object System.Drawing.Size(75, 23)
            $noButton.Text = "No"
            $noButton.DialogResult = [System.Windows.Forms.DialogResult]::No
            $noButton.Add_Click({
                $form.DialogResult = [System.Windows.Forms.DialogResult]::No
                $form.Close()
            })
            $form.Controls.Add($noButton)
            
            $form.Topmost = $true
            $form.Add_Shown({$timer.Start(); $yesButton.Focus()})
            $form.ShowDialog()
            
            if ($form.DialogResult -eq [System.Windows.Forms.DialogResult]::Yes) {
                New-Item -ItemType File -Path $file -Force | Out-Null
                Restart-Computer -Force
            } else {
                Write-Host -ForegroundColor Yellow "[!] WU reboot not requested"
            }
        } else {
            Write-Host -ForegroundColor Green "[+] WU reboot not required"
        }
    }
    

function Step-oobeSetUserRegSettings {
    [CmdletBinding()]
    param ()
    
    # Load Default User Profile hive (ntuser.dat)
    Write-host -ForegroundColor Yellow "[-] Setting default users registry settings ..."
    $DefaultUserProfilePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
    REG LOAD "HKU\Default" $DefaultUserProfilePath | Out-Null

    # Changes to Default User Registry

    Write-host -ForegroundColor DarkGray "[-] Show known file extensions" 
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Change default Explorer view to This PC"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Show User Folder shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f | Out-Null
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Show This PC shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f | Out-Null
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Show item checkboxes"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 1 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Disable Chat on Taskbar"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f | Out-Null   
    
    Write-host -ForegroundColor DarkGray "[-] Disable Windows Spotlight on lockscreen"
    REG ADD "HKU\Default\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f | Out-Null

    # Write-Host -ForegroundColor DarkGray "[-] Unloading the default user registry hive"
    REG UNLOAD "HKU\Default" | Out-Null
    }

function Step-oobeSetDeviceRegSettings {
    [CmdletBinding()]
    param ()
    
    Write-host -ForegroundColor Yellow "[-] Setting default machine registry settings ..."

    Write-host -ForegroundColor DarkGray "[-] Disable IPv6 on all adapters"

        Set-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Enabled $false -ErrorAction SilentlyContinue

    Write-host -ForegroundColor DarkGray "[-] Disable firstlogon animation"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord -ErrorAction SilentlyContinue

    Write-host -ForegroundColor DarkGray "[-] Autoset time zone"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Value "Allow" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate" -Name start -Value "3" -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor DarkGray "[-] Setting start menu items"
        
        if (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start")) {
            New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Force -ErrorAction SilentlyContinue | Out-Null
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
    
    $Username = "ssLocalAdmin"

    # Check if the user already exists
    if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
        Write-Host -ForegroundColor Yellow "[-] Creating local user - $Username"
    
        # Generate a random password of 16 characters
        function Generate-RandomPassword {
            $validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
            $passwordLength = 32
            $random = New-Object System.Random
            $password = 1..$passwordLength | ForEach-Object { $validCharacters[$random.Next(0, $validCharacters.Length)] }
            return $password -join ''
        }
    
        $Password = Generate-RandomPassword
        $NeverExpire = $true
        $UserParams = @{
            "Name"                  = $Username
            "Password"              = (ConvertTo-SecureString -AsPlainText $Password -Force)
            "UserMayNotChangePassword" = $true
            "PasswordNeverExpires"  = $NeverExpire
        }
    
        # Create the user
        New-LocalUser @UserParams | Out-Null
    
        Write-Host -ForegroundColor DarkGray "[+] User '$Username' has been created with password: $Password"
    
        # Add the user to the Administrators group
        Add-LocalGroupMember -Group "Administrators" -Member $Username
    } else {
        Write-Host -ForegroundColor Green "[+] User '$Username' already exists."
    }
    
    }

function Step-desktopWallpaper {
    [CmdletBinding()]
    param ()    
    $scriptPath = "C:\OSDCloud\Scripts\set-desktopWallpaper.ps1"
    if (Test-Path $scriptPath) {
        Write-Host -ForegroundColor Green "[+] Replacing default wallpaper and lockscreen images"        
    } else {        
        Write-Host -ForegroundColor Yellow "[-] Replacing default wallpaper and lockscreen images"
        # Download the script
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/desktopWallpaper.ps1 -OutFile $scriptPath
        # Execute the script
        & $scriptPath -ErrorAction SilentlyContinue
    }        
}

function Step-InstallM365Apps {
    [CmdletBinding()]
    param (
        [System.String]
        $Command
    )    
    $scriptPath = "C:\OSDCloud\Scripts\InstallM365Apps.ps1"
    if (Test-Path $scriptPath) {
        Write-Host -ForegroundColor Green "[+] M365 Applications Installed"        
        return
    } 
    $skyppedPath = "c:\osdcloud\scripts\m365appinstallskipped.txt"
    if (test-path $skyppedPath) {
        Write-Host -ForegroundColor Cyan "[!] Installation of M365 office applications skipped."
        return
    }
    # Display a pop-up asking for user confirmation
    $caption = "Install M365 Apps?"
    $message = "Would you like to install the M365 Office Applications?"
    $options = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $options, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {            
        Write-Host -ForegroundColor Yellow "[-] Installing M365 Applications"
        #$configFile = "C:\OSDCloud\configuration.xml"
        #Invoke-RestMethod -Uri "https://raw.githubusercontent.com/sightsoundtheatres/osd/main/supportFiles/MicrosoftOffice/configuration.xml" -Outfile $configFile
        #winget install microsoft.office --override "/configure $configFile" --accept-source-agreements --accept-package-agreements 
                
        # Download the script
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/InstallM365Apps.ps1 -OutFile $scriptPath
        # Execute the script
        & $scriptPath -XMLURL "https://raw.githubusercontent.com/sightsoundtheatres/osd/main/supportFiles/MicrosoftOffice/configuration.xml" -ErrorAction SilentlyContinue
    }
    else {
        Write-Host -ForegroundColor Cyan "[!] Installation of M365 office applications skipped."
        New-Item -ItemType File -Path $skyppedPath | Out-Null
        return
    }
}

function Step-oobeRestartComputer {
    [CmdletBinding()]
    param ()        
        # Removing downloaded content
        Write-Host -ForegroundColor Yellow "[!] Cleaning up... Removing temperary directories"
        if (Test-Path "C:\osdcloud" -PathType Container) { Remove-Item "C:\osdcloud" -Force -Recurse }
        if (Test-Path "C:\Drivers" -PathType Container) { Remove-Item "C:\Drivers" -Force -Recurse }
        if (Test-Path "C:\Dell" -PathType Container) { Remove-Item "C:\Dell" -Force -Recurse }
        #if (Test-Path "C:\Temp" -PathType Container) { Remove-Item "C:\Temp" -Force -Recurse }
        Write-Host -ForegroundColor Green '[+] Build Complete!'
        Write-Warning 'Device will restart in 30 seconds.  Press Ctrl + C to cancel'
        Stop-Transcript
        Start-Sleep -Seconds 30
        Restart-Computer
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
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/sightsoundtheatres/OSD/master/modules/devicesdell.psm1')       
        osdcloud-InstallDCU
        osdcloud-DCUAutoUpdate
        osdcloud-RunDCU        
        Write-Host -ForegroundColor Green "[+] Dell Command Update installed successfully"
        $ProcessPath = 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe'
    } else {
        Write-Host -ForegroundColor Cyan "[!] DCU not supported"
    }
}
}

function Step-oobeSetDateTime {
    [CmdletBinding()]
    param ()    
        # Syncing time
        #Write-Host -ForegroundColor Green "[+] Syncing system time"
        #w32tm /resync | Out-Null
        
        #$getTime = Get-Date -Format "dddd, MMMM dd, yyyy hh:mm:ss tt zzz"
        #Write-Host -ForegroundColor Yellow "[!] Current time - "$getTime

        Write-Host -ForegroundColor Yellow 'Verify the Date and Time is set properly including the Time Zone'
        Write-Host -ForegroundColor Yellow 'If this is not configured properly, Certificates and Autopilot may fail'
        Start-Process 'ms-settings:dateandtime' | Out-Null
        $ProcessId = (Get-Process -Name 'SystemSettings').Id
        if ($ProcessId) {
            Wait-Process $ProcessId
        }
    }

function Step-oobeHotFix {
    [CmdletBinding()]
    param ()   
    # Check if KB5033055 is installed
    if (Get-HotFix -ID KB5033055 -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor Green "[+] OOBE HOtFix KB5033055 installed."
    }
    else {
        # Download Hotfix for OOBE
        Write-Host -ForegroundColor Yellow "[-] Installing OOBE HotFix KB5033055"
        Invoke-WebRequest -Uri "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/crup/2023/11/windows11.0-kb5033055-x64_62a1eebb6c582bc686dea34197bd2c7165ff5fbf.msu" -OutFile "C:\OSDCloud\windows11.0-kb5033055-x64_62a1eebb6c582bc686dea34197bd2c7165ff5fbf.msu" | Out-Null
        # Install the update
        Start-Process -FilePath "C:\OSDCloud\windows11.0-kb5033055-x64_62a1eebb6c582bc686dea34197bd2c7165ff5fbf.msu" -ArgumentList "/quiet /norestart"
        Write-Host -ForegroundColor Green "[+] OOBE HotFix KB5033055 installed successfully."
    }
}

function step-InstallWinGet {
    [CmdletBinding()]
    param ()

    if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor Green '[+] WinGet is installed'
    }
    else {
        if (Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue) {
            Write-Host -ForegroundColor Yellow '[-] Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
            try {
                Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red '[!] Could not install Microsoft.DesktopAppInstaller AppxPackage'
                Break
            }
        }
    }

    if (Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge '1.21.2701.0' }) {
        Write-Host -ForegroundColor Green '[+] WinGet is current'
    }
    else {
        if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
            $WingetVersion = & winget.exe --version
            [string]$WingetVersion = $WingetVersion -replace '[a-zA-Z\-]'

            Write-Host -ForegroundColor Yellow "[-] WinGet $WingetVersion requires an update"
        }
        else {
            Write-Host -ForegroundColor Yellow '[-] Installing WinGet'
        }

        $progressPreference = 'silentlyContinue'
        Write-Host -ForegroundColor Yellow '[-] Downloading Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

        Write-Host -ForegroundColor Yellow '[-] Downloading Microsoft.VCLibs.x64.14.00.Desktop.appx'
        Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
    
        Write-Host -ForegroundColor Yellow '[-] Downloading Microsoft.UI.Xaml.2.8.x64.appx'
        Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx -OutFile Microsoft.UI.Xaml.2.8.x64.appx

        Write-Host -ForegroundColor Yellow '[-] Installing WinGet and its dependencies'
        Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
        Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
        Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    }
}
    
