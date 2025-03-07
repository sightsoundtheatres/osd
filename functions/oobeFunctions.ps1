[CmdletBinding()]
param()
$ScriptName = 'oobeFunctions.sight-sound.dev'
$ScriptVersion = '25.3.7.3'

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

function Step-installCertificates {

    # Define an array of certificates to install
    $certs = @(
        @{
            Name        = "Cisco Umbrella"
            Url         = "https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer"
            FileName    = "Cisco_Umbrella_Root_CA.cer"
            IssuerMatch = "*Cisco Umbrella*"
        },
        @{
            Name        = "ST-CA"
            Url         = "https://ssintunedata.blob.core.windows.net/cert/24-st-ca.cer"
            FileName    = "24-ST-CA.cer"
            IssuerMatch = "*ST-CA*"
        },
        @{
            Name        = "SST-ROOT-CA"
            Url         = "https://ssintunedata.blob.core.windows.net/cert/SST-ROOT-CA.crt"
            FileName    = "SST-ROOT-CA.crt"
            IssuerMatch = "*SST-ROOT-CA*"
        }
        # To add another certificate, add another hashtable here.
    )

    # Set the directory where certificates will be temporarily stored
    $certDirectory = "C:\OSDCloud\Temp"

    # Ensure the directory exists
    if (-not (Test-Path -Path $certDirectory)) {
        Write-Host -ForegroundColor Yellow "[-] Directory $certDirectory does not exist. Creating it..."
        New-Item -Path $certDirectory -ItemType Directory | Out-Null
    }

    # Loop through each certificate definition
    foreach ($cert in $certs) {

        # Check if the certificate is already installed by matching the issuer name
        $certExists = Get-ChildItem -Path 'Cert:\LocalMachine\Root\' |
                      Where-Object { $_.Issuer -like $cert.IssuerMatch }

        if ($certExists) {
            Write-Host -ForegroundColor Green "[+] $($cert.Name) root certificate is already installed"
        }
        else {
            Write-Host -ForegroundColor Yellow "[-] Installing $($cert.Name) root certificate"

            # Define the full file path for the downloaded certificate
            $certFile = Join-Path -Path $certDirectory -ChildPath $cert.FileName

            # Download the certificate
            Invoke-WebRequest -Uri $cert.Url -OutFile $certFile

            # Load the certificate from the file
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $Certificate.Import($certFile)

            # Open the local machine Root store in ReadWrite mode, add the certificate, then close the store
            $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $Store.Open("ReadWrite")
            $Store.Add($Certificate)
            $Store.Close()

            # Clean up the downloaded file
            Remove-Item $certFile -Force
            Write-Host -ForegroundColor Green "[+] $($cert.Name) root certificate installed"
        }
    }
}
    function Step-oobeInstallModuleGetWindowsAutopilotInfoCommunity {
        [CmdletBinding()]
        param ()
            # Install the get-windowsautopilotinfocommunity script
            Install-Script Get-WindowsAutopilotInfo -Force
            Install-Script Get-AutopilotDiagnosticsCommunity -Force    
    
            # Define the options for the GroupTag parameter
            $GroupTagOptions = @("Development", "Enterprise","MTR-")
    
            # Display the menu for the GroupTag parameter
            Write-Host "Select a GroupTag:" -ForegroundColor Yellow        
            for ($i = 0; $i -lt $GroupTagOptions.Count; $i++) {
                Write-Host "[$($i + 1)]" -ForegroundColor White -NoNewline
                Write-Host " $($GroupTagOptions[$i])" -ForegroundColor DarkCyan
            }
            $GroupTagChoice = Read-Host "Enter your choice"
            $GroupTag = $GroupTagOptions[$GroupTagChoice - 1]
    
            # If GroupTag is MTR-, prompt for room name
            if ($GroupTag -eq "MTR-") {
                Write-Host "Enter the room name (e.g., BR The Garden): " -ForegroundColor Yellow -NoNewline
                $RoomName = Read-Host
    
                # Remove spaces from the room name
                $RoomName = $RoomName -replace '\s+', ''
    
                # Append the formatted room name to the GroupTag
                $GroupTag = $GroupTag + $RoomName
            }
    
            # Prompt the user to enter a value for the AssignedComputerName parameter
            do {
                Write-Host "Enter the AssignedComputerName ex XXWIN-EID-XXXX (15 characters or less): " -ForegroundColor Yellow -NoNewline
                $AssignedComputerName = (Read-Host).ToUpper()
                if ($AssignedComputerName.Length -gt 15) {
                    Write-Host "WARNING: AssignedComputerName must be 15 characters or less" -ForegroundColor Yellow
                }
            } while ($AssignedComputerName.Length -gt 15)
    
            # Define the options for the AddToGroup parameter using the group names directly
            $AddToGroupOptions = @(
                "Autopilot_Devices-GeneralUsers",
                "Autopilot_Devices-Box_CC",
                "AutoPilot_Devices-Retail",
                "Autopilot_Devices-CenterStageKiosk",
                "Autopilot_Devices-SharedDevice",
                "AutoPilot_Devices-TeamsRooms"
            )
    
            # Display the menu for the AddToGroup parameter
            Write-Host "Select an AddToGroup option:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $AddToGroupOptions.Count; $i++) {
                Write-Host "[$($i + 1)]" -ForegroundColor White -NoNewline
                Write-Host " $($AddToGroupOptions[$i])" -ForegroundColor DarkCyan
            }
    
            $AddToGroupChoice = Read-Host "Enter your choice"
            $AddToGroup = $AddToGroupOptions[$AddToGroupChoice - 1]
    
            # Output the selected AddToGroup value for verification
            Write-Host "Tag: $GroupTag - Computer Name: $AssignedComputerName - Group: $AddToGroup" -ForegroundColor Green
    
            # Call the get-windowsautopilotinfo.ps1 script with the specified parameters
            get-windowsautopilotinfo.ps1 -Assign -GroupTag $GroupTag -AssignedComputerName $AssignedComputerName -AddToGroup $AddToGroup -online
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
            Write-Host -ForegroundColor Yellow "[-] Registering Device in Autopilot using get-WindowsAutoPilotInfoCommunity"
            #Step-oobeInstallModuleGetWindowsAutopilotInfoCommunity
            Step-oobeAutoPilotAppRegisteration
        }
        else {
            Write-Host -ForegroundColor Cyan "[!] Device registration with Autopilot skipped."
            return
        }
    }
    function Step-oobeAutoPilotAppRegisteration {
        [CmdletBinding()]
        param ()
    
        # Install the get-windowsautopilotinfocommunity script
        Install-Script Get-WindowsAutopilotInfo -Force
        Install-Script Get-AutopilotDiagnosticsCommunity -Force    
    
        # Loop until options are confirmed
        $optionsConfirmed = $false
        while (-not $optionsConfirmed) {
            # Define the options for the GroupTag parameter
            $GroupTagOptions = @("Development", "Enterprise", "MTR-")
    
            # Display the menu for the GroupTag parameter
            Write-Host "Select a GroupTag:" -ForegroundColor Yellow        
            for ($i = 0; $i -lt $GroupTagOptions.Count; $i++) {
                Write-Host "[$($i + 1)]" -ForegroundColor White -NoNewline
                Write-Host " $($GroupTagOptions[$i])" -ForegroundColor DarkCyan
            }
            $GroupTagChoice = Read-Host "Enter your choice"
            $GroupTag = $GroupTagOptions[$GroupTagChoice - 1]
    
            # If GroupTag is MTR-, prompt for room name
            if ($GroupTag -eq "MTR-") {
                Write-Host "Enter the room name (e.g., BR The Garden): " -ForegroundColor Yellow -NoNewline
                $RoomName = Read-Host
                $RoomName = $RoomName -replace '\s+', ''
                $GroupTag = $GroupTag + $RoomName
            }
    
            # Prompt the user to enter a value for the AssignedComputerName parameter
            do {
                Write-Host "Enter the AssignedComputerName ex XXWIN-EID-XXXX (15 characters or less): " -ForegroundColor Yellow -NoNewline
                $AssignedComputerName = (Read-Host).ToUpper()
                if ($AssignedComputerName.Length -gt 15) {
                    Write-Host "WARNING: AssignedComputerName must be 15 characters or less" -ForegroundColor Yellow
                }
            } while ($AssignedComputerName.Length -gt 15)
    
            # Define the options for the AddToGroup parameter using the group names directly
            $AddToGroupOptions = @(
                "Autopilot_Devices-GeneralUsers",
                "Autopilot_Devices-Box_CC",
                "AutoPilot_Devices-Retail",
                "Autopilot_Devices-CenterStageKiosk",
                "Autopilot_Devices-SharedDevice",
                "AutoPilot_Devices-TeamsRooms"
            )
    
            # Display the menu for the AddToGroup parameter
            Write-Host "Select an AddToGroup option:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $AddToGroupOptions.Count; $i++) {
                Write-Host "[$($i + 1)]" -ForegroundColor White -NoNewline
                Write-Host " $($AddToGroupOptions[$i])" -ForegroundColor DarkCyan
            }
    
            $AddToGroupChoice = Read-Host "Enter your choice"
            $AddToGroup = $AddToGroupOptions[$AddToGroupChoice - 1]
    
            # Output the selected values for verification
            Write-Host "Selected options:" -ForegroundColor Green
            Write-Host "Tag: $GroupTag - Computer Name: $AssignedComputerName - Group: $AddToGroup" -ForegroundColor Green
    
            # Ask for confirmation
            $confirmation = Read-Host "Are these options correct? (Y/N)"
            $optionsConfirmed = $confirmation -eq 'Y' -or $confirmation -eq 'y'
    
            if (-not $optionsConfirmed) {
                Write-Host "Please re-enter the options." -ForegroundColor Yellow
            }
        }
    
        # Define the URL and temporary file path
        $blobUrl = "https://ssintunedata.blob.core.windows.net/autopilot/autopilot.json.enc"
        $tempFile = "$env:TEMP\autopilot.json.enc"
    
        # Download the encrypted file from Blob Storage
        try {
            Invoke-WebRequest -Uri $blobUrl -OutFile $tempFile -ErrorAction Stop
        } catch {
            Write-Error "Failed to download file from $blobUrl : $_"
            return
        }
    
        # Passphrase retry loop
        $maxAttempts = 3
        $attempt = 1
        $decryptedSuccessfully = $false
    
        while (-not $decryptedSuccessfully -and $attempt -le $maxAttempts) {
            # Prompt for passphrase
            $passphrase = Read-Host "Enter the passphrase to enroll the device (Attempt $attempt of $maxAttempts)" -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
            $plainPassphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    
            # Decrypt the file
            try {
                $encryptedBytesWithSaltAndIV = [System.IO.File]::ReadAllBytes($tempFile)
                $salt = $encryptedBytesWithSaltAndIV[0..15]
                $iv = $encryptedBytesWithSaltAndIV[16..31]
                $encryptedBytes = $encryptedBytesWithSaltAndIV[32..($encryptedBytesWithSaltAndIV.Length - 1)]
    
                $aes = [System.Security.Cryptography.Aes]::Create()
                $aes.KeySize = 256
                $aes.BlockSize = 128
                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
                $passphraseBytes = [System.Text.Encoding]::UTF8.GetBytes($plainPassphrase)
                $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphraseBytes, $salt, 100000)
                $aes.Key = $keyDerivation.GetBytes(32)
                $aes.IV = $iv
    
                $decryptor = $aes.CreateDecryptor()
                $memoryStream = New-Object System.IO.MemoryStream
                $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    
                $cryptoStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
                $cryptoStream.FlushFinalBlock()
    
                $decryptedBytes = $memoryStream.ToArray()
                $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    
                $cryptoStream.Close()
                $memoryStream.Close()
                $aes.Dispose()
    
                # Parse the decrypted JSON
                $jsonContent = $decryptedText | ConvertFrom-Json
                $TenantID = $jsonContent.TenantID
                $appID = $jsonContent.appid
                $appsecret = $jsonContent.appsecret
                Write-Host "[+] Successfully extracted tenant information" -ForegroundColor Green
                $decryptedSuccessfully = $true
            } catch {
                Write-Host "Decryption or parsing failed (possibly incorrect passphrase). Please try again." -ForegroundColor Yellow
                $attempt++
            } finally {
                # Clean up passphrase from memory
                if ($bstr) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
                if (Get-Variable -Name plainPassphrase -ErrorAction SilentlyContinue) {
                    Remove-Variable -Name plainPassphrase -Force
                }
            }
        }
    
        # Clean up the temporary file
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    
        # Check if decryption succeeded
        if (-not $decryptedSuccessfully) {
            Write-Error "Failed to decrypt after $maxAttempts attempts. Exiting."
            return
        }
    
        # Call the get-windowsautopilotinfo.ps1 script with the additional parameters
        get-windowsautopilotinfo.ps1 -Assign -GroupTag $GroupTag -AssignedComputerName $AssignedComputerName -AddToGroup $AddToGroup -online -TenantID $TenantID -appID $appID -appsecret $appsecret
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

    #Write-host -ForegroundColor DarkGray "[-] Disable Chat on Taskbar"
    #REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f | Out-Null  
    
    #Write-host -ForegroundColor DarkGray "[-] Disable widgets on Taskbar"
    #REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f | Out-Null   
    
    Write-host -ForegroundColor DarkGray "[-] Disable Windows Spotlight on lockscreen"
    REG ADD "HKU\Default\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f | Out-Null

    Write-host -ForegroundColor DarkGray "[-] Stop Start menu from opening on first logon"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartShownOnUpgrade" /t REG_DWORD /d 1 /f | Out-Null

    Write-Host -ForegroundColor DarkGreen "[+] Unloading the default user registry hive"
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

    Write-Host -ForegroundColor DarkGray "[-] Disabling News and Interests"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" -Name "value" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
    Write-Host -ForegroundColor DarkGray "[-] Disabling Windows Feeds"
        if (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor DarkGray "[-] Setting NumLock to on by default at lockscreen"
        REG ADD "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f | Out-Null
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
        
        $scriptDirectory = "C:\OSDCloud\Scripts"
        $scriptPath = "C:\OSDCloud\Scripts\set-desktopWallpaper.ps1"
    
        # Check if the directory exists, if not, create it
        if (-Not (Test-Path -Path $scriptDirectory)) {
            Write-Host -ForegroundColor Yellow "[-] Directory $scriptDirectory does not exist. Creating it..."
            New-Item -Path $scriptDirectory -ItemType Directory | Out-Null
        }
    
        if (Test-Path $scriptPath) {
            Write-Host -ForegroundColor Green "[+] Replacing default wallpaper and lockscreen images"
        } else {
            Write-Host -ForegroundColor Yellow "[-] Replacing default wallpaper and lockscreen images"
            # Download the script
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/set-lockScreen_Wallpaper.ps1 -OutFile $scriptPath
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
        
        $scriptDirectory = "C:\OSDCloud\Scripts"
        $scriptPath = "C:\OSDCloud\Scripts\InstallM365Apps.ps1"
        $skippedPath = "c:\osdcloud\scripts\m365appinstallskipped.txt"
    
        # Check if the directory exists, if not, create it
        if (-Not (Test-Path -Path $scriptDirectory)) {
            Write-Host -ForegroundColor Yellow "[-] Directory $scriptDirectory does not exist. Creating it..."
            New-Item -Path $scriptDirectory -ItemType Directory | Out-Null
        }
    
        if (Test-Path $scriptPath) {
            Write-Host -ForegroundColor Green "[+] M365 Applications Installed"
            return
        }
    
        if (Test-Path $skippedPath) {
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
            # Download the script
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/sightsoundtheatres/osd/main/functions/InstallM365Apps.ps1 -OutFile $scriptPath
            # Execute the script
            & $scriptPath -XMLURL "https://raw.githubusercontent.com/sightsoundtheatres/osd/main/supportFiles/MicrosoftOffice/configuration.xml" -ErrorAction SilentlyContinue
        }
        else {
            Write-Host -ForegroundColor Cyan "[!] Installation of M365 office applications skipped."
            New-Item -ItemType File -Path $skippedPath | Out-Null
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

    # Check if the system is a Dell
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerSystem.Manufacturer -notmatch "Dell") {
        Write-Host -ForegroundColor Cyan "[!] This is not a Dell system, your running a" $computerSystem.Manufacturer $computerSystem.Model 
        return
    } 

    Write-Host -ForegroundColor Yellow "[-] Dell system detected"

        $Manufacturer = (Get-CimInstance -Class:Win32_ComputerSystem).Manufacturer
        $Model = (Get-CimInstance -Class:Win32_ComputerSystem).Model
        $SystemSKUNumber = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemSKUNumber
        
        write-output "Manufacturer:    $Manufacturer"
        write-output "Model:           $Model"
        write-output "SystemSKUNumber: $SystemSKUNumber"

    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/gwblok/garytown/refs/heads/master/hardware/Dell/CommandUpdate/EMPS/Dell-EMPSps1')

    # Dell system confirmed; check if Dell Command Update is already installed.
    if ((Test-Path 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe') -or (Test-Path 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe')) {
        Write-Host -ForegroundColor Green "[+] Dell Command Update is already installed."
        Invoke-DCU -applyUpdates -reboot Disable
    } else {            
        # Ensure winget is available.
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Error "winget is not available on this system."
            return
        }

        Write-Host -ForegroundColor Yellow "[-] Installing Dell Command Update"

        # Install Dell Command Update via winget.
        winget install Dell.CommandUpdate --accept-source-agreements --accept-package-agreements

        Write-Host -ForegroundColor Green "[+] Dell Command Update installed successfully."
        Write-Host -ForegroundColor Yellow "[-] Applying updates with Dell Command Update."
        Invoke-DCU -applyUpdates -reboot Disable
        Write-Host -ForegroundColor Green "[+] Dell Command Update updates applied successfully."
    }
}    
    
function Step-oobeSetDateTime {
    [CmdletBinding()]
    param ()    
        Write-Host -ForegroundColor Yellow 'Verify the Date and Time is set properly including the Time Zone'
        Write-Host -ForegroundColor Yellow 'If this is not configured properly, Certificates and Autopilot may fail'
        Start-Process 'ms-settings:dateandtime' | Out-Null
        $ProcessId = (Get-Process -Name 'SystemSettings').Id
        if ($ProcessId) {
            Wait-Process $ProcessId
        }
    }
function step-InstallModuleWinget {
    [CmdletBinding()]
    param ()
    $InstallModule = $false
    $PSModuleName = 'Microsoft.WinGet.Client'
    $InstalledModule = Get-Module -Name $PSModuleName -ListAvailable -ErrorAction Ignore | Sort-Object Version -Descending | Select-Object -First 1
    $GalleryPSModule = Find-Module -Name $PSModuleName -ErrorAction Ignore -WarningAction Ignore
    
    if ($GalleryPSModule) {
        if (($GalleryPSModule.Version -as [version]) -gt ($InstalledModule.Version -as [version])) {
            Write-Host -ForegroundColor Yellow "[-] Install-Module $PSModuleName $($GalleryPSModule.Version)"
            Install-Module $PSModuleName -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber
            Install-WinGetPackage Microsoft.AppInstaller -Force | Out-Null
            #Import-Module $PSModuleName -Force
        }
    }
    $InstalledModule = Get-Module -Name $PSModuleName -ListAvailable -ErrorAction Ignore | Sort-Object Version -Descending | Select-Object -First 1
    if ($GalleryPSModule) {
        if (($InstalledModule.Version -as [version]) -ge ($GalleryPSModule.Version -as [version])) {
            Write-Host -ForegroundColor Green "[+] $PSModuleName $($GalleryPSModule.Version)"
        }
    }    
    Write-Host -ForegroundColor Yellow "[-] Upgrading winget packages"
    winget upgrade --all --accept-source-agreements --accept-package-agreements
    Write-Host -ForegroundColor Green "[+] winget packages upgraded"    
}
function step-setTimeZoneFromIP {
    [CmdletBinding()]
    param ()
    # Fetch the time zone data from the API
    $URIRequest = "http://worldtimeapi.org/api/ip"
    $Response = (Invoke-WebRequest -Uri $URIRequest -UseBasicParsing).Content | ConvertFrom-Json

    # Extract the timezone from the response
    $TimeZoneAPI = $Response.timezone

    # Define the mapping
    $WindowsTimeZones = @{
        "America/Chicago" = "Central Standard Time"
        "America/New_York" = "Eastern Standard Time"
        "America/Denver" = "Mountain Standard Time"
        "America/Phoenix" = "US Mountain Standard Time" 
        "America/Los_Angeles" = "Pacific Standard Time"
        "America/Indiana/Indianapolis" = "Eastern Standard Time"
        "America/Detroit" = "Eastern Standard Time"
        "America/Kentucky/Louisville" = "Eastern Standard Time"
        "America/North_Dakota/Center" = "Central Standard Time"
        "America/Boise" = "Mountain Standard Time"
    }

    # Check if the timezone exists in the mapping
    if ($WindowsTimeZones.ContainsKey($TimeZoneAPI)) {
        $WindowsTimeZone = $WindowsTimeZones[$TimeZoneAPI]
        Set-TimeZone -Id $WindowsTimeZone
        Write-Host "[+] Time zone has been updated to - $WindowsTimeZone" -ForegroundColor Green 
    } else {
        Write-Warning "Time zone not found in the mapping. Using the default Windows time zone."
    }
}

