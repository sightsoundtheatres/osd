# Clear the screen and display banner
Clear-Host
Write-Host "###############################################" -ForegroundColor Cyan
Write-Host "#   Microsoft Dynamics Store Commerce Setup   #" -ForegroundColor Cyan
Write-Host "###############################################" -ForegroundColor Cyan

# Ask user for installation type
$installType = Read-Host "Is this a (F)resh install or (U)pdating application? Enter F or U"

if ($installType -eq 'F') {
    Write-Host "Starting Fresh Install..." -ForegroundColor Green

    # Install necessary WinGet Packages
    ########################################################

    $apps = "Microsoft.DotNet.DesktopRuntime.6", "Microsoft.DotNet.SDK.8"

    foreach ($app in $apps) {
        winget install --id $app --accept-package-agreements --accept-source-agreements -e
    }

    # Set necessary reg keys
    ########################################################

    # Function to create registry key if it doesn't exist
    function Create-RegistryKeyIfNotExists {
        param (
            [string]$Path
        )
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    # Function to create registry property if it doesn't exist
    function Create-RegistryPropertyIfNotExists {
        param (
            [string]$Path,
            [string]$Name,
            [string]$Value,
            [string]$PropertyType
        )
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        if (-not (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
        }
    }

    # Create SSL and TLS registry keys and properties
    $protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2")
    foreach ($protocol in $protocols) {
        Create-RegistryKeyIfNotExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
        Create-RegistryPropertyIfNotExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client" "Enabled" 0 "DWord"
        Create-RegistryKeyIfNotExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
        Create-RegistryPropertyIfNotExists "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" "Enabled" 0 "DWord"
    }

    # TLS 1.2 needs special handling
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0

    # Create SchUseStrongCrypto registry keys
    $frameworks = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    foreach ($framework in $frameworks) {
        Create-RegistryPropertyIfNotExists $framework "SchUseStrongCrypto" 1 "DWord"
    }

    # Restart the explorer process to reload the registry
    ########################################################
    $processId = (Get-Process -Name explorer).Id
    Stop-Process -Id $processId -Force

    # Download and install the StoreCommerce app
    ########################################################
    $url = "https://ssintunedata.blob.core.windows.net/d365/StoreCommerce.Installer.exe"
    $outputDir = "C:\temp"
    $outputFile = Join-Path $outputDir "StoreCommerce.Installer.exe"

    if (!(Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    Start-BitsTransfer -Source $url -Destination $outputFile -Priority Foreground
    cd $outputDir
    .\StoreCommerce.Installer.exe install --useremoteappcontent --retailserverurl "https://sst-prodret.operations.dynamics.com/Commerce"

    # Download and install the Epson OPOS ADK
    ########################################################
    $url = "https://ssintunedata.blob.core.windows.net/d365/EPSON_OPOS_ADK_V3.00ER20.exe"
    $outputFile = Join-Path $outputDir "EPSON_OPOS_ADK_V3.00ER20.exe"

    Start-BitsTransfer -Source $url -Destination $outputFile -Priority Foreground
    .\EPSON_OPOS_ADK_V3.00ER20.exe /q DisplayInternalUI=”no”

    # Download and install the Epson OPOS CCOs
    ########################################################
    $url = "https://ssintunedata.blob.core.windows.net/d365/OPOS_CCOs_1.14.001.msi"
    $outputFile = Join-Path $outputDir "OPOS_CCOs_1.14.001.msi"

    Start-BitsTransfer -Source $url -Destination $outputFile -Priority Foreground
    msiexec /I "OPOS_CCOs_1.14.001.msi" /quiet

    # Setup local POSUser account
    ########################################################
    $username = "POSUser"
    $password = ConvertTo-SecureString "Almond1" -AsPlainText -Force

    if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
        Write-Host "User $username already exists. Skipping user creation."
    } else {
        New-LocalUser -Name $username -Password $password -PasswordNeverExpires
        Write-Host -ForegroundColor Green "[+] User $username created with password set to never expire."
    }

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regProps = @{
        "DefaultUserName" = $username
        "DefaultPassword" = "Almond1"
        "AutoAdminLogon" = "1"
    }
    foreach ($prop in $regProps.GetEnumerator()) {
        Set-ItemProperty -Path $regPath -Name $prop.Key -Value $prop.Value
    }

    Write-Host -ForegroundColor Green "[+] Auto-login configured."

    # Disable OneDrive for all users
    ########################################################
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name "DisableFileSyncNGSC" -Value 1
    Write-Host -ForegroundColor Green "[+] OneDrive disabled for all users"

    # Set power settings
    ########################################################
    powercfg /change monitor-timeout-ac 20
    powercfg /change standby-timeout-ac 0

    # Create install notes .txt file in c:\temp
    ########################################################
    $URL = "https://ssintunedata.blob.core.windows.net/d365/POS_install_notes.txt"
    $Destination = "C:\temp\POS_install_notes.txt"

    if (!(Test-Path -Path "C:\temp")) {
        New-Item -ItemType Directory -Path "C:\temp"
    }
    Invoke-WebRequest -Uri $URL -OutFile $Destination
    Write-Host -ForegroundColor Cyan "[!] Install notes .txt file saved in c:\temp"

    # Restart computer
    ########################################################
    Write-Warning 'Device will restart in 30 seconds. Press Ctrl + C to cancel'
    Start-Sleep -Seconds 30
    Restart-Computer -Force

    

} elseif ($installType -eq 'U') {
    Write-Host "Updating Application..." -ForegroundColor Yellow

    # Check if the current version has been uninstalled manually
    $confirmation = Read-Host "You are about to re-install the Store Commerce Application (C to continue)" 
    if ($confirmation -ne 'C') {
        Write-Warning "Please press 'C' to continue."
        exit
    }

    # Download and install the StoreCommerce app
    ########################################################
    $url = "https://ssintunedata.blob.core.windows.net/d365/StoreCommerce.Installer.exe"
    $outputDir = "C:\temp"
    $outputFile = Join-Path $outputDir "StoreCommerce.Installer.exe"

    if (!(Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    # Download the file using System.Net.WebClient
    Write-Host "Downloading Store Commerce Application..." -ForegroundColor Green
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $outputFile)
    cd $outputDir
    .\StoreCommerce.Installer.exe install --useremoteappcontent 
    
else {
    Write-Host "Invalid selection. Please run the script again and choose F or U." -ForegroundColor Red
}
