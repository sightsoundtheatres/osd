# Uninstall StoreCommerce app
########################################################

# Get the package information for the Microsoft Store Commerce application
$package = Get-AppxPackage -Name "Microsoft.StorePurchaseApp"

# Check if the package is installed
if ($package) {
    # Uninstall the Microsoft Store Commerce application
    Remove-AppxPackage -Package $package.PackageFullName
    Write-Output "[+] Microsoft Store Commerce application has been uninstalled successfully." -ForegroundColor Green
} else {
    Write-Warning "Microsoft Store Commerce application is not installed on this system."
}


# Download and install the StoreCommerce app 
########################################################

$url = "https://ssintunedata.blob.core.windows.net/d365/StoreCommerce.Installer.exe"
$outputDir = "C:\temp"
$outputFile = Join-Path $outputDir "StoreCommerce.Installer.exe"

# Check if the output directory exists and create it if necessary
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Download the file
Invoke-WebRequest -Uri $url -OutFile $outputFile

# Run the installer with the provided arguments
cd $outputDir
.\StoreCommerce.Installer.exe install --useremoteappcontent --retailserverurl "https://sst-prodret.operations.dynamics.com/Commerce"

