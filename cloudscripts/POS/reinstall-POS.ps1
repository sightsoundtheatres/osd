# Uninstall StoreCommerce app
########################################################

# Get the package information for the Microsoft Store Commerce application for all users
$packages = Get-AppxPackage -AllUsers -Name "Microsoft.StorePurchaseApp"

# Check if any packages were found
if ($packages) {
    foreach ($package in $packages) {
        # Uninstall the Microsoft Store Commerce application for all users
        Remove-AppxPackage -Package $package.PackageFullName -AllUsers
        Write-Output "Uninstalled: $($package.Name) with PackageFullName: $($package.PackageFullName) for all users."
    }
} else {
    Write-Output "Microsoft Store Commerce application is not installed for any users on this system."
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




