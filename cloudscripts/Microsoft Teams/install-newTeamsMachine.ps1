# Set the download URLs
$teamsbootstrapperURL = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
$MSTeamsx64URL = "https://go.microsoft.com/fwlink/?linkid=2196106"

# Set the destination directory
$destinationDir = "c:\Windows\sightsound"

# Check if the destination directory exists, if not create it
if (!(Test-Path $destinationDir)) {
    New-Item -ItemType Directory -Force -Path $destinationDir
}

# Set the destination file paths
$teamsbootstrapperPath = Join-Path $destinationDir "teamsbootstrapper.exe"
$MSTeamsx64Path = Join-Path $destinationDir "MSTeams-x64.msix"

# Download the files using curl
curl $teamsbootstrapperURL -o $teamsbootstrapperPath
curl $MSTeamsx64URL -o $MSTeamsx64Path