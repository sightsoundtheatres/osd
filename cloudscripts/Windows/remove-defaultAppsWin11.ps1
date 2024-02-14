#   Description:
# This script removes unwanted Apps that come with Windows. If you  do not want
# to remove certain Apps comment out the corresponding lines below.


Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 11 apps
	
	#"Microsoft.549981C3F5F10"
	"Microsoft.BingNews"
	"Microsoft.BingWeather"
	"Microsoft.GamingApp"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	#"Microsoft.MicrosoftEdge.Stable"
	#"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftSolitaireCollection"
	#"Microsoft.MicrosoftStickyNotes"
	#"Microsoft.Paint"
	"Microsoft.People"
	#"Microsoft.PowerAutomateDesktop"
	#"Microsoft.ScreenSketch"
	#"Microsoft.Todos"
	#"Microsoft.Windows.Photos"
	#"Microsoft.WindowsAlarms"
	#"Microsoft.WindowsCalculator"
	#"Microsoft.WindowsCamera"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.WindowsMaps"
	#"Microsoft.WindowsNotepad"
	#"Microsoft.WindowsSoundRecorder"
	#"Microsoft.WindowsTerminal"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxSpeechToTextOverlay"
	#"Microsoft.YourPhone"
	#"Microsoft.ZuneMusic"
	#"Microsoft.ZuneVideo"
	"Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
	#"Microsoft.OneDriveSync"
	#"Microsoft.OneDriveSync_21220.1024.5.0_neutral__8wekyb3d8bbwe"

	# Default Windows 11 apps
	"Clipchamp.Clipchamp"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
		
	# Cleanup Local App Data
    $appPath="$Env:LOCALAPPDATA\Packages\$app*"
    Remove-Item $appPath -Recurse -Force -ErrorAction 0
}

