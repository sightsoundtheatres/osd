# Install the get-windowsautopilotcommunity.ps1 script
install-script get-windowsautopilotinfocommunity.ps1 -Force

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
    $AssignedComputerName = Read-Host "Enter the AssignedComputerName (15 characters or less)"
    if ($AssignedComputerName.Length -gt 15) {
        Write-Warning "AssignedComputerName must be 15 characters or less"
    }
} while ($AssignedComputerName.Length -gt 15)

# Define the options for the AddToGroup parameter
$AddToGroupOptions = @("Group 1", "Group 2", "Group 3", "Group 4", "Group 5")

# Display the menu for the AddToGroup parameter
Write-Host "Select an AddToGroup option:"
for ($i = 0; $i -lt $AddToGroupOptions.Count; $i++) {
    Write-Host "$($i + 1): $($AddToGroupOptions[$i])"
}
$AddToGroupChoice = Read-Host "Enter your choice"
$AddToGroup = $AddToGroupOptions[$AddToGroupChoice - 1]

# Call the get-windowsautopilotinfo.ps1 script with the specified parameters
get-windowsautopilotinfocommunity.ps1 -online -GroupTag $GroupTag -AssignedComputerName $AssignedComputerName -AddToGroup $AddToGroup