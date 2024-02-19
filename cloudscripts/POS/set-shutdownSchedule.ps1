<#
This script creates a new scheduled task action to execute the shutdown.exe command with the arguments /s /f /t 0 
to shut down the computer immediately. The trigger for the task is set to run at midnight on every day of the week 
except for Wednesday. The task is then registered with the name "Shutdown"
#>

$Action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/s /f /t 0'
$DaysOfWeek = [System.DayOfWeek]::Sunday, [System.DayOfWeek]::Monday, [System.DayOfWeek]::Tuesday, [System.DayOfWeek]::Thursday, [System.DayOfWeek]::Friday, [System.DayOfWeek]::Saturday
$Trigger = New-ScheduledTaskTrigger -DaysOfWeek $DaysOfWeek -At 12:00am
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Shutdown" -Description "Shutdown computer every night at midnight, except for Wednesday night"