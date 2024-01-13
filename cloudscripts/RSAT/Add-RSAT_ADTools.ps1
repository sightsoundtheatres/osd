#Requires -RunAsAdministrator

#Install AD RSAT Tools:
Get-WindowsCapability -Name "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools" -Online | Add-WindowsCapability -Online