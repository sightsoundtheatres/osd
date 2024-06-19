#!/bin/bash

# Define variables
adminaccountname="ssLocalAdmin"       # This is the account name of the new admin
adminaccountfullname="SS Local Admin" # This is the full name of the new admin user
adminpassword="PASSWORD1!"            # This is the password for the new admin user
certurl="https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer" # URL to the root certificate

# Create new local admin account
echo "Creating new local admin account [$adminaccountname]"

# Use dscl to create the user and set its properties
dscl . -create /Users/"$adminaccountname"
dscl . -create /Users/"$adminaccountname" UserShell /bin/bash
dscl . -create /Users/"$adminaccountname" RealName "$adminaccountfullname"
dscl . -create /Users/"$adminaccountname" UniqueID 1001
dscl . -create /Users/"$adminaccountname" PrimaryGroupID 80
dscl . -create /Users/"$adminaccountname" NFSHomeDirectory /Users/"$adminaccountname"
dscl . -passwd /Users/"$adminaccountname" "$adminpassword"
dscl . -append /Groups/admin GroupMembership "$adminaccountname"