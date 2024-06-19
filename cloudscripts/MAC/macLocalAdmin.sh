#!/bin/bash

adminaccountname="sslocaladmin"       # This is the account name of the new admin
adminaccountfullname="SS Local Admin" # This is the full name of the new admin user
scriptname="Create Local Admin Account"
logandmetadir="/Library/IntuneScripts/createLocalAdminAccount"
log="$logandmetadir/createLocalAdminAccount.log"

# function to delay until the user has finished setup assistant.
function waitforSetupAssistant {
  until [[ -f /var/db/.AppleSetupDone ]]; do
    delay=$(( $RANDOM % 50 + 10 ))
    echo "$(date) |  + Setup Assistant not done, waiting [$delay] seconds"
    sleep $delay
  done
  echo "$(date) | Setup Assistant is done, lets carry on"
}

## Check if the log directory has been created and start logging
if [ -d "$logandmetadir" ]; then
    ## Already created
    echo "# $(date) | Log directory already exists - $logandmetadir"
else
    ## Creating Metadirectory
    echo "# $(date) | creating log directory - $logandmetadir"
    mkdir -p "$logandmetadir"
fi

# start logging
exec 1>> "$log" 2>&1

# Begin Script Body

echo ""
echo "##############################################################"
echo "# $(date) | Starting $scriptname"
echo "############################################################"
echo ""

echo "Creating new local admin account [$adminaccountname]"

serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
hash=$(echo -n "$serial" | shasum -a 256 | awk '{print $1}')
p=$(echo "$hash" | xxd -r -p | head -c 9 | base64)

waitforSetupAssistant

echo "Adding $adminaccountname to hidden users list"
sudo defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$adminaccountname"

if id "$adminaccountname" &>/dev/null; then
    echo "Deleting existing user $adminaccountname"
    sudo sysadminctl -deleteUser "$adminaccountname"
fi

echo "Creating new user $adminaccountname with admin privileges"
sudo sysadminctl -adminUser "$adminaccountname" -adminPassword "$p" -addUser "$adminaccountname" -fullName "$adminaccountfullname" -password "$p" -admin

# Get the currently logged-in user
currentuser=$(stat -f "%Su" /dev/console)

# Make the current logged-in user a standard user
echo "Making current logged-in user [$currentuser] a standard user"
sudo dscl . -delete /Groups/admin GroupMembership "$currentuser"

echo "Finished creating local admin account and changing current user to standard user."
