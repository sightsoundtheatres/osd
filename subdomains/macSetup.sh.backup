#!/bin/bash

adminaccountname="sslocaladmin"       # This is the account name of the new admin
adminaccountfullname="SS Local Admin" # This is the full name of the new admin user
certurl="https://ssintunedata.blob.core.windows.net/cert/Cisco_Umbrella_Root_CA.cer" # URL to the root certificate

# Create new local admin account
echo "Creating new local admin account [$adminaccountname]"

serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
hash=$(echo -n "$serial" | shasum -a 256 | awk '{print $1}')
p=$(echo "$hash" | xxd -r -p | head -c 9 | base64)

echo "Adding $adminaccountname to hidden users list"
sudo defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$adminaccountname"

if id "$adminaccountname" &>/dev/null; then
    echo "Deleting existing user $adminaccountname"
    sudo sysadminctl -deleteUser "$adminaccountname"
fi

echo "Creating new user $adminaccountname with admin privileges"
sudo sysadminctl -adminUser "$adminaccountname" -adminPassword "$p" -addUser "$adminaccountname" -fullName "$adminaccountfullname" -password "$p" -admin

# Install root certificate
echo "Downloading and installing root certificate"

certpath="/tmp/Cisco_Umbrella_Root_CA.cer"
curl -s -o "$certpath" "$certurl"

if [ -f "$certpath" ]; then
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$certpath"
    echo "Root certificate installed successfully."
else
    echo "Failed to download the root certificate."
fi

csrutil enable
reboot


echo "Script execution completed."
