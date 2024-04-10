# Function to take ownership of a file or folder
function Take-Ownership {
    param(
        [string]$Path
    )

    try {
        # Get the current ACL
        $acl = Get-Acl -Path $Path

        # Get the current owner
        $owner = $acl.Owner

        # Take ownership if not already owned by the current user
        if ($owner -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) {
            $acl.SetOwner([System.Security.Principal.NTAccount]"BUILTIN\Administrators")
            Set-Acl -Path $Path -AclObject $acl
        }
    }
    catch {
        Write-Warning "Failed to take ownership of $Path: $_"
    }
}

# Function to download and replace a file
function Download-And-Replace {
    param(
        [string]$Url,
        [string]$Destination
    )

    try {
        # Download the file
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to download $Url: $_"
        return
    }

    try {
        # Replace the existing file
        Copy-Item -Path $Destination -Destination $Destination -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to replace $Destination: $_"
    }
}

# URLs for wallpaper and lock screen
$WallPaperURL = "https://ssintunedata.blob.core.windows.net/customization/img0_3840x2160.jpg"
$LockScreenURL = "https://ssintunedata.blob.core.windows.net/customization/img100.jpg"

# Paths for wallpaper and lock screen folders
$WallpaperFolder = "C:\Windows\Web\Wallpaper\Windows"
$LockScreenFolder = "C:\Windows\Web\Screen"
$Wallpaper4KFolder = "C:\Windows\Web\4K\Wallpaper\Windows"

# Take ownership of folders and files
Take-Ownership -Path $WallpaperFolder
Take-Ownership -Path $LockScreenFolder
Take-Ownership -Path $Wallpaper4KFolder

# Download and replace wallpaper and lock screen files
Download-And-Replace -Url $WallPaperURL -Destination "$WallpaperFolder\img0.jpg"
Download-And-Replace -Url $LockScreenURL -Destination "$LockScreenFolder\img100.jpg"
Download-And-Replace -Url $WallPaperURL -Destination "$Wallpaper4KFolder\img0_3840x2160.jpg"