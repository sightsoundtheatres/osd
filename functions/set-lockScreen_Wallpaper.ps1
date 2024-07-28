# Define folders
$WallpaperFolder = "C:\Windows\Web\Wallpaper\Windows"
$LockScreenFolder = "C:\Windows\Web\Screen"
$Wallpaper4KFolder = "C:\Windows\Web\4K\Wallpaper\Windows"

# Define files to rename
$FilesToRename = @(
    "$WallpaperFolder\img0.jpg",
    "$LockScreenFolder\img100.jpg",
    "$LockScreenFolder\img105.jpg",
    "$Wallpaper4KFolder\img0_1920x1200.jpg"
)

# Function to set full control permissions for administrators group
function Set-FullControlPermissions {
    param (
        [parameter(Mandatory = $true)]
        [string]$FilePath,
        [parameter(Mandatory = $true)]
        [string]$Principal
    )

    try {
        # Get the current ACL
        $acl = Get-Acl $FilePath

        # Define the access rule
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, "FullControl", "Allow")

        # Add the access rule to the ACL
        $acl.SetAccessRule($rule)

        # Set the modified ACL back to the file
        Set-Acl $FilePath $acl | Out-Null
    }
    catch {
        Write-Host "Failed to set permissions for $FilePath. Error: $_" -ForegroundColor Red
    }
}

# Function to rename files
function Rename-Files {
    param (
        [parameter(Mandatory = $true)]
        [string[]]$FilePaths
    )

    foreach ($FilePath in $FilePaths) {
        try {
            $NewFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($FilePath), [System.IO.Path]::GetFileNameWithoutExtension($FilePath) + "_original" + [System.IO.Path]::GetExtension($FilePath))
            Rename-Item -Path $FilePath -NewName $NewFilePath -Force -ErrorAction Stop
            Write-Host "Renamed file: $FilePath to $NewFilePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to rename file: $FilePath. Error: $_" -ForegroundColor Red
        }
    }
}

# Function to download files
function Download-Files {
    param (
        [parameter(Mandatory = $true)]
        [string]$Uri,
        [parameter(Mandatory = $true)]
        [string]$OutFile
    )

    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -ErrorAction Stop | Out-Null
        Write-Host "Downloaded file: $OutFile" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to download file from $Uri to $OutFile. Error: $_" -ForegroundColor Red
    }
}

# Set full control permissions for administrators group on each file
$AdministratorsGroup = "BUILTIN\Administrators"
foreach ($File in $FilesToRename) {
    Set-FullControlPermissions -FilePath $File -Principal $AdministratorsGroup
}

# Rename the files
Rename-Files -FilePaths $FilesToRename

# URLs for downloading new files
$WallPaperURL = "https://ssintunedata.blob.core.windows.net/customization/img0_3840x2160.jpg"
$LockScreenURL = "https://ssintunedata.blob.core.windows.net/customization/img100.jpg"

# Download and replace wallpaper and lock screen files
Download-Files -Uri $WallPaperURL -OutFile "$WallpaperFolder\img0.jpg"
Download-Files -Uri $LockScreenURL -OutFile "$LockScreenFolder\img100.jpg"
Download-Files -Uri $LockScreenURL -OutFile "$LockScreenFolder\img105.jpg"
Download-Files -Uri $WallPaperURL -OutFile "$Wallpaper4KFolder\img0_1920x1200.jpg"
