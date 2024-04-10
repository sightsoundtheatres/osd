$ScriptVersion = "24.4.9.1"

# Function to enable privilege
function enable-privilege {
    param(
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        $ProcessId = $pid,
        [Switch] $Disable
    )

    $definition = @'
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid {
            public int Count;
            public long Luid;
            public int Attr;
        }
  
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege, bool disable) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            if (disable) {
                tp.Attr = SE_PRIVILEGE_DISABLED;
            }
            else {
                tp.Attr = SE_PRIVILEGE_ENABLED;
            }
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

# Function to set owner of a file
function Set-Owner {
    Param (
        [Parameter(Mandatory=$true)][string] $identity,
        [Parameter(Mandatory=$true)][String] $filepath
    )

    $file = Get-Item -Path $filepath -Force
    $acl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    $me = [System.Security.Principal.NTAccount]$identity
    $acl.SetOwner($me)
    $file.SetAccessControl($acl)

    $acl = $file.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $file.SetAccessControl($acl)
}

# Function to set permission of a file
function Set-Permission {
    Param (
        [Parameter(Mandatory=$true)][string] $identity,
        [Parameter(Mandatory=$true)][String] $filepath,
        [Parameter(Mandatory=$true)][string] $FilesSystemRights,
        [Parameter(Mandatory=$true)][String] $type
    )

    $file = Get-Item $filepath -Force
    $newacl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)

    $FilesSystemAccessRuleArgumentList = $identity, $FilesSystemRights, $type
    $FilesSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FilesSystemAccessRuleArgumentList
    $NewAcl.SetAccessRule($FilesSystemAccessRule)
    Set-Acl -Path $file.FullName -AclObject $NewAcl
}

# Enable Take Ownership privilege
enable-privilege SeTakeOwnershipPrivilege 

# Paths for wallpaper and lock screen folders
$WallpaperFolder = "C:\Windows\Web\Wallpaper\Windows"
$LockScreenFolder = "C:\Windows\Web\Screen"
$Wallpaper4KFolder = "C:\Windows\Web\4K\Wallpaper\Windows"

# Take ownership of folders and files
Set-Owner -identity "BUILTIN\Administrators" -filepath $WallpaperFolder
Set-Owner -identity "BUILTIN\Administrators" -filepath $LockScreenFolder
Set-Owner -identity "BUILTIN\Administrators" -filepath $Wallpaper4KFolder

# Set permissions for folders and files
Set-Permission -identity "BUILTIN\Administrators" -type "Allow" -FilesSystemRights "FullControl" -filepath $WallpaperFolder
Set-Permission -identity "BUILTIN\Administrators" -type "Allow" -FilesSystemRights "FullControl" -filepath $LockScreenFolder
Set-Permission -identity "BUILTIN\Administrators" -type "Allow" -FilesSystemRights "FullControl" -filepath $Wallpaper4KFolder

# Download and replace wallpaper and lock screen files
$WallPaperURL = "https://ssintunedata.blob.core.windows.net/customization/img0_3840x2160.jpg"
$LockScreenURL = "https://ssintunedata.blob.core.windows.net/customization/img100.jpg"

# Delete existing files if they exist
Remove-Item -Path "$WallpaperFolder\img0.jpg" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$LockScreenFolder\img100.jpg" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$LockScreenFolder\img105.jpg" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$Wallpaper4KFolder\img0_1920x1200.jpg" -Force -ErrorAction SilentlyContinue


Invoke-WebRequest -UseBasicParsing -Uri $WallPaperURL -OutFile "$WallpaperFolder\img0.jpg"
Invoke-WebRequest -UseBasicParsing -Uri $LockScreenURL -OutFile "$LockScreenFolder\img100.jpg"
Invoke-WebRequest -UseBasicParsing -Uri $LockScreenURL -OutFile "$LockScreenFolder\img105.jpg"
Invoke-WebRequest -UseBasicParsing -Uri $WallPaperURL -OutFile "$Wallpaper4KFolder\img0_1920x1200.jpg"
