$ScriptVersion = "24.4.9.1"

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

try {
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
}
catch {
    Write-Output "Not in TS"
}

if ($tsenv) {
    $InWinPE = $tsenv.value('_SMSTSInWinPE')
}

if ($InWinPE -ne "TRUE") {
    enable-privilege SeTakeOwnershipPrivilege 

    $wallpaperFiles = Get-ChildItem -Path C:\Windows\Web\4K -Recurse | where-object {$_.Extension -eq ".jpg"}
    $lockScreenFiles = Get-ChildItem -Path C:\Windows\Web\Screen

    $identity = "BUILTIN\Administrators"
    foreach ($filechild in $wallpaperFiles) {
        Set-Owner -identity $identity -filepath $filechild.fullname
    }

    foreach ($filechild in $lockScreenFiles) {
        Set-Owner -identity $identity -filepath $filechild.fullname
    }

    $identity = "BUILTIN\Administrators"
    $FilesSystemRights = "FullControl"
    $type = "Allow"
    foreach ($filechild in $wallpaperFiles) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.fullname
    }

    foreach ($filechild in $lockScreenFiles) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.fullname
    }

    $identity = "NT AUTHORITY\SYSTEM"
    $FilesSystemRights = "FullControl"
    $type = "Allow"
    foreach ($filechild in $wallpaperFiles) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.fullname
    }

    foreach ($filechild in $lockScreenFiles) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.fullname
    }

    foreach ($filechild in $lockScreenFiles) {
        remove-item -Path $filechild.fullname -Force -Verbose
        Write-Output "Deleting $($filechild.fullname)"
    }
}

$WallPaperURL = "https://ssintunedata.blob.core.windows.net/customization/img0_3840x2160.jpg"
$LockScreenURL = "https://ssintunedata.blob.core.windows.net/customization/img100.jpg"

Invoke-WebRequest -UseBasicParsing -Uri $WallPaperURL -OutFile "$env:TEMP\wallpaper.jpg"
Invoke-WebRequest -UseBasicParsing -Uri $LockScreenURL -OutFile "$env:TEMP\lockscreen.jpg"

if (Test-Path -Path "$env:TEMP\wallpaper.jpg") {
    Copy-Item "$env:TEMP\wallpaper.jpg" "C:\Windows\Web\Wallpaper\Windows\img0.jpg" -Force -Verbose
}
else {
    Write-Output "Did not find wallpaper.jpg in temp folder - Please confirm URL"
}

if (Test-Path -Path "$env:TEMP\lockscreen.jpg") {
    Copy-Item "$env:TEMP\lockscreen.jpg" "C:\Windows\Web\Screen\img100.jpg" -Force -Verbose
    Copy-Item "$env:TEMP\lockscreen.jpg" "C:\Windows\Web\Screen\img105.jpg" -Force -Verbose
}
else {
    Write-Output "Did not find lockscreen.jpg in temp folder - Please confirm URL"
}

exit $exitcode