#      **************** SET THIS VARIABLE ONLY!! ****************           
# This is the URL to the script. NOT the raw URL, that's handled automatically.

$originalScriptLocation = '<INSERT NON-RAW URL>'

#      **************** DO NOT EDIT ANYTHING BELOW **********

Import-Module $env:SyncroModule

<#
.SYNOPSIS
  Secure framework to download & execute a remote script using a GitHub PAT.
  - Secrets stored via DPAPI (Machine and per-User).
  - Framework must run as SYSTEM (LocalSystem).
  - If $runasuser -eq 'yes', payload runs as the logged-in user.

.NOTES
  Original Author: ROI Technology Inc.
  Created: 2025-01-01
  Revised: 2025-08-25
  Version: 2.3.2

 .DISCLAIMER
    Copyright (C) 2025 ROI Technology Inc. and contributors

    Licensed under the GNU General Public License v3.0 (GPLv3).
    See <https://www.gnu.org/licenses/gpl-3.0.html> for details.

    ----------------------------------------------------------------------
    USE AT YOUR OWN RISK:
    These scripts are provided as-is.
    You are solely responsible for validating script integrity, functionality, 
    and safety, including but not limited to any
    payloads you deploy with The Framework. By using The Framework scripts,
    you accept full responsibility for any outcomes, intended or not.
    No warranty is expressed or implied.
    ---------------------------------------------------------------------- 
#>

if (-not $runasuser) { $runasuser = 'no' } # "yes" to run payload as the logged-in user
$ProgressPreference = 'SilentlyContinue'

# Used in Execution Flow section later.
$nonRawUrl = "$originalScriptLocation"
# $rawUrl    = Convert-GitHubToRawUrl $nonRawUrl

# ===================== SECURITY CONSTANTS (generic) =====================
$SECRET_NAME   = 'GITHUB_PAT'
$ENTROPY_BYTES = [Text.Encoding]::UTF8.GetBytes("Org-Secret-v1:$SECRET_NAME")
$USER_BLOB     = Join-Path $env:APPDATA 'SecureStore\Secrets\GITHUB_PAT.bin'
$MACH_BLOB     = "${Env:ProgramData}\SecureStore\Secrets\GITHUB_PAT.bin"
$TEMP_DIR      = "${Env:ProgramData}\SecureStore\Temp"

# ===================== IDENTITY / CONTEXT HELPERS =====================
function Test-IsSystem {
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return ($sid -eq 'S-1-5-18')  # LocalSystem SID
    } catch { return $false }
}
function Get-InteractiveUser { try { (Get-CimInstance Win32_ComputerSystem).UserName } catch { $null } }

# ===================== DPAPI TYPE LOADER =====================
function Ensure-DpapiTypes {
    try { $null = [System.Security.Cryptography.ProtectedData]; $null = [System.Security.Cryptography.DataProtectionScope]; return } catch {}
    $loaded = $false
    foreach($asm in 'System.Security','System.Security.Cryptography.ProtectedData','System.Security.Cryptography.Algorithms'){
        try { Add-Type -AssemblyName $asm -ErrorAction Stop; $loaded = $true; break } catch {}
    }
    if(-not $loaded){ try { [Reflection.Assembly]::Load('System.Security') | Out-Null } catch {} }
    try { $null = [System.Security.Cryptography.ProtectedData]; $null = [System.Security.Cryptography.DataProtectionScope] }
    catch { throw "DPAPI types unavailable in this host/runspace (ProtectedData/DataProtectionScope)." }
}

# ===================== SECRET UTILITIES =====================
function Unprotect-Blob {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][bool]$IsUserScope)
    if (-not (Test-Path $Path)) { return $null }
    Ensure-DpapiTypes
    $enc   = [System.IO.File]::ReadAllBytes($Path)
    $scope = if ($IsUserScope) { [System.Security.Cryptography.DataProtectionScope]::CurrentUser } else { [System.Security.Cryptography.DataProtectionScope]::LocalMachine }
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $ENTROPY_BYTES, $scope)
    $tok   = [System.Text.Encoding]::UTF8.GetString($bytes)
    $bytes=$null; $enc=$null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    return $tok
}
function Get-GitHubPat {
    $token = $null
    if ($env:APPDATA) { $token = Unprotect-Blob -Path $USER_BLOB -IsUserScope $true }
    if (-not $token)  { $token = Unprotect-Blob -Path $MACH_BLOB -IsUserScope $false }
    if (-not $token) { throw "No stored PAT found for user or machine." }
    return $token
}

# ===================== URL CONVERSION ===================== 
# Define the Convert-GitHubToRawUrl function
function Convert-GitHubToRawUrl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url)

    $uri = [Uri]$Url
    if ($uri.Host -eq 'raw.githubusercontent.com') {
        $builder = [System.UriBuilder]::new($Url)
        $builder.Query    = $null
        $builder.Fragment = $null
        $raw = $builder.Uri.AbsoluteUri
        Set-Variable -Name rawURLOutput -Value $raw -Scope 1
        return $raw
    }
    if ($uri.Host -ne 'github.com') {
        throw "Only github.com file URLs can be converted."
    }
    $segments = $uri.AbsolutePath.Trim('/').Split('/')
    $blobIndex = [Array]::IndexOf($segments, 'blob')
    if ($blobIndex -eq -1) { $blobIndex = [Array]::IndexOf($segments, 'tree') }
    if ($blobIndex -eq -1 -or $segments.Length -lt $blobIndex + 3) {
        throw "URL must contain '/blob/' or '/tree/' followed by a branch or ref."
    }
    $owner = $segments[0]; $repo = $segments[1]; $ref  = $segments[$blobIndex + 1]
    $pathSegments = $segments[($blobIndex + 2)..($segments.Length - 1)]
    if ($ref -eq 'refs') {
        $ref = "$($segments[$blobIndex + 1])/$($segments[$blobIndex + 2])/$($segments[$blobIndex + 3])"
        $pathSegments = $segments[($blobIndex + 4)..($segments.Length - 1)]
    } elseif ($ref -notmatch '^[0-9A-Fa-f]{40}$') {
        $ref = "refs/heads/$ref"
    }
    $rawPath = "$owner/$repo/$ref"
    if ($pathSegments) { $rawPath += '/' + ($pathSegments -join '/') }
    $builder = [System.UriBuilder]::new('https','raw.githubusercontent.com',-1,'/' + $rawPath)
    $builder.Query = $null; $builder.Fragment = $null
    $rawUrl = $builder.Uri.AbsoluteUri
    Set-Variable -Name rawURLOutput -Value $rawUrl -Scope 1
    return $rawUrl
}


# ===================== SEED PER-USER SECRET (SYSTEM ONLY) =====================
function Ensure-UserSecretFromMachine {
    if (-not (Test-IsSystem)) { throw "Seeding requires SYSTEM context." }
    $interactive = Get-InteractiveUser
    if (-not $interactive)  { return }                     # no active user
    if (Test-Path $USER_BLOB) { return }                   # already seeded
    if (-not (Test-Path $MACH_BLOB)) { return }            # nothing to seed

    if (-not (Test-Path $TEMP_DIR)) {
        New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
        (Get-Item $TEMP_DIR).Attributes = 'Hidden','System'
    }
    $userScript = Join-Path $TEMP_DIR 'SeedUserPat.ps1'
    $taskName   = 'SecureStore_SeedUserPAT'

    $content = @"
`$ErrorActionPreference = 'Stop'
function Ensure-DpapiTypes {
    try { `$null = [System.Security.Cryptography.ProtectedData]; `$null = [System.Security.Cryptography.DataProtectionScope]; return } catch {}
    `$loaded = `$false
    foreach(`$asm in 'System.Security','System.Security.Cryptography.ProtectedData','System.Security.Cryptography.Algorithms'){
        try { Add-Type -AssemblyName `$asm -ErrorAction Stop; `$loaded = `$true; break } catch {}
    }
    if(-not `$loaded){ try { [Reflection.Assembly]::Load('System.Security') | Out-Null } catch {} }
    try { `$null = [System.Security.Cryptography.ProtectedData]; `$null = [System.Security.Cryptography.DataProtectionScope] }
    catch { throw "DPAPI types unavailable in this host/runspace (ProtectedData/DataProtectionScope)." }
}
Ensure-DpapiTypes

`$Name     = '$SECRET_NAME'
`$Entropy  = [Text.Encoding]::UTF8.GetBytes("Org-Secret-v1:`$Name")
`$MachFile = '$MACH_BLOB'
`$UserBase = Join-Path `$env:APPDATA 'SecureStore\Secrets'
`$UserFile = Join-Path `$UserBase ('{0}.bin' -f `$Name)

if (-not (Test-Path `$MachFile)) { throw "Machine secret missing (`$MachFile)" }

`$enc   = [System.IO.File]::ReadAllBytes(`$MachFile)
`$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(`$enc, `$Entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
`$token = [System.Text.Encoding]::UTF8.GetString(`$bytes)

if (-not (Test-Path `$UserBase)) { New-Item -ItemType Directory -Path `$UserBase -Force | Out-Null }

`$bytesU = [System.Text.Encoding]::UTF8.GetBytes(`$token)
`$encU   = [System.Security.Cryptography.ProtectedData]::Protect(`$bytesU, `$Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.IO.File]::WriteAllBytes(`$UserFile, `$encU)

`$token=$null; `$bytes=$null; `$enc=$null; `$bytesU=$null; `$encU=$null
[GC]::Collect(); [GC]::WaitForPendingFinalizers()
"@
    Set-Content -Path $userScript -Value $content -Encoding UTF8 -Force

    # Temporary read access to machine blob
    $acl  = Get-Acl $MACH_BLOB
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($interactive,'Read','Allow')
    $acl.AddAccessRule($rule); Set-Acl -Path $MACH_BLOB -AclObject $acl

    # One-shot task in user's session
    $start = (Get-Date).AddMinutes(1).ToString('HH:mm')
    schtasks /Create /F /TN $taskName /TR "powershell -NoProfile -ExecutionPolicy Bypass -File `"$userScript`"" /SC ONCE /ST $start /RL LIMITED /RU "$interactive" /IT | Out-Null
    schtasks /Run /TN $taskName | Out-Null

    Start-Sleep -Seconds 10
    try { schtasks /Delete /F /TN $taskName | Out-Null } catch {}
    try { Remove-Item -Path $userScript -Force } catch {}

    # Revoke temporary read
    $acl = Get-Acl $MACH_BLOB
    $acl.RemoveAccessRule($rule) | Out-Null
    Set-Acl -Path $MACH_BLOB -AclObject $acl
}

# ===================== PAYLOAD RUNNERS =====================
function Invoke-RemoteScript {
    param([Parameter(Mandatory)][string]$RemoteScriptUrl, [Parameter(Mandatory)][string]$GitHubPAT)
    $DownloadDirectory = "${Env:ProgramData}\SecureStore\Runtime\Temp"
    $DownloadPath      = Join-Path $DownloadDirectory 'remoteScript.ps1'
    try {
        if (-not (Test-Path -Path $DownloadDirectory)) {
            Write-Host "Creating directory: $DownloadDirectory"
            New-Item -ItemType Directory -Path $DownloadDirectory -Force | Out-Null
        }
        $Headers = @{ Authorization = "Bearer $GitHubPAT"; 'User-Agent' = 'SecureFramework/2.3' }
        Write-Host "Downloading remote script from: $RemoteScriptUrl"
        Write-Host "========================="
        Invoke-WebRequest -Uri $RemoteScriptUrl -Headers $Headers -OutFile $DownloadPath -ErrorAction Stop
        Write-Host "Executing downloaded script: $DownloadPath"
        Write-Host "`n===========BEGIN PAYLOAD OUTPUT==============`n"
        . $DownloadPath
    } catch {
        Write-Error "An error occurred: $_"
        Write-Host "========================="
    } finally {
        Write-Host "`n===========END PAYLOAD OUTPUT==============`n"
        Write-Host "Starting cleanup process from within the function Invoke-RemoteScript"
        Write-Host "========================="
        if (Test-Path $DownloadPath) { Remove-Item -Path $DownloadPath -Force }
        $Headers=$null; $GitHubPAT=$null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        Write-Host "Cleanup process has successfully remove the payload from $DownloadPath"        
    }
}
function Invoke-RemoteScriptAsUser {
    param([Parameter(Mandatory)][string]$RemoteScriptUrl)
    $interactive = Get-InteractiveUser
    if (-not $interactive) { throw "runasuser='yes' but no interactive user is logged in." }
    try { Ensure-UserSecretFromMachine } catch { throw "Unable to seed per-user secret: $($_.Exception.Message)" }

    if (-not (Test-Path $TEMP_DIR)) {
        New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
        (Get-Item $TEMP_DIR).Attributes = 'Hidden','System'
    }
    $bootstrap = Join-Path $TEMP_DIR 'RunPayloadAsUser.ps1'
    $content = @"
`$ErrorActionPreference = 'Stop'
function Ensure-DpapiTypes {
    try { `$null = [System.Security.Cryptography.ProtectedData]; `$null = [System.Security.Cryptography.DataProtectionScope]; return } catch {}
    `$loaded = `$false
    foreach(`$asm in 'System.Security','System.Security.Cryptography.ProtectedData','System.Security.Cryptography.Algorithms'){
        try { Add-Type -AssemblyName `$asm -ErrorAction Stop; `$loaded = `$true; break } catch {}
    }
    if(-not `$loaded){ try { [Reflection.Assembly]::Load('System.Security') | Out-Null } catch {} }
    try { `$null = [System.Security.Cryptography.ProtectedData]; `$null = [System.Security.Cryptography.DataProtectionScope] }
    catch { throw "DPAPI types unavailable in this host/runspace (ProtectedData/DataProtectionScope)." }
}
Ensure-DpapiTypes

function Get-PatUser {
    `$Name     = '$SECRET_NAME'
    `$Entropy  = [Text.Encoding]::UTF8.GetBytes("Org-Secret-v1:`$Name")
    `$UserFile = Join-Path `$env:APPDATA 'SecureStore\Secrets\GITHUB_PAT.bin'
    if (-not (Test-Path `$UserFile)) { throw "User PAT missing (`$UserFile)" }
    `$enc   = [System.IO.File]::ReadAllBytes(`$UserFile)
    `$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(`$enc, `$Entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    `$tok   = [System.Text.Encoding]::UTF8.GetString(`$bytes)
    `$bytes=$null; `$enc=$null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    return `$tok
}

`$RemoteScriptUrl = '$RemoteScriptUrl'
`$GitHubPAT = Get-PatUser

`$DownloadDirectory = Join-Path `$env:TEMP 'SecureFramework\Runtime\Temp'
if (-not (Test-Path `$DownloadDirectory)) { New-Item -ItemType Directory -Path `$DownloadDirectory -Force | Out-Null }
`$DownloadPath = Join-Path `$DownloadDirectory 'remoteScript.ps1'

`$Headers = @{ Authorization = "Bearer `$GitHubPAT"; 'User-Agent' = 'SecureFramework/2.3' }
Invoke-WebRequest -Uri `$RemoteScriptUrl -Headers `$Headers -OutFile `$DownloadPath -ErrorAction Stop
. `$DownloadPath

if (Test-Path `$DownloadPath) { Remove-Item -Path `$DownloadPath -Force }
`$Headers=$null; `$GitHubPAT=$null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
"@
    Set-Content -Path $bootstrap -Value $content -Encoding UTF8 -Force

    $taskName = 'SecureStore_RunPayloadAsUser'
    $start    = (Get-Date).AddMinutes(1).ToString('HH:mm')
    schtasks /Create /F /TN $taskName /TR "powershell -NoProfile -ExecutionPolicy Bypass -File `"$bootstrap`"" /SC ONCE /ST $start /RL LIMITED /RU "$interactive" /IT | Out-Null
    schtasks /Run /TN $taskName | Out-Null

    Start-Sleep -Seconds 10
    try { schtasks /Delete /F /TN $taskName | Out-Null } catch {}
    try { Remove-Item -Path $bootstrap -Force } catch {}
}

# ===================== HARD REQUIREMENT: MUST RUN AS SYSTEM =====================
if (-not (Test-IsSystem)) {
    Write-Host "This Framework must be run as SYSTEM (LocalSystem)."
    Write-Host "If you need the payload to run in the user's context:"
    Write-Host "  1) Re-run this Framework as SYSTEM, and"
    Write-Host "  2) Set `$runasuser = 'yes' for that job."
    exit 1
}

# ===================== EXECUTION FLOW =====================
Write-Host "========================="
Write-Host "Framework executed at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")"
Write-Host "========================="
Write-Host "Converting $nonRawUrl to raw URL..."
Write-Host "========================="
# Convert the non-raw script path to a raw path so we can download the payload and run it. 
$RemoteScriptUrl = Convert-GitHubToRawUrl $nonRawUrl
Write-Host "RAW URL is $RemoteScriptURL"
Write-Host "========================="
Write-Host "The original script is located at: $originalScriptLocation"
Write-Host "========================="
try {
    if ($runasuser -eq 'yes') {
        Write-Host "Script was instructed to run payload as user. Create one-shot scheduled task to run payload as user"
        Invoke-RemoteScriptAsUser -RemoteScriptUrl $RemoteScriptUrl
    } else {
        $GitHubPAT = Get-GitHubPat
        Write-Host "runasuser='no' | running payload as SYSTEM (machine secret)"
        Write-Host "========================="
        Invoke-RemoteScript -RemoteScriptUrl $RemoteScriptUrl -GitHubPAT $GitHubPAT
        Write-Host "========================="
        Write-Host "The payload has finished, cleaning up GitHubPAT"
        Write-Host "========================="
        Remove-Variable -Name GitHubPAT -ErrorAction SilentlyContinue
        Write-Host "Cleanup finished, exiting The Framework"
        exit 0
    }
} catch {
    Write-Error "Framework error: $($_.Exception.Message)"
    exit 1
}
