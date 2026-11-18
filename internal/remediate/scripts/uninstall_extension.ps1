# Fleet Hound: remove one browser extension from this host (Windows).
# One generic script: the server fills in the three parameters below per run
# and sends it as a one-off Fleet script. Nothing is saved in Fleet.
#
# The host supplies everything else: user profiles, browser data roots and
# browser profiles are discovered here, so the same script serves every
# extension.
$ExtId = '__EXT_ID__'
$ExtStore = '__EXT_STORE__'
$Block = '__BLOCK__'
# Path prefix for tests only; always empty in production.
$Root = ''

$ErrorActionPreference = 'Stop'
$removed = 0
$failed = 0
$blockState = 'not_requested'

# Browser data roots per store, relative to a user profile directory.
$chromiumRoots = @{
    chrome   = @('AppData\Local\Google\Chrome\User Data', 'AppData\Local\Google\Chrome Beta\User Data',
        'AppData\Local\Google\Chrome Dev\User Data', 'AppData\Local\Google\Chrome SxS\User Data')
    edge     = @('AppData\Local\Microsoft\Edge\User Data', 'AppData\Local\Microsoft\Edge Beta\User Data',
        'AppData\Local\Microsoft\Edge Dev\User Data', 'AppData\Local\Microsoft\Edge SxS\User Data')
    brave    = @('AppData\Local\BraveSoftware\Brave-Browser\User Data', 'AppData\Local\BraveSoftware\Brave-Browser-Beta\User Data',
        'AppData\Local\BraveSoftware\Brave-Browser-Nightly\User Data')
    chromium = @('AppData\Local\Chromium\User Data')
    vivaldi  = @('AppData\Local\Vivaldi\User Data')
    opera    = @('AppData\Roaming\Opera Software\Opera Stable', 'AppData\Roaming\Opera Software\Opera GX Stable')
}
$firefoxRoot = 'AppData\Roaming\Mozilla\Firefox\Profiles'

# Machine policy keys per store (HKLM). ExtensionSettings\<id> subkeys are the
# per-extension registry form, so no existing JSON value has to be rewritten.
$policyKeys = @{
    chrome   = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    edge     = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    brave    = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
    chromium = 'HKLM:\SOFTWARE\Policies\Chromium'
}

function Join-Rel([string]$base, [string]$rel) {
    return Join-Path $base $rel.Replace('\', [string][IO.Path]::DirectorySeparatorChar)
}

function Get-UserHomes {
    $usersDir = if ($Root) { Join-Path $Root 'Users' } else { "$env:SystemDrive\Users" }
    if (-not (Test-Path -LiteralPath $usersDir)) { return @() }
    $skip = @('Public', 'Default', 'Default User', 'All Users')
    return @(Get-ChildItem -LiteralPath $usersDir -Directory -Force |
            Where-Object { $skip -notcontains $_.Name } | ForEach-Object { $_.FullName })
}

function Test-Link($item) {
    return [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# These folders belong to users and this script runs as SYSTEM, so a planted
# junction or symlink must never steer a delete. True when no directory
# between the user home and the target is a reparse point.
function Test-NoLinkParents([string]$userHome, [string]$path) {
    $p = Split-Path -Parent $path
    while ($p -and ($p.TrimEnd('\', '/') -ne $userHome.TrimEnd('\', '/'))) {
        $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if (-not $item -or (Test-Link $item)) { return $false }
        $p = Split-Path -Parent $p
    }
    return [bool]$p
}

# Deletes a tree without following links: a reparse point is unlinked, never
# entered. Remove-Item -Recurse is not used because Windows PowerShell 5.1
# follows junctions with it.
function Remove-Tree([string]$path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) {
        if (-not (Test-Link $item)) {
            foreach ($child in @(Get-ChildItem -LiteralPath $path -Force)) { Remove-Tree $child.FullName }
        }
        [IO.Directory]::Delete($path, $false)
    } else {
        $item.Attributes = [IO.FileAttributes]::Normal
        [IO.File]::Delete($path)
    }
}

function Remove-Target([string]$userHome, [string]$path) {
    if (-not (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue)) { return }
    if (-not (Test-NoLinkParents $userHome $path)) {
        Write-Output "skipped (link in path): $path"
        return
    }
    try {
        Remove-Tree $path
        $script:removed++
        Write-Output "removed: $path"
    } catch {
        $script:failed++
        Write-Output "FAILED to remove: $path ($($_.Exception.Message))"
    }
}

function Remove-Chromium {
    foreach ($userHome in Get-UserHomes) {
        foreach ($rel in $chromiumRoots[$ExtStore]) {
            $base = Join-Rel $userHome $rel
            if (-not (Test-Path -LiteralPath $base)) { continue }
            # Every profile (Default, Profile 1, ...) plus a profile-less root.
            foreach ($profileDir in @(Get-ChildItem -LiteralPath $base -Directory -Force)) {
                Remove-Target $userHome (Join-Path (Join-Path $profileDir.FullName 'Extensions') $ExtId)
            }
            Remove-Target $userHome (Join-Path (Join-Path $base 'Extensions') $ExtId)
        }
    }
}

function Remove-Firefox {
    foreach ($userHome in Get-UserHomes) {
        $profiles = Join-Rel $userHome $firefoxRoot
        if (-not (Test-Path -LiteralPath $profiles)) { continue }
        foreach ($profileDir in @(Get-ChildItem -LiteralPath $profiles -Directory -Force)) {
            $ext = Join-Path $profileDir.FullName 'extensions'
            Remove-Target $userHome (Join-Path $ext "$ExtId.xpi")
            Remove-Target $userHome (Join-Path $ext $ExtId)
        }
    }
}

function Block-Chromium {
    $key = $policyKeys[$ExtStore]
    if (-not $key) { return 'unsupported_store' }
    if ($Root) { return 'skipped_test_root' }
    try {
        $existing = Get-ItemProperty -LiteralPath $key -Name 'ExtensionSettings' -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output "block skipped: $key already sets ExtensionSettings as one value; add $ExtId there" | Out-Host
            return 'skipped_existing_policy'
        }
        $sub = "$key\ExtensionSettings\$ExtId"
        New-Item -Path $sub -Force | Out-Null
        New-ItemProperty -LiteralPath $sub -Name 'installation_mode' -Value 'removed' -PropertyType String -Force | Out-Null
        Write-Output "policy written: $sub" | Out-Host
        return 'written'
    } catch {
        Write-Output "block failed: $($_.Exception.Message)" | Out-Host
        return 'failed'
    }
}

if ($ExtStore -eq 'firefox') {
    Remove-Firefox
} elseif ($chromiumRoots.ContainsKey($ExtStore)) {
    Remove-Chromium
} else {
    Write-Output 'FH_RESULT=error'
    Write-Output "unsupported store: $ExtStore"
    exit 2
}

if ($Block -eq '1') {
    if ($ExtStore -eq 'firefox') {
        # Firefox keeps ExtensionSettings as one JSON value; not merged here.
        $blockState = 'unsupported_store'
    } else {
        $blockState = Block-Chromium
    }
}

Write-Output "FH_REMOVED=$removed"
Write-Output "FH_BLOCK=$blockState"
if ($failed -gt 0) {
    Write-Output 'FH_RESULT=error'
    exit 1
}
if ($removed -gt 0) { Write-Output 'FH_RESULT=removed' } else { Write-Output 'FH_RESULT=not_found' }
exit 0
