# ==========================================
#       OGC Windows Utility Mode Selector
#              By Honest Goat
#               Version: 0.4
# ==========================================

# Start with administrator privileges, bypass execution policy and force black background
function Test-Admin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Test-Admin

Set-ExecutionPolicy Bypass -Scope Process -Force
$host.UI.RawUI.WindowTitle = "OGCWin Utility Launcher"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

# Define colour functions and progress bars
function Write-Color {
    param (
        [string]$Text,
        [string]$ForegroundColor = "White",
        [string]$BackgroundColor = "Black"
    )
    Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
}


# ==========================================
#             DEFINITIONS
# ==========================================

# OGCWin folder definitions
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configsFolder = Join-Path $parentFolder "configs"
$scriptsFolder = Join-Path $parentFolder "scripts"
$binDir = Join-Path $parentFolder "bin"
$tempFolder = Join-Path $parentFolder "temp"

# Filename definitions
$ogcWin = Join-Path $scriptsFolder "OGCWin.ps1"
$ogcWiz11 = Join-Path $scriptsFolder "OGCWiz11.ps1"
$sysInfo = Join-Path $scriptsFolder "sysinfo.ps1"
$launchScript = Join-Path $scriptsFolder "launch.ps1"
$versionLocal = "$configsFolder\version.cfg"

# Update configurations
$versionOnline = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/version.cfg"

# Validation Lists
$RequiredScripts = @("OGCWin.ps1", "OGCWiz11.ps1", "sysinfo.ps1")

# Folder structure
$folders = @($parentFolder, $configsFolder, $scriptsFolder, $binDir, $tempFolder)

# System Info
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption


# ==========================================
#             FUNCTIONS
# ==========================================

function Show-Progress {
    param (
        [string]$Message
    )
    for ($i = 1; $i -le 100; $i += 10) {
        Write-Progress -Activity $Message -Status "$i% Complete" -PercentComplete $i
        Start-Sleep -Milliseconds 300
    }
}

function Get-VersionNumber {
    param ($fileContent)
    if ($fileContent -match "Version=([\d]+(?:\.\d{1,3})?)") { 
        return [version]$matches[1]
    }
    return [version]"0.0"
}


# ==========================================
#        SETUP & VALIDATION
# ==========================================

# Ensure folders exist
foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) { 
        New-Item -Path $folder -ItemType Directory -Force | Out-Null 
    }
}

# Check for Critical Scripts
$MissingScripts = $false

foreach ($s in $RequiredScripts) {
    if (-not (Test-Path (Join-Path $scriptsFolder $s))) {
        Write-Host "Missing critical script: $s" -ForegroundColor Yellow
        $MissingScripts = $true
    }
}

# Repair Logic if scripts are missing
if ($MissingScripts) {
    Write-Host "Installation incomplete or corrupt. Attempting repair..." -ForegroundColor Red
    Start-Sleep -Seconds 2
    
    if (Test-Path $launchScript) {
        Write-Host "Launching local repair..." -ForegroundColor Cyan
        & $launchScript
        exit
    } else {
        Write-Host "Local repair script missing. Initiating full web reinstall..." -ForegroundColor Magenta
        Invoke-Expression (Invoke-RestMethod "https://ogc.win")
        exit
    }
}

# Update Check Logic
if (Test-Path $versionLocal) {
    $localVersion = Get-VersionNumber (Get-Content $versionLocal -Raw)
} else {
    $localVersion = [version]"0.0"
}

try {
    $remoteVersion = Get-VersionNumber (Invoke-RestMethod -Uri $versionOnline -UseBasicParsing)
    
    if ($localVersion -lt $remoteVersion) {
        Write-Host "New version available ($remoteVersion). Updating..." -ForegroundColor Cyan
        Start-Sleep -Seconds 2
        & $launchScript
        exit
    } else {
        Write-Host "OGCWin is up to date (Version $localVersion)." -ForegroundColor Green
    }
} catch {
    Write-Host "Could not check for updates (Offline?). Skipping." -ForegroundColor DarkGray
}


# ==========================================
#           MAIN PROGRAM
# ==========================================

Write-Host ""
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "    OGC Windows Utility Launcher       " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host ""

while ($true) {
    Write-Host "Select Mode:" -ForegroundColor Cyan
    Write-Host "1. Utility Mode - Access the main utility menu" -ForegroundColor Yellow
    
    if ($winVer -match "Windows 11") {
        Write-Host "2. Wizard Mode - Step-by-step new PC setup wizard" -ForegroundColor Yellow
    } else {
        Write-Host "2. Wizard Mode - [WARNING: Windows 11 Only] Setup wizard" -ForegroundColor Red
    }
    
    Write-Host "3. System Information - View hardware/OS details" -ForegroundColor Yellow
    Write-Host "Q. Quit" -ForegroundColor DarkGray
    Write-Host ""
    
    $choice = Read-Host "Enter Selection"
    
    switch ($choice) {
        "1" { 
            Write-Host "Starting Utility..." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            & $ogcWin
        }
        "2" {
            if ($winVer -notmatch "Windows 11") {
                Write-Host "WARNING: This wizard is optimized for Windows 11." -ForegroundColor Red
                Write-Host "Running it on $winVer may cause issues or break features." -ForegroundColor Red
                $confirm = Read-Host "Are you sure you want to proceed? (y/n)"
                if ($confirm -ne "y") { continue }
            }
            Write-Host "Starting Wizard..." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            & $ogcWiz11
        }
        "3" {
            Start-Sleep -Seconds 1
            & $sysInfo
            Write-Host ""
        }
        "Q" { exit }
        "q" { exit }
        default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
    Clear-Host
}