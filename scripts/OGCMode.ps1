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
$configsFolder = "$parentFolder\configs"
$scriptsFolder = "$parentFolder\scripts"
$binDir = "$parentFolder\bin"
$tempFolder = "$parentFolder\temp"

# Filename definitions
$ogcWin = "$scriptsFolder\OGCWin.ps1"
$ogcWiz11 = "$scriptsFolder\OGCWiz11.ps1"
$sysInfo = "$scriptsFolder\sysinfo.ps1"
$launchScript = "$scriptsFolder\launch.ps1"
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
$versionLocal = "$configsFolder\version.cfg"
$versionOnline = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/version.cfg"

# Validation Lists
$RequiredScripts = @("OGCWin.ps1", "OGCWiz11.ps1", "sysinfo.ps1")

# Folder structure
$folders = @($parentFolder, $configsFolder, $scriptsFolder, $binDir, $tempFolder, $logFolder)


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

function Write-Log {
    param (
        [Parameter(Mandatory=$true)] [string]$Message,
        [Parameter(Mandatory=$false)] [ValidateSet("SUCCESS","FAILURE","INFO","WARNING","ERROR")] [string]$Status = "INFO",
        [string]$Module = "General"
    )
    $logFolder = Join-Path $parentFolder "logs"
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $logFile = Join-Path $logFolder "${scriptName}_log.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $lineNumber = $MyInvocation.ScriptLineNumber
    $logEntry = "[$Status] [$timestamp] [Line:$lineNumber] [$Module] $Message"
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    try { Add-Content -Path $logFile -Value $logEntry -Force -ErrorAction Stop }
    catch { Write-Host "CRITICAL: Can't write to $logFile" -ForegroundColor Red }
    if ($Status -eq "FAILURE") { Write-Host "Error ($Module): $Message" -ForegroundColor Red }
    elseif ($Status -eq "WARNING") { Write-Host "Warning ($Module): $Message" -ForegroundColor Yellow }
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
    try {
        if (-not (Test-Path $folder)) { 
            New-Item -Path $folder -ItemType Directory -Force | Out-Null 
            Write-Log "Created directory: $folder"
        }
    } catch {
        Write-Log "Failed to create directory $folder : $_" "ERROR"
    }
}

Write-Log "Starting OGCWin Mode Selector. Detected OS: $winVer"

# Check for Critical Scripts
$MissingScripts = $false

foreach ($s in $RequiredScripts) {
    if (-not (Test-Path (Join-Path $scriptsFolder $s))) {
        Write-Host "Missing critical script: $s" -ForegroundColor Yellow
        Write-Log "Critical script missing: $s" "WARNING"
        $MissingScripts = $true
    }
}

# Repair Logic if scripts are missing
if ($MissingScripts) {
    Write-Host "Installation incomplete or corrupt. Attempting repair..." -ForegroundColor Red
    Write-Log "Missing scripts detected. Initiating repair." "WARNING"
    Start-Sleep -Seconds 2
    
    if (Test-Path $launchScript) {
        Write-Host "Launching local repair..." -ForegroundColor Cyan
        try {
            Write-Log "Launching local repair script."
            & $launchScript
            exit
        } catch {
            Write-Log "Failed to execute local repair script: $_" "ERROR"
        }
    } else {
        Write-Host "Local repair script missing. Initiating full web reinstall..." -ForegroundColor Magenta
        try {
            Write-Log "Local repair missing. Starting web reinstall."
            Invoke-Expression (Invoke-RestMethod "https://ogc.win")
            exit
        } catch {
            Write-Log "Failed to initiate web reinstall: $_" "ERROR"
        }
    }
}

# Update Check Logic
if (Test-Path $versionLocal) {
    $localVersion = Get-VersionNumber (Get-Content $versionLocal -Raw)
} else {
    $localVersion = [version]"0.0"
}

try {
    Write-Log "Checking for updates..."
    $remoteVersion = Get-VersionNumber (Invoke-RestMethod -Uri $versionOnline -UseBasicParsing -ErrorAction Stop)
    
    if ($localVersion -lt $remoteVersion) {
        Write-Host "New version available ($remoteVersion). Updating..." -ForegroundColor Cyan
        Write-Log "Update available: Local ($localVersion) < Remote ($remoteVersion). Updating."
        Start-Sleep -Seconds 2
        
        try {
            & $launchScript
            exit
        } catch {
            Write-Log "Failed to launch update script: $_" "ERROR"
        }
    } else {
        Write-Host "OGCWin is up to date (Version $localVersion)." -ForegroundColor Green
        Write-Log "OGCWin is up to date (Version $localVersion)."
    }
} catch {
    Write-Host "Could not check for updates (Offline?). Skipping." -ForegroundColor DarkGray
    Write-Log "Update check failed (Likely offline): $_" "WARNING"
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
    Write-Host "1. Menu Mode   - Access the main utility menu" -ForegroundColor Yellow
    
    if ($winVer -match "Windows 11") {
        Write-Host "2. Wizard Mode - Step-by-step new PC setup wizard" -ForegroundColor Yellow
    } else {
        Write-Host "2. Wizard Mode - [WARNING: Not meant for Windows 10]" -ForegroundColor Red
    }
    
    Write-Host "3. View System Information" -ForegroundColor Yellow
    Write-Host "Q. Quit" -ForegroundColor DarkGray
    Write-Host ""
    
    $choice = Read-Host "Enter Selection"
    
    switch ($choice) {
        "1" { 
            Write-Host "Starting Utility..." -ForegroundColor Magenta
            Write-Log "User selected Utility Mode."
            Start-Sleep -Seconds 1
            try {
                & $ogcWin
            } catch {
                Write-Log "Failed to launch OGCWin: $_" "ERROR"
                Write-Host "Error launching OGCWin. Check logs." -ForegroundColor Red
            }
        }
        "2" {
            Write-Log "User selected Wizard Mode."
            if ($winVer -notmatch "Windows 11") {
                Write-Host "WARNING: This wizard is optimized for Windows 11." -ForegroundColor Red
                Write-Host "Running it on $winVer may cause issues or break features." -ForegroundColor Red
                $confirm = Read-Host "Are you sure you want to proceed? (y/n)"
                if ($confirm -ne "y") { 
                    Write-Log "User cancelled Wizard Mode due to OS warning."
                    continue 
                }
                Write-Log "User proceeded with Wizard Mode despite OS warning." "WARNING"
            }
            Write-Host "Starting Wizard..." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            try {
                & $ogcWiz11
            } catch {
                Write-Log "Failed to launch OGCWiz11: $_" "ERROR"
                Write-Host "Error launching Wizard. Check logs." -ForegroundColor Red
            }
        }
        "3" {
            Start-Sleep -Seconds 1
            Write-Log "User selected System Information."
            try {
                & $sysInfo
            } catch {
                Write-Log "Failed to launch SysInfo: $_" "ERROR"
            }
            Write-Host ""
        }
        "q" { 
            Write-Log "User selected Quit."
            Exit 
        }
        default { 
            Write-Host "Invalid selection." -ForegroundColor Red
            Start-Sleep -Seconds 1 
        }
    }
    Clear-Host
}