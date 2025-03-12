# OGC Windows Utility Mode Selector by Honest Goat
# Version: 0.1
# This script prompt which mode to launch OGCWin in.

# Start with administrator privileges, bypass execution policy and force black background
function Test-Admin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
}
Test-Admin

Set-ExecutionPolicy Bypass -Scope Process -Force
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

function Show-Progress {
    param (
        [string]$Message
    )
    for ($i = 1; $i -le 100; $i += 10) {
        Write-Progress -Activity $Message -Status "$i% Complete" -PercentComplete $i
        Start-Sleep -Milliseconds 300
    }
    Write-Host "`n[$Message Complete]" -ForegroundColor Green
}

# Function to load URLs from urls.cfg
function Get-Url {
    param ($key)
    $configData = Get-Content -Path $urlsConfigPath | Where-Object { $_ -match "=" }
    $urlMap = @{}

    foreach ($line in $configData) {
        $parts = $line -split "=", 2
        if ($parts.Count -eq 2) {
            $urlMap[$parts[0].Trim()] = $parts[1].Trim()
        }
    }

    if ($urlMap.ContainsKey($key)) {
        return $urlMap[$key]
    } else {
        Write-Host "Warning: URL key '$key' not found in urls.cfg" -ForegroundColor Red
        return $null
    }
}

# Function to get script paths dynamically
function Get-ScriptPath {
    param ($scriptKey)
    $scriptPaths = @{
        "OGClaunch" = "$parentFolder\launch.ps1"
        "OGCWinBat" = "$parentFolder\OGCWin.bat"
        "OGCWin10" = "$scriptsFolder\OGCWin10.ps1"
        "OGCWin11" = "$scriptsFolder\OGCWin11.ps1"
        "OGCWiz10" = "$scriptsFolder\OGCWiz10.ps1"
        "OGCWiz11" = "$scriptsFolder\OGCWiz11.ps1"
        "SysInfo" = "$scriptsFolder\sysinfo.ps1"
    }

    if ($scriptPaths.ContainsKey($scriptKey)) {
        return $scriptPaths[$scriptKey]
    } else {
        Write-Host "Warning: Script key '$scriptKey' not found in script paths" -ForegroundColor Red
        return $null
    }
}

# Clear terminal and display OGC Banner again.
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
if ($winVer -match "Windows 10") {
    # Windows 10 Banner
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "    OGC Windows 10 Utility Launcher    " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
} elseif ($winVer -match "Windows 11") {
    # Windows 11 Banner
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "    OGC Windows 11 Utility Launcher    " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
} else {
    Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

# Function to determine Windows version
function Get-WindowsVersion {
    $winVer = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($winVer -match "Windows 10") {
        return "Windows 10"
    } elseif ($winVer -match "Windows 11") {
        return "Windows 11"
    } else {
        Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
}

# Check OGCWin Version and update if old

# Define folder paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configsFolder = "$parentFolder\configs"
$scriptsFolder = "$parentFolder\scripts"
$localVersionFile = "$configsFolder\version.cfg"
$remoteVersionURL = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/version.cfg"
$updateScript = "$scriptsFolder\launch.ps1"  # Now launching launch.ps1 directly

# Function to extract version number from version.cfg
function Get-VersionNumber {
    param ($fileContent)
    if ($fileContent -match "Version=([\d\.]+)") {
        return [version]$matches[1]
    } else {
        return $null
    }
}

# Check if local version file exists
if (Test-Path $localVersionFile) {
    $localVersionContent = Get-Content $localVersionFile -Raw
    $localVersion = Get-VersionNumber $localVersionContent
} else {
    Write-Host "Local version.cfg file not found. Assuming outdated version." -ForegroundColor Yellow
    $localVersion = [version]"0.0"
}

# Download remote version file
try {
    $remoteVersionContent = Invoke-RestMethod -Uri $remoteVersionURL -UseBasicParsing
    $remoteVersion = Get-VersionNumber $remoteVersionContent
} catch {
    Write-Host "Failed to retrieve remote version information. Check internet connection." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

# Compare versions
if ($localVersion -lt $remoteVersion) {
    Write-Host "OGCWin is out of date. Updating to version $remoteVersion..." -ForegroundColor Cyan
    
    # Run launch.ps1 in the same window with admin rights, black background, and execution policy bypass
    powershell.exe -NoExit -ExecutionPolicy Bypass -NoProfile -Command "
        `$host.UI.RawUI.BackgroundColor = 'Black'; 
        `$host.UI.RawUI.ForegroundColor = 'White'; 
        Clear-Host;
        & '$updateScript'
    "
    
    Start-Sleep -Seconds 3
    exit
} else {
    Write-Host "OGCWin is up to date (Version $localVersion)." -ForegroundColor Green
}

# Function to prompt user for mode selection
function Get-UserSelection {
    $windowsVersion = Get-WindowsVersion

    while ($true) {
        Write-Host "What mode would you like to launch the OGC Windows Utility in:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. [NOT AVAILABLE YET] Utility Mode - Access the main utility menu" -ForegroundColor Red
#        Write-Host "1. Utility Mode - Access the main utility menu" -ForegroundColor Yellow
        Write-Host "2. Wizard Mode - Step-by-step guided setup for fresh installations of Windows" -ForegroundColor Yellow
        Write-Host "3. Display useful system information" -ForegroundColor Yellow
        $modeChoice = Read-Host "Please make a selection"

        if ($modeChoice -eq "1") {
            Write-Host "Utility Mode not yet available. Please select another option." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
            continue
#            Write-Host "Starting OGC Windows Utility..." -ForegroundColor Magenta
#            Start-Sleep -Seconds 1
#            $scriptPath = if ($windowsVersion -eq "Windows 10") { "$scriptsFolder\OGCWin10.ps1" } else { "$scriptsFolder\OGCWin11.ps1" }
#            Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -WindowStyle Normal -Command `" 
#                `$host.UI.RawUI.BackgroundColor = 'Black'; 
#                `$host.UI.RawUI.ForegroundColor = 'White'; 
#                Clear-Host; 
#                & '$scriptPath'`"" -Verb RunAs
#            Start-Sleep -Seconds 1 
#            exit
        } elseif ($modeChoice -eq "2") {
            Write-Host "Starting OGC Fresh Installation Setup Wizard..." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            $scriptPath = if ($windowsVersion -eq "Windows 10") { "$scriptsFolder\OGCWiz10.ps1" } else { "$scriptsFolder\OGCWiz11.ps1" }
            Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -WindowStyle Normal -Command `" 
                `$host.UI.RawUI.BackgroundColor = 'Black'; 
                `$host.UI.RawUI.ForegroundColor = 'White'; 
                Clear-Host; 
                & '$scriptPath'`"" -Verb RunAs
            Start-Sleep -Seconds 1
            exit
        } elseif ($modeChoice -eq "3") {
            Start-Sleep -Seconds 1
            powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$scriptsFolder\sysinfo.ps1"
            Write-Host ""
            continue
        } else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            $Host.UI.RawUI.BackgroundColor = "Black"
            $Host.UI.RawUI.ForegroundColor = "White"
            Clear-Host
            continue
        }
    }
}

# Call the function to start selection process
Get-UserSelection

Write-Host "You may now close this window." -ForegroundColor Green
