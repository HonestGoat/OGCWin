# OGC Windows Utility Updater by Honest Goat
# Version: 0.1
# This script will check for software dependencies, update powershell,
# update the folder structure and files for the Utility and then launch the mode selector.

# Start with administrator privileges, bypass execution policy and force black background
function Test-Admin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Start-Process pwsh.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
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

# Detect Banner Version
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
    if ($winVer -match "Windows 10 Home" -or $winVer -match "Windows 10 Pro") {
        return "Windows10"
        Write-Host "Running in Windows 10 mode." -ForegroundColor Cyan
    } elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
        return "Windows11"
        Write-Host "Running in Windows 11 mode." -ForegroundColor Cyan
    } else {
        Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
}

# Install OGCWin to ProgramData folder on C Drive.
# Define OGCWin folder paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$downloadsFolder = "$parentFolder\downloads"
#$redistributableFolder = "$parentFolder\redist"
$configsFolder = "$parentFolder\configs"
#$imagesFolder = "$parentFolder\images"
$tempFolder = "$parentFolder\temp"
#$driversFolder = "$parentFolder\drivers"
#$pythonFolder = "$parentFolder\python"
$scriptsFolder = "$parentFolder\scripts"
$backupFolder = "$parentFolder\backups"
$registryBackup = "$backupFolder\registry"
#$bin = "$parentFolder\bin"

# Ensure all necessary folders exist
$folders = @($parentFolder, $backupFolder, $registryBackup, $downloadsFolder, $configsFolder, $tempFolder, $scriptsFolder) # add ass needed $redistributableFolder, $imagesFolder, $driversFolder, $pythonFolder, $bin
foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) { 
        New-Item -Path $folder -ItemType Directory -Force | Out-Null 
    }
}

# Function to check if an exclusion exists in Windows Defender
function Test-ExclusionSet {
    param ([string]$path)
    $existingExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    return $existingExclusions -contains $path
}

# Add Windows Defender exclusion for OGCWin parent folder only
if (-Not (Test-ExclusionSet $parentFolder)) {
    Add-MpPreference -ExclusionPath "$parentFolder" -ErrorAction SilentlyContinue
}

# Define file names and locations
$ogclaunch = "$scriptsFolder\launch.ps1"
$ogcwinbat = "$parentFolder\OGCWin.bat"
$ogcmode = "$scriptsFolder\OGCMode.ps1"
$ogcwin10 = "$scriptsFolder\OGCWin10.ps1"
$ogcwin11 = "$scriptsFolder\OGCWin11.ps1"
$ogcwiz10 = "$scriptsFolder\OGCWiz10.ps1"
$ogcwiz11 = "$scriptsFolder\OGCWiz11.ps1"
$sysinfo = "$scriptsFolder\sysinfo.ps1"

# Download config files (Always overwrite to ensure updates)
$urlsConfigPath = "$configsFolder\urls.cfg"
$urlsConfigUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/urls.cfg"
$versionConfigPath = "$configsFolder\version.cfg"
$versionConfigUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/version.cfg"
if (Test-Path $urlsConfigPath) {
    Write-Host "Updating OGCWin..." -ForegroundColor Yellow
    Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait
    Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$versionConfigPath`" `"$versionConfigUrl`"" -NoNewWindow -Wait
} else {
    Write-Host "Downloading OGCWin..." -ForegroundColor Yellow
    Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait
    Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$versionConfigPath`" `"$versionConfigUrl`"" -NoNewWindow -Wait
    Start-Sleep -Seconds 1
    Write-Host "Installing OGCWin..." -ForegroundColor Yellow
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

# Function to always update files from GitHub
function Get-Scripts {
    $scripts = @{
        "OGClaunch" = $ogclaunch
        "OGCMode" = $ogcmode
        "OGCWin10" = $ogcwin10
        "OGCWin11" = $ogcwin11
        "OGCWiz10" = $ogcwiz10
        "OGCWiz11" = $ogcwiz11
        "OGCWinBat" = $ogcwinbat
        "SysInfo" = $sysinfo
    }

    foreach ($script in $scripts.Keys) {
        $scriptPath = $scripts[$script]
        $scriptUrl = Get-Url $script

        # Always redownload and overwrite the scripts silently
        Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$scriptPath`" `"$scriptUrl`"" -WindowStyle Hidden -Wait
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

# Call function to update scripts
Get-Scripts


## SHORTCUT CREATION SECTION
# Function to create a desktop shortcut for OGCWin.bat
function New-Shortcut {
    param (
        [string]$TargetPath,
        [string]$ShortcutPath,
        [string]$Description,
        [string]$IconPath
    )

    if (-Not (Test-Path $ShortcutPath)) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $TargetPath
        $Shortcut.Description = $Description
        $Shortcut.IconLocation = $IconPath
        $Shortcut.Save()
    }
}

# Define desktop shortcut path
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "OGC Windows Utility.lnk")

# Use Windows Start Menu-style icon
$windowsIcon = "C:\Windows\System32\imageres.dll,97"  # Windows-style system icon

# Create the shortcut with the Windows icon
New-Shortcut -TargetPath $ogcwinbat -ShortcutPath $desktopPath -Description "Launch OGC Windows Utility" -IconPath $windowsIcon

Write-Host "OGCWin setup complete. In the future you can launch OGCWin from the desktop shortcut." -ForegroundColor Green

# Check for dependencies for OGCWin
Start-Sleep -Seconds 1
Write-Host "Checking for OGCWin dependencies..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Function to check if WinGet is installed properly
function Test-WinGet {
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        Write-Host "WinGet found: $($wingetPath.Source)" -ForegroundColor Green
        return $true
    } else {
        Write-Host "WinGet is NOT installed or not in PATH!" -ForegroundColor Red
        return $false
    }
}

# Function to check if an Appx package is installed
function Test-AppxInstalled {
    param ($PackageName)
    $installed = Get-AppxPackage | Where-Object { $_.Name -eq $PackageName }
    if ($installed) {
        Write-Host "Dependency found: $PackageName" -ForegroundColor Green
        return $true
    } else {
        Write-Host "Dependency MISSING: $PackageName" -ForegroundColor Red
        return $false
    }
}

# Function to install dependencies and WinGet
function Install-WinGet {
    # Load URLs from config
    $vclibsUrl = Get-Url "VCLibs"
    $xamlUrl = Get-Url "UIXaml"
    $wingetApiUrl = Get-Url "WinGetAPI"

    # Set download paths
    $vclibsPath = "$downloadsFolder\Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $xamlPath = "$downloadsFolder\Microsoft.UI.Xaml.2.8_8.2501.31001.0_x64.appx"

    # Install Microsoft.VCLibs
    if (-not (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop")) {
        Write-Host "Downloading and Installing Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
        Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait
        Add-AppxPackage -Path $vclibsPath
    }

    # Install Microsoft.UI.Xaml
    if (-not (Test-AppxInstalled "Microsoft.UI.Xaml.2.8")) {
        Write-Host "Downloading and Installing Microsoft.UI.Xaml.2.8..." -ForegroundColor Yellow
        Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$xamlPath`" `"$xamlUrl`"" -NoNewWindow -Wait
        Add-AppxPackage -Path $xamlPath
    }

    # Install WinGet
    if (-not (Test-WinGet)) {
        Write-Host "Downloading and Installing WinGet..." -ForegroundColor Yellow
        $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl
        $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
        $wingetUrl = $wingetAsset.browser_download_url
        $wingetPath = "$downloadsFolder\$($wingetAsset.name)"

        Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait
        Add-AppxPackage -Path $wingetPath
    }

    # Confirm installations
    if (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop" -and `
        Test-AppxInstalled "Microsoft.UI.Xaml.2.8" -and `
        Test-WinGet) {
        Write-Host "All dependencies installed successfully." -ForegroundColor Green
        Remove-Item -Path "$downloadsFolder\*" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Some dependencies failed to install." -ForegroundColor Red
    }
}

# Winget installation check
if (-not (Test-WinGet)) {
    Write-Host "WinGet is not installed. Attempting to install..." -ForegroundColor Yellow
    Install-WinGet
    Start-Sleep -Seconds 5

    if (-not (Test-WinGet)) {
        Write-Host "WinGet installation failed. Exiting Utility." -ForegroundColor Red
        Write-Host "Please follow the manual installation instructions" -ForegroundColor Red
        Write-Host "Pinned in the Tech Support channel in the OGC Discord." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }
} else {
    Write-Host "All required dependencies are already installed." -ForegroundColor Green
}

# Check PowerShell version
Start-Sleep -Seconds 1
Write-Host "Checking Powershell version..." -ForegroundColor Magenta

# Install latest PowerShell using WinGet
winget install Microsoft.Powershell --source winget --silent --accept-package-agreements --accept-source-agreements
Start-Sleep -Seconds 1

Write-Host "All dependencies installed." -ForegroundColor Green
Start-Sleep -Seconds 1
Write-Host ""

# Launch OGCWin mode selector in PowerShell 7
Start-Process pwsh.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -Command `" 
    `$host.UI.RawUI.BackgroundColor = 'Black'; 
    `$host.UI.RawUI.ForegroundColor = 'White'; 
    Clear-Host; 
    & '$scriptsFolder\OGCMode.ps1'`"" -Verb RunAs -Wait

# Close this window
Start-Sleep -Seconds 2
$host.UI.RawUI.FlushInputBuffer()
Stop-Process -Id $PID -Force

