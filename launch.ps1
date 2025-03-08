# OGC Windows Utility Launcher by Honest Goat
# Version: 0.1
# This script will check for software dependencies, update powershell,
# create the folder structure for the Utility and then launch the Utility.

# Detect Banner Version
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
if ($winVer -match "Windows 10 Home" -or $winVer -match "Windows 10 Pro") {
    # Windows 10 Banner
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
} elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
    # Windows 11 Banner
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
Write-Host "Setting up OGCWin..." -ForegroundColor Cyan
Start-sleep -Seconds 1

# Define OGCWin folder paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$downloadsFolder = "$parentFolder\downloads"
$redistributableFolder = "$parentFolder\redist"
$configurationsFolder = "$parentFolder\configs"
$imagesFolder = "$parentFolder\images"
$tempFolder = "$parentFolder\temp"
$driversFolder = "$parentFolder\drivers"
$pythonFolder = "$parentFolder\python"
$scriptsFolder = "$parentFolder\scripts"
$bin = "$parentFolder\bin"

# Ensure all necessary folders exist
$folders = @($parentFolder, $downloadsFolder, $redistributableFolder, $configurationsFolder, $imagesFolder, $tempFolder, $driversFolder, $pythonFolder, $scriptsFolder, $bin)
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

# Download urls.cfg (Always overwrite to ensure updates)
$urlsConfigPath = "$configurationsFolder\urls.cfg"
$urlsConfigUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/urls.cfg"

if (Test-Path $urlsConfigPath) {
    Write-Host "Updating OGCWin..." -ForegroundColor Yellow
} else {
    Write-Host "Installing OGCWin..." -ForegroundColor Yellow
}

Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait

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

# Define file names and locations
$ogclaunch = "$parentFolder\launch.ps1"
$ogcwinbat = "$parentFolder\OGCWin.bat"
$ogcwin10 = "$scriptsFolder\OGCWin10.ps1"
$ogcwin11 = "$scriptsFolder\OGCWin11.ps1"
$ogcwiz10 = "$scriptsFolder\OGCWiz10.ps1"
$ogcwiz11 = "$scriptsFolder\OGCWiz11.ps1"
$sysinfo = "$scriptsFolder\sysinfo.ps1"

# Function to always update files from GitHub
function Get-Scripts {
    $scripts = @{
        "OGClaunch" = $ogclaunch
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

Write-Host "OGCWin setup complete. In future you can launch OGCWin from the desktop shortcut." -ForegroundColor Green

# Check for dependencies for OGCWin
Start-Sleep -Seconds 1
Write-Host "Checking for dependencies..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Function to check if WinGet is installed
function Test-WinGet {
    try {
        winget --version
        return $true
    } catch {
        return $false
    }
}

# Function to check if an Appx package is installed
function Test-AppxInstalled {
    param ($PackageName)
    return $null -ne (Get-AppxPackage | Where-Object { $_.Name -eq $PackageName })
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
        if (-not (Test-Path $vclibsPath)) {
            Write-Host "Downloading Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Cyan
        Add-AppxPackage -Path $vclibsPath
    } else {
        Write-Host "Microsoft.VCLibs.140.00.UWPDesktop is already installed." -ForegroundColor Green
    }

    # Install Microsoft.UI.Xaml
    if (-not (Test-AppxInstalled "Microsoft.UI.Xaml.2.8")) {
        if (-not (Test-Path $xamlPath)) {
            Write-Host "Downloading Microsoft.UI.Xaml.2.8..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$xamlPath`" `"$xamlUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing Microsoft.UI.Xaml.2.8..." -ForegroundColor Cyan
        Add-AppxPackage -Path $xamlPath
    } else {
        Write-Host "Microsoft.UI.Xaml.2.8 is already installed." -ForegroundColor Green
    }

    # Install WinGet
    Write-Host "Fetching latest WinGet release information..." -ForegroundColor Yellow
    $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl
    $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
    $wingetUrl = $wingetAsset.browser_download_url
    $wingetPath = "$downloadsFolder\$($wingetAsset.name)"

    if (-not (Test-WinGet)) {
        if (-not (Test-Path $wingetPath)) {
            Write-Host "Downloading WinGet..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing WinGet..." -ForegroundColor Cyan
        Add-AppxPackage -Path $wingetPath
    } else {
        Write-Host "WinGet is already installed." -ForegroundColor Green
    }

    # Clean up downloaded files
    if (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop" -and `
        Test-AppxInstalled "Microsoft.UI.Xaml.2.8" -and `
        Test-WinGet) {
        Write-Host "Cleaning up installation files..." -ForegroundColor Cyan
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

# Clear terminal and display OGC Banner again.
Clear-Host
Clear-Host
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
if ($winVer -match "Windows 10 Home" -or $winVer -match "Windows 10 Pro") {
    # Windows 10 Banner
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
} elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
    # Windows 11 Banner
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
    } elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
        return "Windows11"
    } else {
        Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
}

# Function to prompt user for mode selection
function Get-UserSelection {
    $windowsVersion = Get-WindowsVersion

    while ($true) {
        Write-Host "What mode would you like to launch the OGC Windows Utility in:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. [NOT AVAILABLE YET] Utility Mode - Access the main utility menu" -ForegroundColor Red
#        Write-Host "1. Utility Mode - Access the main utility menu" -ForegroundColor Yellow
        Write-Host "2. Wizard Mode - Step-by-step guided setup for new installations of Windows" -ForegroundColor Yellow
        Write-Host "3. Display useful system information" -ForegroundColor Yellow
        $modeChoice = Read-Host "Please make a selection"

        if ($modeChoice -eq "1") {
            Write-Host "Utility Mode not yet available. Please select another option." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
            continue
#            Write-Host "Starting OGC Windows Utility..." -ForegroundColor Magenta
#            Start-Sleep -Seconds 1
#            $scriptPath = if ($windowsVersion -eq "Windows10") { "$scriptsFolder\OGCWin10.ps1" } else { "$scriptsFolder\OGCWin11.ps1" }
#            Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -WindowStyle Normal -Command `" 
#                `$host.UI.RawUI.BackgroundColor = 'Black'; 
#                `$host.UI.RawUI.ForegroundColor = 'White'; 
#                Clear-Host; 
#                & '$scriptPath'`"" -Verb RunAs
#            exit 1
        } elseif ($modeChoice -eq "2") {
            Write-Host "Starting OGC New Installation Setup Wizard..." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            $scriptPath = if ($windowsVersion -eq "Windows10") { "$scriptsFolder\OGCWiz10.ps1" } else { "$scriptsFolder\OGCWiz11.ps1" }
            Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -WindowStyle Normal -Command `" 
                `$host.UI.RawUI.BackgroundColor = 'Black'; 
                `$host.UI.RawUI.ForegroundColor = 'White'; 
                Clear-Host; 
                & '$scriptPath'`"" -Verb RunAs
            exit
        } elseif ($modeChoice -eq "3") {
            Write-Host "Gathering system information..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            & "$scriptsFolder\sysinfo.ps1"
            Write-Host ""
            continue
        } else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Clear-Host
            continue
        }
    }
}

# Call the function to start selection process
Get-UserSelection

Write-Host "You may now close this window." -ForegroundColor Green
