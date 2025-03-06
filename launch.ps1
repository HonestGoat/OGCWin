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

Start-Sleep -Seconds 1

Write-Host "Checking for dependencies..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Define OGCWin folder paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$downloadsFolder = "$parentFolder\downloads"

# Ensure the folder structure exists (silently)
if (-not (Test-Path $parentFolder)) { 
    New-Item -Path $parentFolder -ItemType Directory -Force | Out-Null 
}
if (-not (Test-Path $downloadsFolder)) { 
    New-Item -Path $downloadsFolder -ItemType Directory -Force | Out-Null 
}

# Function to check if WinGet is installed
function Test-WinGet {
    try {
        winget --version
        return $true
    } catch {
        return $false
    }
}

# Function to install WinGet
function Install-WinGet {
    # Define URLs for dependencies and WinGet
    $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $wingetApiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"

    # Set download paths
    $vclibsPath = "$downloadsFolder\Microsoft.VCLibs.x64.14.00.Desktop.appx"

    # Download and install Microsoft.VCLibs.140.00.UWPDesktop
    Write-Host "Downloading Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait
    Add-AppxPackage -Path $vclibsPath

    # Get the download URL of the latest WinGet installer from GitHub
    Write-Host "Fetching latest WinGet release information..." -ForegroundColor Yellow
    $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl
    $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
    $wingetUrl = $wingetAsset.browser_download_url

    # Set WinGet download path
    $wingetPath = "$downloadsFolder\$($wingetAsset.name)"

    # Download and install WinGet
    Write-Host "Downloading WinGet..." -ForegroundColor Yellow
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait
    Add-AppxPackage -Path $wingetPath

    # Clean up downloaded files but keep folder structure

}

# Winget check completion
if (-not (Test-WinGet)) {
    Write-Host "WinGet is not installed. Attempting to install..." -ForegroundColor Yellow
    Install-WinGet
    Start-Sleep -Seconds 5 # Wait for installation to complete
    if (-not (Test-WinGet)) {
        Write-Host "WinGet installation failed. Exiting Utility." -ForegroundColor Red
        Write-Host "Please follow the manual installation instructions" -ForegroundColor Red
        Write-Host "pinned in the Tech Support channel in the OGC Discord." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit 1
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

Write-Host "Starting OGC Windows Utility..." -ForegroundColor Magenta
Start-Sleep -Seconds 1

# Start OGC Windows Utility or New Windows Setup Wizard a new PowerShell window with a black background
# Prompt user for mode selection
Write-Host "What mode would you like to launch the OGC Windows Utility in:" -ForegroundColor Cyan
Write-Host "1. [NOT AVAILABLE] Utility Mode - Access the main utility menu" -ForegroundColor Yellow
Write-Host "2. Wizard Mode - Step-by-step guided setup for new installations of Windows" -ForegroundColor Yellow
$modeChoice = Read-Host "Enter 1 for Utility Mode or 2 for Wizard Mode"

# Determine the script URL based on user choice
if ($modeChoice -eq "1") {
    Write-Host "Utility Mode not yet available. The wizard will start instead."
    Start-Sleep -Seconds 3
    $modeChoice -eq 2
    #    $scriptUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/OGCWin.ps1"
} elseif ($modeChoice -eq "2") {
    $scriptUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/OGCWiz.ps1"
} else {
    Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    exit
}

# Function to prompt user for mode selection
function Get-UserSelection {
    while ($true) {
        Write-Host "What mode would you like to launch the OGC Windows Utility in:" -ForegroundColor Cyan
        Write-Host "1. [NOT AVAILABLE]" -ForegroundColor Red  "Utility Mode - Access the main utility menu" -ForegroundColor Yellow
        Write-Host "2. Wizard Mode - Step-by-step guided setup for new installations of Windows" -ForegroundColor Yellow
        $modeChoice = Read-Host "Enter 1 for Utility Mode or 2 for Wizard Mode"
        if ($modeChoice -eq "1") {
            Write-Host "Utility Mode not yet available. The wizard will start instead."
            Start-Sleep -Seconds 3
            $modeChoice -eq 2
#            Write-Host "Starting OGC Windows Utility..." -ForegroundColor Magenta
#            Start-Sleep -Seconds 1
#            return "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/OGCWin.ps1"
        } elseif ($modeChoice -eq "2") {
            Write-Host "Starting OGC New Windows Setup Wizard.." -ForegroundColor Magenta
            Start-Sleep -Seconds 1
            return "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/OGCWiz.ps1"
        } else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

# Get valid script URL from user
$scriptUrl = Get-UserSelection

# Start the selected mode in a new PowerShell window with a black background
$psCommand = @"
`$host.UI.RawUI.BackgroundColor = 'Black'
`$host.UI.RawUI.ForegroundColor = 'White'
Clear-Host
irm $scriptUrl | iex
"@

Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -Command `"$psCommand`"" -Verb RunAs
exit
Write-Host "You may now close this window." -ForegroundColor Green
