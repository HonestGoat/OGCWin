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

# Function to check if an Appx package is installed
function Test-AppxInstalled {
    param ($PackageName)
    return $null -ne (Get-AppxPackage | Where-Object { $_.Name -eq $PackageName })
}

# Function to install dependencies and WinGet
function Install-WinGet {
    # Define URLs for dependencies and WinGet
    $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $xamlUrl = "https://aka.ms/Microsoft.UI.Xaml.2.8"
    $wingetApiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"

    # Set download paths
    $vclibsPath = "$downloadsFolder\Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $xamlPath = "$downloadsFolder\Microsoft.UI.Xaml.2.8_8.2501.31001.0_x64.appx"

    # Check and install Microsoft.VCLibs
    if (-not (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop")) {
        if (-not (Test-Path $vclibsPath)) {
            Write-Host "Downloading Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Green
        Add-AppxPackage -Path $vclibsPath
    } else {
        Write-Host "Microsoft.VCLibs.140.00.UWPDesktop is already installed." -ForegroundColor Cyan
    }

    # Check and install Microsoft.UI.Xaml.2.8
    if (-not (Test-AppxInstalled "Microsoft.UI.Xaml.2.8")) {
        if (-not (Test-Path $xamlPath)) {
            Write-Host "Downloading Microsoft.UI.Xaml.2.8..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$xamlPath`" `"$xamlUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing Microsoft.UI.Xaml.2.8..." -ForegroundColor Green
        Add-AppxPackage -Path $xamlPath
    } else {
        Write-Host "Microsoft.UI.Xaml.2.8 is already installed." -ForegroundColor Cyan
    }

    # Get the latest WinGet installer URL from GitHub
    Write-Host "Fetching latest WinGet release information..." -ForegroundColor Yellow
    $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl
    $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
    $wingetUrl = $wingetAsset.browser_download_url
    $wingetPath = "$downloadsFolder\$($wingetAsset.name)"

    # Check and install WinGet
    if (-not (Test-WinGet)) {
        if (-not (Test-Path $wingetPath)) {
            Write-Host "Downloading WinGet..." -ForegroundColor Yellow
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait
        }
        Write-Host "Installing WinGet..." -ForegroundColor Green
        Add-AppxPackage -Path $wingetPath
    } else {
        Write-Host "WinGet is already installed." -ForegroundColor Cyan
    }

    # Final verification of installations
    if (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop" -and `
        Test-AppxInstalled "Microsoft.UI.Xaml.2.8" -and `
        Test-WinGet) {

        # Clean up downloaded files but keep folder structure
        Write-Host "Cleaning up downloaded installation files..." -ForegroundColor Cyan
        Remove-Item -Path "$downloadsFolder\*" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Some dependencies failed to install. Please check manually." -ForegroundColor Red
    }
}

# Winget check completion
if (-not (Test-WinGet)) {
    Write-Host "WinGet is not installed. Attempting to install..." -ForegroundColor Yellow
    Install-WinGet
    Start-Sleep -Seconds 5 # Wait for installation to complete

    # Re-check installation status
    if (-not (Test-WinGet)) {
        Write-Host "WinGet installation failed. Exiting Utility." -ForegroundColor Red
        Write-Host "Please follow the manual installation instructions" -ForegroundColor Red
        Write-Host "Pinned in the Tech Support channel in the OGC Discord." -ForegroundColor Red
        Start-Sleep -Seconds 5
        pause
#        exit
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

# Start OGC Windows Utility or New Windows Setup Wizard a new PowerShell window with a black background
# Function to prompt user for mode selection
function Get-UserSelection {
    while ($true) {
        Write-Host "What mode would you like to launch the OGC Windows Utility in:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. [NOT AVAILABLE] Utility Mode - Access the main utility menu" -ForegroundColor Red
        Write-Host "2. Wizard Mode - Step-by-step guided setup for new installations of Windows" -ForegroundColor Yellow
        Write-Host "3. Display useful system information" -ForegroundColor Yellow
        $modeChoice = Read-Host "Please make a selection"

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
        } elseif ($modeChoice -eq "3") {
            # SYSTEM INFORMATION SCRIPT
            Write-Host "Gathering system information..." -ForegroundColor Cyan
            
            # Define output path
            $desktopPath = [System.Environment]::GetFolderPath("Desktop")
            $outputFile = "$desktopPath\SystemInfo.txt"

            # Function to get Windows version
            function Get-WindowsVersion {
                $version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
                $edition = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
                $os = (Get-CimInstance Win32_OperatingSystem).Caption
                return "$os $version ($edition)"
            }

            # Function to get Windows installation date
            function Get-WindowsInstallDate {
                $os = Get-CimInstance Win32_OperatingSystem
                return $os.InstallDate
            }

            # Function to retrieve Windows product key
            function Get-WindowsProductKey {
                try {
                    $key = (Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService").OA3xOriginalProductKey
                    if (-not $key) { return "Product key not found (OEM key may be stored in BIOS)" }
                    return $key
                } catch {
                    return "Could not retrieve product key"
                }
            }

            # Function to get CPU information
            function Get-CPUInfo {
                $cpu = Get-CimInstance Win32_Processor
                return "$($cpu.Name) | $($cpu.NumberOfCores) Cores, $($cpu.L3CacheSize) KB L3 Cache"
            }

            # Function to get motherboard information
            function Get-MotherboardInfo {
                $board = Get-CimInstance Win32_BaseBoard
                return "$($board.Manufacturer) $($board.Product)"
            }

            # Function to get RAM information
            function Get-RAMInfo {
                $ram = Get-CimInstance Win32_PhysicalMemory
                $totalRAM = ($ram | Measure-Object -Property Capacity -Sum).Sum / 1GB
                return "Installed RAM: ${totalRAM}GB"
            }

            # Function to get storage information (Model & Capacity only, excluding "Virtual Disk")
            function Get-StorageInfo {
                $drives = Get-PhysicalDisk | Where-Object { $_.Model -ne "Virtual Disk" }
                $output = "Drives:"
                foreach ($drive in $drives) {
                    $output += "`n  $($drive.Model) | Size: $([math]::Round($drive.Size / 1GB, 2)) GB"
                }
                return $output
            }

            # Function to get GPU information (List each GPU separately)
            function Get-GPUInfo {
                $gpus = Get-CimInstance Win32_VideoController
                $output = "GPUs:"
                foreach ($gpu in $gpus) {
                    $output += "`n  $($gpu.Name)"
                }
                return $output
            }

            # Function to get display information (Brand & Model only)
            function Get-DisplayInfo {
                $monitors = Get-CimInstance WmiMonitorID -Namespace root\wmi
                $output = "Connected Displays:"
                foreach ($monitor in $monitors) {
                    $brand = [System.Text.Encoding]::ASCII.GetString($monitor.ManufacturerName) -replace '\0'
                    $model = [System.Text.Encoding]::ASCII.GetString($monitor.UserFriendlyName) -replace '\0'
                    if ($brand -and $model) {
                        $output += "`n  $brand $model"
                    }
                }
                return $output
            }

            # Collect system information
            $systemInfo = @"
===================================
    SYSTEM INFORMATION REPORT
===================================
Windows Version   : $(Get-WindowsVersion)
Windows Installed : $(Get-WindowsInstallDate)
Product Key       : $(Get-WindowsProductKey)

CPU              : $(Get-CPUInfo)
Motherboard      : $(Get-MotherboardInfo)
RAM              : $(Get-RAMInfo)
Storage          : $(Get-StorageInfo)

$(Get-GPUInfo)
$(Get-DisplayInfo)

===================================
"@

            # Display system information
            Write-Host $systemInfo -ForegroundColor Cyan

            # Automatically save to file on Desktop
            $systemInfo | Out-File -Encoding utf8 $outputFile
            Write-Host "`nSystem information saved to: $outputFile" -ForegroundColor Green
            Start-Sleep -Seconds 3

        } else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

# Get valid script URL from user (or run system info)
$scriptUrl = Get-UserSelection

# Start the selected mode in a new PowerShell window with a black background (if not system info)
if ($scriptUrl) {
    $psCommand = @"
    `$host.UI.RawUI.BackgroundColor = 'Black'
    `$host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host
    irm $scriptUrl | iex
"@
    Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -NoProfile -Command `"$psCommand`"" -Verb RunAs
    exit
}

Write-Host "You may now close this window." -ForegroundColor Green
