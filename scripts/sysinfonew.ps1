# OGC Windows System Information Tool by Honest Goat
# Version: 0.6 (Added Cleanup & Renamed $bin to $binFolder)

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
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"

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

# Define OGCWin folder paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configurationsFolder = "$parentFolder\configs"
$binFolder = "$parentFolder\bin"
$tempFolder = "$parentFolder\temp"

# Ensure all necessary folders exist
$folders = @($parentFolder, $configurationsFolder, $binFolder, $tempFolder)
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

Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait

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

# Ensure ProduKey is downloaded and extracted
$produKeyZipUrl = Get-Url "ProduKey"
$produKeyZipPath = "$downloadsFolder\ProduKey.zip"
$produKeyExePath = "$binFolder\ProduKey.exe"

if (-not (Test-Path $produKeyExePath)) {
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$produKeyZipPath`" `"$produKeyZipUrl`"" -NoNewWindow -Wait
    Expand-Archive -Path $produKeyZipPath -DestinationPath $binFolder -Force
}

# Gather System Information
Write-Host "Gathering system information..." -ForegroundColor Cyan

# PowerShell script to display system information
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$outputFile = "$desktopPath\SystemInfo.txt"

# Function to get Windows version (for report output)
$os = (Get-CimInstance Win32_OperatingSystem).Caption
function Get-WindowsVersion {
    $version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    $edition = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    return "$os $version ($edition)"
}

# Function to get Windows installation date
function Get-WindowsInstallDate {
    return (Get-CimInstance Win32_OperatingSystem).InstallDate
}

# Function to retrieve Windows product key using multiple methods (Conditional WMIC for non-Windows 11)
function Get-WindowsProductKey {
    $productKey = $null

    # Runs wmic command only if Windows 10 is detected
    if ($os -match "Windows 10") {
        $wmicKey = (wmic path softwareLicensingService get OA3xOriginalProductKey | Select-Object -Skip 1) -match "\w"
        if ($wmicKey) {
            $productKey = $wmicKey.Trim()
        }
    }

    # If WMIC failed, attempt WMIObject method
    if (-not $productKey) {
        try {
            $wmiKey = (Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService").OA3xOriginalProductKey
            if ($wmiKey) {
                $productKey = $wmiKey
            }
        } catch { }
    }

    # If still no key, attempt ProduKey
    if (-not $productKey -and (Test-Path $produKeyExePath)) {
        $tempKeyFile = "$tempFolder\WindowsKey.txt"

        # Run ProduKey and wait for up to 5 secs to read key
        & $produKeyExePath /WindowsKeys /stext $tempKeyFile
        $timeout = 5
        while (!(Test-Path $tempKeyFile) -and $timeout -gt 0) {
            Start-Sleep -Seconds 1
            $timeout--
        }

        # Once key available, extract the key
        if (Test-Path $tempKeyFile) {
            Start-Sleep -Seconds 1  # add a second to allow file to write properly
            $fileContent = Get-Content $tempKeyFile

            # Search for the first occurrence of "Product Key" and extract key after the colon
            $keyLine = $fileContent | Where-Object { $_ -match "^Product Key\s+:\s+(.+)$" } | Select-Object -First 1

            if ($keyLine) {
                $extractedKey = ($keyLine -split ":\s+")[1]  # Extract key after colon
                
                # Validate key format (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)
                if ($extractedKey -match "^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$") {
                    $productKey = $extractedKey
                }
            }

            # Clean up temporary key file
            Remove-Item -Path $tempKeyFile -Force
        }
    }

    # Return the best available product key
    if ($productKey) {
        return $productKey
    } else {
        return "Unable to retrieve product key"
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

# Function to get storage information (Model & Capacity, excluding "Virtual Disk")
function Get-StorageInfo {
    $drives = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Model -ne "Virtual Disk" }
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

# Prompt user if they want to save to a file
$saveToFile = Read-Host "Do you want to save this report to your desktop? (y/n)"
if ($saveToFile -eq "y") {
    $systemInfo | Out-File -Encoding utf8 $outputFile
    Write-Host "`nSystem information saved to: $outputFile" -ForegroundColor Green
}

# Clean up $downloadsFolder and $tempFolder after extraction
if (Test-Path $produKeyZipPath) {
    Remove-Item -Path $produKeyZipPath -Force
}
#if (Test-Path $tempFolder) {
#    Get-ChildItem -Path $tempFolder -File | Remove-Item -Force
#    Write-Host "Cleaned up temporary files." -ForegroundColor Green
#}
