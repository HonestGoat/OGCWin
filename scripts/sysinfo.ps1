# OGC Windows System Information Tool by Honest Goat
# Version: 0.4 (Fixed Unused Variable & Improved Storage Info)

Write-Host "Gathering system information..." -ForegroundColor Cyan

# PowerShell script to display system information
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

# Function to retrieve Windows product key (Tries both methods)
function Get-WindowsProductKey {
    try {
        # Method 1: Get-WmiObject
        $key = (Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService").OA3xOriginalProductKey
        if ($key) { return $key }

        # Method 2: WMIC
        $key = (wmic path softwareLicensingService get OA3xOriginalProductKey | Select-Object -Skip 1)
        if ($key -match "\w") { return $key.Trim() }
    } catch {
        return "Could not retrieve product key"
    }

    return "Product key not found (OEM key may be stored in BIOS)"
}

# Function to check if Microsoft Recall is active (Windows 11 only)
function Get-MicrosoftRecallStatus {
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($os -match "Windows 11") {
        # Check if Recall service is running
        if (Get-Service -Name "Recall" -ErrorAction SilentlyContinue) {
            return "Active"
        }

        # Check if Recall is available via DISM
        $dismCheck = (DISM /Online /Get-FeatureInfo /FeatureName:Recall 2>&1)
        if ($dismCheck -match "State : Enabled") {
            return "Active"
        } elseif ($dismCheck -match "State : Disabled") {
            return "Available but Disabled"
        } else {
            return "Not Found"
        }
    }
    return "N/A (Windows 10 or Older)"
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

# Function to get storage information (Manufacturer, Model & Capacity, excluding "Virtual Disk")
function Get-StorageInfo {
    $drives = Get-CimInstance Win32_DiskDrive | Where-Object { $_.MediaType -ne "Removable Media" -and $_.Model -ne "Virtual Disk" }
    $output = "Drives:"
    foreach ($drive in $drives) {
        $manufacturer = if ($drive.Manufacturer) { $drive.Manufacturer.Trim() } else { "Manufacturer" }
        $output += "`n  $manufacturer $($drive.Model) | Size: $([math]::Round($drive.Size / 1GB, 2)) GB"
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
Microsoft Recall  : $(Get-MicrosoftRecallStatus)

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
