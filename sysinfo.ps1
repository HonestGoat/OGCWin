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
    $virtualMemory = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty TotalVirtualMemorySize
    return "Installed RAM: ${totalRAM}GB | Virtual Memory: $([math]::Round($virtualMemory / 1MB, 2)) GB"
}

# Function to get storage information
function Get-StorageInfo {
    $drives = Get-PhysicalDisk | Where-Object MediaType -ne "Unspecified"  # Removes virtual disks
    $volumes = Get-Volume | Where-Object { $_.DriveLetter -match "[A-Z]" } # Only physical drives with letters

    $output = "Drives:"
    foreach ($drive in $drives) {
        $volume = $volumes | Where-Object { $_.UniqueId -eq $drive.DeviceId }
        $driveLetter = if ($volume) { "$($volume.DriveLetter):" } else { "No Letter" }
        $freeSpace = if ($volume) { "{0:N2}" -f ($volume.SizeRemaining / 1GB) } else { "Unknown" }
        $output += "`n  [$driveLetter] $($drive.Model) | Size: $([math]::Round($drive.Size / 1GB, 2)) GB | Free Space: ${freeSpace} GB | Type: $($drive.MediaType)"
    }
    return $output
}

# Function to get GPU information (supports multiple GPUs)
function Get-GPUInfo {
    $gpus = Get-CimInstance Win32_VideoController
    $output = "GPUs:"
    foreach ($gpu in $gpus) {
        $vram = if ($gpu.AdapterRAM -gt 0) { [math]::Round($gpu.DedicatedVideoMemory / 1GB, 2) } else { "Unknown" }
        $output += "`n  $($gpu.Name) | VRAM: ${vram}GB | Driver: $($gpu.DriverVersion)"
    }
    return $output
}

# Function to get proper display brand and model
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
