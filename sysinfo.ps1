# PowerShell script to display system information in an organized format
$desktopPath = [System.Environment]::GetFolderPath("Desktop")
$outputFile = "$desktopPath\SystemInfo.txt"

# Function to get Windows version (e.g., Windows 11 24H2)
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
    (Get-WmiObject -Query "SELECT * FROM SoftwareLicensingService").OA3xOriginalProductKey
}

# Function to check if Windows updates are available
function Get-WindowsUpdateStatus {
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $result = $updateSearcher.Search("IsInstalled=0")
        return if ($result.Updates.Count -gt 0) { "Updates available" } else { "Fully up to date" }
    } catch {
        return "Could not check update status"
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
    $drives = Get-PhysicalDisk | Select-Object MediaType, Model, @{Name="Size (GB)"; Expression={"{0:N2}" -f ($_.Size / 1GB)}}
    $output = "Drives:"
    foreach ($drive in $drives) {
        $output += "`n  $($drive.Model) | Size: $($drive.'Size (GB)') GB | Type: $($drive.MediaType)"
    }
    return $output
}

# Function to get GPU information
function Get-GPUInfo {
    $gpu = Get-CimInstance Win32_VideoController
    return "$($gpu.Name) | VRAM: $([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB | Driver: $($gpu.DriverVersion)"
}

# Function to get connected display information
function Get-DisplayInfo {
    $monitors = Get-CimInstance WmiMonitorID -Namespace root\wmi
    $output = "Connected Displays:"
    foreach ($monitor in $monitors) {
        $model = [System.Text.Encoding]::ASCII.GetString($monitor.UserFriendlyName) -replace '\0'
        $output += "`n  Model: $model"
    }
    return $output
}

# Function to get keyboard and mouse information
function Get-InputDevices {
    $devices = Get-PnpDevice | Where-Object { $_.Class -match "Keyboard|Mouse" } | Select-Object FriendlyName
    return "Input Devices:`n" + ($devices.FriendlyName -join "`n  ")
}

# Function to get audio devices
function Get-AudioDevices {
    $audio = Get-CimInstance Win32_SoundDevice
    return "Audio Devices:`n" + ($audio | ForEach-Object { "  $($_.Manufacturer) $($_.ProductName)" }) -join "`n"
}

# Collect system information
$systemInfo = @"
===================================
    SYSTEM INFORMATION REPORT
===================================
Windows Version   : $(Get-WindowsVersion)
Windows Installed : $(Get-WindowsInstallDate)
Product Key       : $(Get-WindowsProductKey)
Update Status     : $(Get-WindowsUpdateStatus)

CPU              : $(Get-CPUInfo)
Motherboard      : $(Get-MotherboardInfo)
RAM              : $(Get-RAMInfo)
Storage          : $(Get-StorageInfo)

GPU              : $(Get-GPUInfo)
Displays         : $(Get-DisplayInfo)
Input Devices    : $(Get-InputDevices)
Audio Devices    : $(Get-AudioDevices)

===================================
"@

# Display system information
Write-Host $systemInfo -ForegroundColor Cyan

# Save to a file
$systemInfo | Out-File -Encoding utf8 $outputFile
Write-Host "`nSystem information saved to: $outputFile" -ForegroundColor Green
