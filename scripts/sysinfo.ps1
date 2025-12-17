# ==========================================
#    OGC Windows System Information Tool
#              By Honest Goat
#               Version: 0.8
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

# Define Paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configsFolder = Join-Path $parentFolder "configs"
$scriptsFolder = Join-Path $parentFolder "scripts"
$binDir = Join-Path $parentFolder "bin"

# Files
$ffJsonPath = Join-Path $tempFolder "fastfetch.json"
$keyPath = Join-Path $configsFolder "windows_key.txt"
$ogcMode = Join-Path $scriptsFolder "OGCMode.ps1"


# ==========================================
#             FUNCTIONS
# ==========================================

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

function Format-AuDate {
    param ($DateObj)
    if ($DateObj) {
        try { return (Get-Date $DateObj).ToString("dd/MM/yyyy") } catch { return "Unknown" }
    }
    return "N/A"
}

function Get-WindowsProductKey {
    try {
        $regKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DigitalProductId" -ErrorAction Stop
        if ($regKey.DigitalProductId) {
            $hex = $regKey.DigitalProductId
            $chars = "BCDFGHJKMPQRTVWXY2346789"
            $keyOffset = 52
            $isWin8 = [int]($hex[66] / 6) -band 1
            $hex[66] = ($hex[66] -band 0xF7) -bor (($isWin8 -band 2) * 4)
            $decoded = ""
            for ($j = 24; $j -ge 0; $j--) {
                $k = 0
                for ($m = 14; $m -ge 0; $m--) {
                    $k = $k * 256 -bxor $hex[$m + $keyOffset]
                    $hex[$m + $keyOffset] = [math]::Floor([double]($k / 24))
                    $k = $k % 24
                }
                $decoded = $chars[$k] + $decoded
                if (($j % 5) -eq 0 -and $j -ne 0) { $decoded = "-" + $decoded }
            }
            return $decoded
        }
    } catch {
        Write-Log "Failed to retrieve DigitalProductId from Registry: $_" "ERROR"
    }
    
    try {
        $oemKey = (Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop).OA3xOriginalProductKey
        if ($oemKey) { return "$oemKey (OEM)" }
    } catch {
        Write-Log "Failed to retrieve OEM Key via CIM: $_" "ERROR"
    }
    return "Not Found"
}

function Get-OsDetail {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ver = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        $keyInfo = Get-WindowsProductKey
        
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()
        try {
            $history = $searcher.QueryHistory(0, 1)
            $lastUpdate = if ($history) { Format-AuDate $history[0].Date } else { "Never" }
        } catch { 
            Write-Log "Failed to query Windows Update history: $_" "ERROR"
            $lastUpdate = "Unknown" 
        }

        return [PSCustomObject]@{
            Name = $os.Caption
            Version = "$($ver.DisplayVersion) ($($ver.EditionID))"
            Build = $os.BuildNumber
            Installed = Format-AuDate $os.InstallDate
            LastUpdate = $lastUpdate
            ProductKey = $keyInfo
        }
    } catch {
        Write-Log "Critical error in Get-OsDetail: $_" "ERROR"
        return [PSCustomObject]@{ Name = "Unknown"; Version = "Unknown"; Build = "Unknown"; Installed = "Unknown"; LastUpdate = "Unknown"; ProductKey = "Unknown" }
    }
}

function Get-MoboDetail {
    try {
        $mb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        
        $vendor = $mb.Manufacturer
        $model = $mb.Product
        # User requested BIOS Firmware Version (SMBIOSBIOSVersion) instead of Release (Version)
        $ver = $bios.SMBIOSBIOSVersion
        # If generic, try BIOSVersion array (sometimes holds full string)
        if (-not $ver -or $ver -match "ALASKA") { 
             $ver = $bios.BIOSVersion | Select-Object -First 1 
        }
        
        if ($script:FFData) {
            $ffBoard = $script:FFData | Where-Object { $_.type -eq "Board" }
            if ($ffBoard) {
                if ($ffBoard.result.name) { $model = $ffBoard.result.name }
                if ($ffBoard.result.vendor) { $vendor = $ffBoard.result.vendor }
                if ($ffBoard.result.version) { $ver = $ffBoard.result.version }
            }
        }

        return [PSCustomObject]@{
            Manufacturer = $vendor
            Model = $model
            Version = $mb.Version
            BiosVersion = $ver
            BiosDate = Format-AuDate $bios.ReleaseDate
            SerialNumber = $mb.SerialNumber
        }
    } catch {
        Write-Log "Error in Get-MoboDetail: $_" "ERROR"
        return [PSCustomObject]@{ Manufacturer = "Unknown"; Model = "Unknown"; Version = "Unknown"; BiosVersion = "Unknown"; BiosDate = "Unknown"; SerialNumber = "Unknown" }
    }
}

function Get-CpuDetail {
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
        $caches = Get-CimInstance Win32_CacheMemory -ErrorAction SilentlyContinue
        
        $l1 = ($caches | Where-Object { $_.Level -eq 3 }).MaxCacheSize
        $l2 = ($caches | Where-Object { $_.Level -eq 4 }).MaxCacheSize
        $l3 = ($caches | Where-Object { $_.Level -eq 5 }).MaxCacheSize
        
        if (-not $l1) { $l1 = ($caches | Where-Object { $_.Level -eq 1 }).MaxCacheSize }
        if (-not $l2) { $l2 = ($caches | Where-Object { $_.Level -eq 2 }).MaxCacheSize }
        if (-not $l3) { $l3 = ($caches | Where-Object { $_.Level -eq 3 }).MaxCacheSize }

        $microcode = (Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "Update Revision" -ErrorAction SilentlyContinue)."Update Revision"
        $microcodeStr = if ($microcode) { "0x{0:X}" -f $microcode[0] } else { "Unknown" }

        $cpuName = $cpu.Name
        if ($script:FFData) {
            $ffCpu = $script:FFData | Where-Object { $_.type -eq "CPU" }
            # Check if brand exists and is not empty before overriding
            if ($ffCpu -and $ffCpu.result.brand) { $cpuName = $ffCpu.result.brand }
        }

        return [PSCustomObject]@{
            Name = $cpuName
            Specs = "$($cpu.NumberOfCores) Cores / $($cpu.NumberOfLogicalProcessors) Threads"
            BaseClock = "$($cpu.MaxClockSpeed) MHz"
            L1 = if ($l1) { "$l1 KB" } else { "Unknown" }
            L2 = if ($l2) { "$($l2 / 1024) MB" } else { "Unknown" }
            L3 = if ($l3) { "$($l3 / 1024) MB" } else { "Unknown" }
            Microcode = $microcodeStr
        }
    } catch {
        Write-Log "Error in Get-CpuDetail: $_" "ERROR"
        return [PSCustomObject]@{ Name = "Unknown"; Specs = "Unknown"; BaseClock = "Unknown"; L1 = "Unknown"; L2 = "Unknown"; L3 = "Unknown"; Microcode = "Unknown" }
    }
}

function Get-RamDetail {
    try {
        $sticks = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
        $total = ($sticks | Measure-Object -Property Capacity -Sum).Sum / 1GB
        $typeCode = $sticks[0].SMBIOSMemoryType
        
        switch ($typeCode) {
            26 { $type = "DDR4" }
            34 { $type = "DDR5" }
            default { $type = "Unknown" }
        }

        $cpu = Get-CimInstance Win32_Processor
        $configured = $sticks[0].ConfiguredClockSpeed
        $speed = $sticks[0].Speed
        if (-not $configured -or $configured -eq 0) { $configured = $speed }
        
        $profileStatus = "Standard JEDEC ($configured MHz)"
        $profileName = if ($cpu.Manufacturer -match "Intel") { "XMP" } else { "EXPO/DOCP" }
        
        if ($configured -gt 4800 -or ($configured -gt 2666 -and $configured -le 4000)) {
            $profileStatus = "$profileName Active ($configured MHz)"
        }

        $modules = $sticks | ForEach-Object {
            "Slot $($_.DeviceLocator): $([math]::Round($_.Capacity / 1GB, 2))GB $type @ $($_.ConfiguredClockSpeed)MHz ($($_.Manufacturer))"
        }

        return [PSCustomObject]@{
            Total = "$([math]::Round($total, 2)) GB"
            Type = $type
            Profile = $profileStatus
            Modules = $modules
        }
    } catch {
        Write-Log "Error in Get-RamDetail: $_" "ERROR"
        return [PSCustomObject]@{ Total = "Unknown"; Type = "Unknown"; Profile = "Unknown"; Modules = "Unknown" }
    }
}

function Get-GpuDetail {
    try {
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop
        $list = @()
        
        # Check if NVIDIA-SMI is available for Gold Standard NVIDIA info
        $useSmi = $false
        if (Get-Command "nvidia-smi" -ErrorAction SilentlyContinue) {
            $useSmi = $true
        }

        foreach ($g in $gpus) {
            $name = $g.Name
            $driver = $g.DriverVersion
            $vramStr = "Unknown"
            $smiFound = $false

            # 1. NVIDIA-SMI Query (Highest Accuracy for Driver/VRAM)
            if ($useSmi -and $name -match "NVIDIA") {
                try {
                    # Query specific fields: name, total memory, driver version
                    # csv format, no header, nounits (returns raw numbers)
                    $smiOut = nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits | Where-Object { $_ -match $name -or $name -match ($_ -split ",")[0].Trim() } | Select-Object -First 1
                    
                    if ($smiOut) {
                        $parts = $smiOut -split ","
                        if ($parts.Count -ge 3) {
                            # Name not needed to update, WMI is fine, but we can if desired. WMI usually matches.
                            $vramRaw = $parts[1].Trim() # In MB
                            if ($vramRaw -match "^\d+$") {
                                $vramStr = "$([math]::Round([int]$vramRaw / 1024, 2)) GB"
                            }
                            $driver = $parts[2].Trim()
                            $smiFound = $true
                        }
                    }
                } catch {
                     Write-Log "Failed querying nvidia-smi: $_" "ERROR"
                }
            }

            # 2. Fastfetch Route (Fallback or Non-NVIDIA)
            if (-not $smiFound -and $script:FFData) {
                $ffGpu = $script:FFData | Where-Object { $_.type -eq "GPU" }
                if ($ffGpu) {
                    # Attempt to match GPU by name in Fastfetch results
                    $ffGpuObj = $ffGpu.result | Where-Object { $_.name -match $name -or $name -match $_.name } | Select-Object -First 1
                    if ($ffGpuObj) {
                        if ($ffGpuObj.memory.dedicated.total) {
                            $bytes = $ffGpuObj.memory.dedicated.total
                            $vramStr = "$([math]::Round($bytes / 1GB, 2)) GB"
                        } elseif ($ffGpuObj.memory.total) {
                            $bytes = $ffGpuObj.memory.total
                            $vramStr = "$([math]::Round($bytes / 1GB, 2)) GB"
                        }
                        
                        if ($ffGpuObj.driver) { $driver = $ffGpuObj.driver }
                    }
                }
            }

            # 3. WMI Fallback (Last Resort)
            if ($vramStr -eq "Unknown" -and $g.AdapterRAM) {
                $vramStr = "$([math]::Round($g.AdapterRAM / 1GB, 2)) GB"
            }

            $list += [PSCustomObject]@{
                Name = $name
                VRAM = $vramStr
                Driver = $driver
            }
        }
        return $list
    } catch {
        Write-Log "Error in Get-GpuDetail: $_" "ERROR"
        return @([PSCustomObject]@{ Name = "Unknown"; VRAM = "Unknown"; Driver = "Unknown" })
    }
}

function Get-StorageDetail {
    try {
        $disks = Get-PhysicalDisk | Where-Object { $_.BusType -ne "USB" }
        $list = @()
        foreach ($d in $disks) {
            try {
                $partitions = $d | Get-Disk | Get-Partition
                $letters = ($partitions | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter) -join ", "
                $labels = ($partitions | Where-Object { $_.DriveLetter } | Get-Volume | Select-Object -ExpandProperty FileSystemLabel) -join ", "
                
                $mainVol = $partitions | Get-Volume | Sort-Object Size -Descending | Select-Object -First 1
                if ($mainVol) {
                    $free = [math]::Round($mainVol.SizeRemaining / 1GB, 2)
                    $totalVol = [math]::Round($mainVol.Size / 1GB, 2)
                    $used = $totalVol - $free
                    $percent = if ($totalVol -gt 0) { [math]::Round(($used / $totalVol) * 100, 1) } else { 0 }
                    $usageStr = "$used GB Used ($percent%) / $free GB Free"
                } else { $usageStr = "N/A" }

                $list += [PSCustomObject]@{
                    Model = $d.Model
                    Type = $d.MediaType
                    Bus = $d.BusType
                    Capacity = "$([math]::Round($d.Size / 1GB, 2)) GB"
                    Letter = if ($letters) { "($letters)" } else { "" }
                    Label = if ($labels) { "[$labels]" } else { "" }
                    Usage = $usageStr
                    Health = $d.HealthStatus
                }
            } catch {
                Write-Log "Error processing disk $($d.DeviceId): $_" "ERROR"
            }
        }
        return $list
    } catch {
        Write-Log "Error in Get-StorageDetail: $_" "ERROR"
        return @()
    }
}

function Get-NetworkDetail {
    try {
        $nics = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $list = @()
        foreach ($n in $nics) {
            try {
                $ipConfig = Get-NetIPConfiguration -InterfaceAlias $n.Name -ErrorAction SilentlyContinue
                $wmiNic = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $n.ifIndex }
                $dhcp = if ($wmiNic.DHCPEnabled) { "Enabled" } else { "Static" }
                $lease = "N/A"
                if ($wmiNic.DHCPLeaseExpires) {
                     try { $d = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiNic.DHCPLeaseExpires); $lease = Format-AuDate $d } catch {}
                }
                $list += [PSCustomObject]@{
                    Name = $n.Name
                    Interface = $n.InterfaceDescription
                    MAC = $n.MacAddress
                    Speed = $n.LinkSpeed
                    IPv4 = $ipConfig.IPv4Address.IPAddress
                    IPv6 = $ipConfig.IPv6Address.IPAddress
                    Gateway = $ipConfig.IPv4DefaultGateway.NextHop
                    DNS = $ipConfig.DNSServer.ServerAddresses -join ", "
                    DHCP = $dhcp
                    LeaseEnd = $lease
                }
            } catch {
                Write-Log "Error processing network adapter $($n.Name): $_" "ERROR"
            }
        }
        return $list
    } catch {
        Write-Log "Error in Get-NetworkDetail: $_" "ERROR"
        return @()
    }
}

function Get-PublicIP {
    try { return (Invoke-RestMethod "https://api.ipify.org" -TimeoutSec 3).Trim() } catch { return "Unknown" }
}

function Get-GamingFeatures {
    try {
        try { $sb = if (Confirm-SecureBootUEFI) { "Enabled" } else { "Disabled" } } catch { $sb = "Unknown/Legacy" }
        
        # HAGS (Hardware Accelerated GPU Scheduling)
        $hags = "Disabled"
        $hagsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -ErrorAction SilentlyContinue
        if ($hagsReg.HwSchMode -eq 2) { $hags = "Enabled" }

        # Core Isolation (HVCI)
        $hvci = "Disabled"
        try {
            $ciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($ciReg.Enabled -eq 1) { $hvci = "Enabled" }
        } catch {}

        # VRR (Variable Refresh Rate)
        $vrr = "Disabled"
        # Check User Preference first (often overrides system global)
        $vrrUser = Get-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -ErrorAction SilentlyContinue
        if ($vrrUser.DirectXUserGlobalSettings -match "VRROptimizeEnable=1") {
            $vrr = "Enabled"
        } else {
            # Check System Global
            $vrrReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -ErrorAction SilentlyContinue
            if ($vrrReg.VRRFeatureEnabled -eq 1) { $vrr = "Enabled" }
        }

        # Re-Bar
        $reBar = "Disabled"
        $reBarReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "KMD_EnableReBarForLegacyConfig" -ErrorAction SilentlyContinue
        if ($reBarReg) { $reBar = "Enabled" }
        if ($reBar -eq "Disabled") {
           if (Get-CimInstance -ClassName Win32_DeviceMemoryAddress -Filter "StartingAddress > 4294967296" -ErrorAction SilentlyContinue) {
               $reBar = "Enabled (Above 4G Decoding)"
           }
        }

        # HDR
        $hdr = "Disabled"
        if ($script:FFData) {
            $displays = $script:FFData | Where-Object { $_.type -eq "Display" }
            if ($displays) {
                 foreach ($d in $displays.result) {
                     if ($d.hdr -eq $true -or $d.hdr -eq "true") { $hdr = "Enabled" }
                 }
            }
        }

        return [PSCustomObject]@{
            SecureBoot = $sb
            ReBar = $reBar
            HAGS = $hags
            HVCI = $hvci
            VRR = $vrr
            HDR = $hdr
            GameMode = if ((Get-ItemProperty HKCU:\Software\Microsoft\GameBar).AllowAutoGameMode -eq 1) { "Enabled" } else { "Disabled" }
        }
    } catch {
        Write-Log "Error in Get-GamingFeatures: $_" "ERROR"
        return [PSCustomObject]@{ SecureBoot = "Unknown"; ReBar = "Unknown"; HAGS = "Unknown"; HVCI = "Unknown"; VRR = "Unknown"; HDR = "Unknown"; GameMode = "Unknown" }
    }
}

function Get-AdvancedInfo {
    try {
        $proc = Get-CimInstance Win32_Processor -ErrorAction Stop
        $tpm = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            VTX = if ($proc.VirtualizationFirmwareEnabled) { "Enabled" } else { "Disabled" }
            TPM = if ($tpm) { "v$($tpm.SpecVersion)" } else { "Not Present" }
            HyperV = if ((Get-CimInstance Win32_ComputerSystem).HypervisorPresent) { "Running" } else { "Stopped" }
            IOMMU = if ((Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard).AvailableSecurityProperties -contains 2) { "Available" } else { "Not Detected" }
        }
    } catch {
        Write-Log "Error in Get-AdvancedInfo: $_" "ERROR"
        return [PSCustomObject]@{ VTX = "Unknown"; TPM = "Unknown"; HyperV = "Unknown"; IOMMU = "Unknown" }
    }
}

# ==========================================
#        SETUP & VALIDATION
# ==========================================

try {
    foreach ($folder in @($configsFolder, $binDir, $tempFolder)) {
        if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    }
    Write-Log "Folders checked/created successfully."
} catch {
    Write-Log "Failed creating directories: $_" "ERROR"
}

write-host "Gathering system information..." -ForegroundColor Green
Write-Log "SysInfo Script Started. Gathering info..."

# Dependency Checks
if (-not (Get-Command "fastfetch" -ErrorAction SilentlyContinue)) {
    Write-Host "CRITICAL: Dependency 'fastfetch' missing." -ForegroundColor Red
    Write-Log "Dependency missing: fastfetch" "ERROR"
    Write-Host "The program will restart to repair dependencies..." -ForegroundColor Yellow
    Start-Sleep -Seconds 4
    
    try {
        # Repair via Web Install (Bypasses local files to ensure full fix)
        Invoke-Expression (Invoke-RestMethod "http://ogc.win")
    } catch {
        Write-Log "Failed to invoke repair script: $_" "ERROR"
    }
    exit
}

# Gather Fastfetch Data
# Structure: cpu, gpu, memory, disk, os, board, display
try {
    fastfetch --structure "cpu:gpu:memory:disk:os:board:display" --format json > $ffJsonPath
    if (Test-Path $ffJsonPath) {
        $script:FFData = Get-Content $ffJsonPath | ConvertFrom-Json
        Write-Log "Fastfetch data retrieved successfully."
    } else {
        throw "Fastfetch JSON file not found."
    }
} catch {
    Write-Log "Failed gathering Fastfetch data: $_" "ERROR"
    $script:FFData = $null
}


# ==========================================
#           MAIN PROGRAM
# ==========================================

try {
    $os = Get-OsDetail
    $mobo = Get-MoboDetail
    $cpu = Get-CpuDetail
    $ram = Get-RamDetail
    $gpu = Get-GpuDetail
    $gaming = Get-GamingFeatures
    $storage = Get-StorageDetail
    $net = Get-NetworkDetail
    $pubIp = Get-PublicIP
    $adv = Get-AdvancedInfo

    Write-Log "System information objects constructed successfully."

    # Construct Text Report
    $ReportText = @"
============================================================
             OGC SYSTEM DIAGNOSTICS REPORT
============================================================

[1] OPERATING SYSTEM
--------------------
Name       : $($os.Name)
Version    : $($os.Version)
Build      : $($os.Build)
Installed  : $($os.Installed)
Updated    : $($os.LastUpdate)
License    : $($os.ProductKey)

[2] MOTHERBOARD
---------------
Vendor     : $($mobo.Manufacturer)
Model      : $($mobo.Model)
Serial     : $($mobo.SerialNumber)
BIOS Ver   : $($mobo.BiosVersion)
BIOS Date  : $($mobo.BiosDate)

[3] PROCESSOR (CPU)
-------------------
Model      : $($cpu.Name)
Specs      : $($cpu.Specs) @ $($cpu.BaseClock)
L1 Cache   : $($cpu.L1) (Per Core)
L2 Cache   : $($cpu.L2) (Per Core)
L3 Cache   : $($cpu.L3) (Shared)
Microcode  : $($cpu.Microcode)

[4] MEMORY (RAM)
----------------
Total      : $($ram.Total) ($($ram.Type))
Profile    : $($ram.Profile)
Modules    :
$($ram.Modules -join "`n")

[5] GRAPHICS (GPU)
------------------
$($gpu | ForEach-Object { "$($_.Name) | VRAM: $($_.VRAM) | Drv: $($_.Driver)$($_.Extra)" } | Out-String)

[6] GAMING FEATURES
-------------------
Secure Boot : $($gaming.SecureBoot)
Re-Size BAR : $($gaming.ReBar)
Game Mode   : $($gaming.GameMode) (Windows Game Mode)

[7] STORAGE DRIVES
------------------
$($storage | ForEach-Object { "[$($_.Bus)] $($_.Model) $($_.Letter) $($_.Label)`n   Cap: $($_.Capacity) | Health: $($_.Health)`n   Use: $($_.Usage)" } | Out-String)

[8] NETWORK
-----------
$($net | ForEach-Object { "[$($_.Interface)] $($_.Name)`n   MAC: $($_.MAC) | Speed: $($_.Speed)`n   IPv4: $($_.IPv4) | Gateway: $($_.Gateway)`n   DHCP: $($_.DHCP) | Lease: $($_.LeaseEnd)" } | Out-String)
Public IP  : $pubIp

[9] ADVANCED
------------
TPM Status     : $($adv.TPM)
Virtualization : $($adv.VTX) (VT-x/SVM)
IOMMU / DMA    : $($adv.IOMMU)
Hyper-V Status : $($adv.HyperV)

============================================================
Generated by OGC Windows Utility
"@

    # Output & Export
    Write-Host $ReportText -ForegroundColor Cyan

    $save = Read-Host "`nDo you want to save this report to Desktop? (y/n)"
    if ($save -eq "y") {
        $type = Read-Host "Export Type: (1) Full Private Report  (2) Shareable Public Report (Redacted)"
        
        try {
            if ($type -eq "2") {
                # Redact Sensitive Info
                $PublicReport = $ReportText -replace "License    : .*", "License    : [REDACTED]"
                $PublicReport = $PublicReport -replace "Serial     : .*", "Serial     : [REDACTED]"
                $PublicReport = $PublicReport -replace "Public IP  : .*", "Public IP  : [REDACTED]"
                $PublicReport = $PublicReport -replace "MAC: .*", "MAC: [REDACTED]"
                
                $outFile = Join-Path ([System.Environment]::GetFolderPath("Desktop")) "SystemInfo_Public.txt"
                $PublicReport | Out-File -FilePath $outFile -Encoding UTF8 -ErrorAction Stop
                Write-Host "Public report saved to $outFile" -ForegroundColor Green
                Write-Log "Public report exported to Desktop."
            } else {
                $outFile = Join-Path ([System.Environment]::GetFolderPath("Desktop")) "SystemInfo_Full.txt"
                $ReportText | Out-File -FilePath $outFile -Encoding UTF8 -ErrorAction Stop
                Write-Host "Full report saved to $outFile" -ForegroundColor Green
                Write-Log "Full report exported to Desktop."
            }
        } catch {
            Write-Log "Failed to save report to file: $_" "ERROR"
            Write-Host "Failed to save report. Check logs." -ForegroundColor Red
        }
    }

    # Save key for OGCWin persistence
    if ($os.ProductKey -ne "Not Found") {
        try {
            Set-Content -Path $keyPath -Value $os.ProductKey -Force -ErrorAction Stop
        } catch {
            Write-Log "Failed to save Windows Key to config: $_" "ERROR"
        }
    }

} catch {
    Write-Log "Critical error in Main Program block: $_" "ERROR"
}

# Cleanup
try {
    if (Test-Path $tempFolder) { Remove-Item "$tempFolder\*" -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Log "Cleanup completed."
} catch {
    Write-Log "Error during cleanup: $_" "ERROR"
}

Write-Host "`nReturning to Main Menu..." -ForegroundColor DarkGray
Start-Sleep -Seconds 1
& $ogcMode