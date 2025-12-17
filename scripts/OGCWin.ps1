# ==========================================    
#           OGC Windows Utility
#              By Honest Goat
#               Version: 0.4
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

# Define Paths (Strict Local Structure)
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configsFolder = Join-Path $parentFolder "configs"
$scriptsFolder = Join-Path $parentFolder "scripts"
$utilitiesFolder = Join-Path $parentFolder "utilities"

# Config and Data
$ConfigPath = Join-Path $configsFolder "urls.cfg"
$Urls = @{}

# Dependencies for this script
$Dependencies = @(
    "$configsFolder\urls.cfg",
    "$scriptsFolder\sysinfo.ps1",
    "$utilitiesFolder\email-backup.ps1",
    "$utilitiesFolder\progsave-backup.ps1"
)



# ==========================================
#             FUNCTIONS
# ==========================================

function Wait-UserAction {
    Write-Host ""
    Write-Host "Press any key to return to the menu..." -ForegroundColor DarkGray
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)] [string]$Message,
        [Parameter(Mandatory=$false)] [ValidateSet("SUCCESS","FAILURE","INFO","WARNING","ERROR")] [string]$Status = "INFO",
        [string]$Module = "General"
    )
    $logFolder = Join-Path $parentFolder "logs"
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $logFile = Join-Path $logFolder "${scriptName}_log.txt"
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$Status] [$timestamp] [$Module] $Message"
    try { Add-Content -Path $logFile -Value $logEntry -Force -ErrorAction Stop }
    catch { Write-Host "CRITICAL: Can't write to $logFile" -ForegroundColor Red }
    if ($Status -eq "FAILURE") { Write-Host "Error ($Module): $Message" -ForegroundColor Red }
    elseif ($Status -eq "WARNING") { Write-Host "Warning ($Module): $Message" -ForegroundColor Yellow }
}

function Set-RegistryValue {
    param ([string]$Path, [string]$Name, [string]$Value, [string]$Type = "DWord")
    if ($Path -match "^HK(LM|CU|CR|U|CC)\") { $Path = $Path -replace "^HK(LM|CU|CR|U|CC)\", "HK`$1:\" }
    try {
        if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        switch ($Type) {
            "REG_DWORD" { $Type = "DWord" }
            "REG_SZ"    { $Type = "String" }
            "REG_BINARY"{ $Type = "Binary" }
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    } catch {
        $regPath = $Path -replace "^HK(LM|CU|CR|U|CC):\", "HK$1\"
        $regType = "REG_DWORD"; if ($Type -eq "String") { $regType = "REG_SZ" }; if ($Type -eq "Binary") { $regType = "REG_BINARY" }
        try { Start-Process -FilePath "reg.exe" -ArgumentList "add `"$regPath`" /v `"$Name`" /t $regType /d `"$Value`" /f" -NoNewWindow -Wait -ErrorAction Stop } catch {}
    }
}

function Remove-AppxPackageAllUsers {
    param ([string]$PackageName)
    Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$PackageName*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

function Test-AppInstallation {
    param ([string]$AppName)
    return ($null -ne (Get-AppxPackage -Name $AppName -AllUsers -ErrorAction SilentlyContinue))
}

function New-RestorePoint {
    Write-Host "Creating System Restore Point..." -ForegroundColor Cyan
    try {
        Checkpoint-Computer -Description "OGC Utility Checkpoint" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "Restore point created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Could not create restore point. Ensure System Restore is enabled." -ForegroundColor Yellow
    }
}

function Install-Download { 
    param($url, $path, $InstallArgs)
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$path`" `"$url`"" -NoNewWindow -Wait
    if (Test-Path $path) { 
        Start-Process -FilePath $path -ArgumentList $InstallArgs -NoNewWindow -Wait
        Remove-Item $path -Force 
    }
}

# --- External Script Wrappers ---

function Invoke-SysInfo {
    & (Join-Path $scriptsFolder "sysinfo.ps1")
    Wait-UserAction
}

function Invoke-EmailBackup {
    & (Join-Path $utilitiesFolder "email-backup.ps1")
    Wait-UserAction
}

function Invoke-ProgSaveBackup {
    & (Join-Path $utilitiesFolder "progsave-backup.ps1")
    Wait-UserAction
}

function Invoke-DesktopLayout {
    & (Join-Path $utilitiesFolder "desktop-layout.ps1")
    Wait-UserAction
}

# --- Core Modules ---

function Invoke-Telemetry {
    Write-Host "Disabling Telemetry & Tracking..." -ForegroundColor Magenta
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    foreach ($service in @("DiagTrack", "dmwappushservice", "Wecsvc", "WerSvc")) { 
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Write-Host "Telemetry disabled." -ForegroundColor Green
    Wait-UserAction
}

function Invoke-Bloatware {
    Write-Host "Removing common bloatware..." -ForegroundColor Magenta
    $crapware = @("Microsoft.BingWeather", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftStickyNotes", "Microsoft.People", "Microsoft.SkypeApp", "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.WindowsCommunicationsApps")
    foreach ($app in $crapware) { Remove-AppxPackageAllUsers $app; Write-Host "Removed $app" -ForegroundColor DarkGray }
    Write-Host "Bloatware removal complete." -ForegroundColor Green
    Wait-UserAction
}

function Invoke-Software {
    Write-Host "--- Software Installation ---" -ForegroundColor Cyan
    Write-Host "1. Gaming (Steam, Epic, Discord...)"
    Write-Host "2. Browsers (Chrome, Firefox...)"
    Write-Host "3. Office (MS Office, LibreOffice...)"
    $choice = Read-Host "Select category (1-3)"
    
    switch ($choice) {
        "1" { 
            winget install Valve.Steam --silent --accept-package-agreements --accept-source-agreements
            winget install EpicGames.EpicGamesLauncher --silent --accept-package-agreements --accept-source-agreements
            winget install Discord.Discord --silent --accept-package-agreements --accept-source-agreements
        }
        "2" {
            $b = Read-Host "Install: 1.Chrome 2.Firefox 3.Brave"
            if ($b -eq "1") { winget install Google.Chrome }
            if ($b -eq "2") { winget install Mozilla.Firefox }
            if ($b -eq "3") { winget install Brave.Brave }
        }
        "3" {
            $o = Read-Host "Install: 1.MS Office 2.LibreOffice"
            if ($o -eq "1") { winget install Microsoft.Office --silent --accept-package-agreements --accept-source-agreements } 
            if ($o -eq "2") { winget install TheDocumentFoundation.LibreOffice --silent --accept-package-agreements --accept-source-agreements }
        }
    }
    Wait-UserAction
}

function Invoke-Drivers {
    Write-Host "--- Driver Installation ---" -ForegroundColor Cyan
    Write-Host "1. NVIDIA"; Write-Host "2. AMD"; Write-Host "3. Intel"
    $d = Read-Host "Select GPU (1-3)"
    
    switch ($d) {
        "1" { Install-Download -url $Urls["DriverNvidia"] -path "$env:TEMP\NVIDIA.exe" -InstallArgs "-s" }
        "2" { Install-Download -url $Urls["DriverAmd"] -path "$env:TEMP\AMD.exe" -InstallArgs "/INSTALL /SILENT" }
        "3" { Install-Download -url $Urls["DriverIntelHd"] -path "$env:TEMP\Intel.exe" -InstallArgs "-s" }
    }
    Wait-UserAction
}

function Invoke-SystemTools {
    Write-Host "--- System Tools ---" -ForegroundColor Cyan
    Write-Host "1. System File Checker (SFC /scannow)"
    Write-Host "2. DISM Restore Health"
    Write-Host "3. IP Configuration (ipconfig /all)"
    Write-Host "4. Disk Cleanup"
    $t = Read-Host "Select Tool (1-4)"
    
    switch ($t) {
        "1" { sfc /scannow }
        "2" { dism /online /cleanup-image /restorehealth }
        "3" { ipconfig /all; Wait-UserAction }
        "4" { cleanmgr }
    }
    if ($t -in "1","2") { Wait-UserAction }
}

function Invoke-DisableUpdates {
    Write-Host "--- DISABLE WINDOWS UPDATES ---" -ForegroundColor Red
    Write-Host "WARNING: Disabling updates stops security patches." -ForegroundColor Yellow
    Write-Host "This is recommended for Windows 10 EOL to prevent forced upgrades to Windows 11,"
    Write-Host "performance degradation, and unwanted feature changes."
    Write-Host "However, ensure your system is behind a firewall and avoid risky behavior."
    Write-Host ""
    $confirm = Read-Host "Are you sure you want to FULLY DISABLE Windows Updates? (y/n)"
    if ($confirm -ne "y") { return }

    Write-Host "Disabling Update Services..." -ForegroundColor Magenta
    $services = @("wuauserv", "UsoSvc", "WaaSMedicSvc")
    foreach ($s in $services) {
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
    }

    Write-Host "Blocking Updates via Registry..." -ForegroundColor Magenta
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1
    
    # Remove Target Release Version locks if they exist to ensure block works cleanly
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ProductVersion" -ErrorAction SilentlyContinue

    Write-Host "Windows Updates have been fully disabled." -ForegroundColor Green
    Wait-UserAction
}

function Invoke-EnableUpdates {
    Write-Host "--- ENABLE WINDOWS UPDATES ---" -ForegroundColor Cyan
    Write-Host "1. Security Updates Only (Locks to Win10 22H2 - Recommended)"
    Write-Host "2. Full Updates (Enables Feature Upgrades & Win11)"
    $c = Read-Host "Select Option (1-2)"

    Write-Host "Enabling Update Services..." -ForegroundColor Magenta
    $services = @("wuauserv", "UsoSvc", "WaaSMedicSvc")
    foreach ($s in $services) {
        Set-Service -Name $s -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name $s -ErrorAction SilentlyContinue
    }
    
    # Enable Auto Update Policy
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0

    if ($c -eq "1") {
        Write-Host "Locking Target Version to Windows 10 22H2..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -Value 1
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -Value "22H2" -Type "String"
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ProductVersion" -Value "Windows 10" -Type "String"
        Write-Host "Updates enabled but locked to Security Updates only." -ForegroundColor Green
    } elseif ($c -eq "2") {
        Write-Host "Unlocking Target Version..." -ForegroundColor Magenta
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ProductVersion" -ErrorAction SilentlyContinue
        Write-Host "Full Windows Updates enabled." -ForegroundColor Green
    }
    Wait-UserAction
}


# ==========================================
#        SETUP & VALIDATION
# ==========================================

$MissingDeps = $false

foreach ($dep in $Dependencies) {
    if (-not (Test-Path $dep)) {
        Write-Host "Missing dependency: $dep" -ForegroundColor Yellow
        $MissingDeps = $true
    }
}

if ($MissingDeps) {
    Write-Host "Required files missing. Initiating repair..." -ForegroundColor Red
    Start-Sleep -Seconds 2
    
    $LocalLaunch = Join-Path $scriptsFolder "launch.ps1"
    if (Test-Path $LocalLaunch) {
        & $LocalLaunch
        exit
    } else {
        Invoke-Expression (Invoke-RestMethod "https://ogc.win")
        exit
    }
}

# Load Config
Get-Content $ConfigPath | ForEach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
        $Urls[$matches[1]] = $matches[2]
    }
}


# ==========================================
#           MAIN PROGRAM
# ==========================================

while ($true) {
    Clear-Host
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "        OGC Windows 11 Utility         " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host ""
    Write-Host "System: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "--- GENERAL ---" -ForegroundColor Yellow
    Write-Host "1.  View System Information"
    Write-Host "2.  Create System Restore Point"
    
    Write-Host "`n--- PRIVACY & CLEANUP ---" -ForegroundColor Yellow
    Write-Host "3.  Disable Telemetry & Tracking"
    Write-Host "4.  Remove Bloatware"
    Write-Host "5.  Disable Cortana & Search"
    Write-Host "6.  Debloat Taskbar (Remove Weather, Search Bar, Widgets, News & Interests etc)"
    
    Write-Host "`n--- SOFTWARE & DRIVERS ---" -ForegroundColor Yellow
    Write-Host "7.  Install Common Software (Browsers, Gaming, Office Suites)"
    Write-Host "8.  Install Graphics Drivers"
    
    Write-Host "`n--- UTILITIES & TOOLS ---" -ForegroundColor Yellow
    Write-Host "9.  System File Checker & Repair tools"
    Write-Host "10. Desktop Layout Manager (BETA)"
    Write-Host "11. Email Backup & Restore (BETA)"
    Write-Host "12. Game Save & Settings Backup (BETA)"
    
    Write-Host "`n--- ADVANCED ---" -ForegroundColor Yellow
    Write-Host "13. Run New PC Setup Wizard"
    Write-Host "14. Disable Windows Updates (Use with Caution)"
    Write-Host "15. Enable Windows Updates (Security Only or Full)"
    Write-Host "Q.  Quit"
    Write-Host ""
    
    $selection = Read-Host "Select an option"
    
    switch ($selection) {
        "1"  { Invoke-SysInfo }
        "2"  { New-RestorePoint; Wait-UserAction }
        "3"  { Invoke-Telemetry }
        "4"  { Invoke-Bloatware }
        "5"  { 
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
            Remove-AppxPackageAllUsers "Microsoft.549981C3F5F10"
            Write-Host "Cortana disabled." -ForegroundColor Green
            Wait-UserAction
        }
        "6"  {
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1
            Write-Host "Taskbar debloated." -ForegroundColor Green
            Wait-UserAction
        }
        "7"  { Invoke-Software }
        "8"  { Invoke-Drivers }
        "9"  { Invoke-SystemTools }
        "10" { Invoke-DesktopLayout }
        "11" { Invoke-EmailBackup }
        "12" { Invoke-ProgSaveBackup }
        "13" { 
            $wizPath = Join-Path $scriptsFolder "OGCWiz11.ps1"
            if (Test-Path $wizPath) { & $wizPath } else { Write-Host "Wizard script not found." -ForegroundColor Red; Wait-UserAction }
        }
        "14" { Invoke-DisableUpdates }
        "15" { Invoke-EnableUpdates }
        "Q"  { exit }
        "q"  { exit }
        default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}