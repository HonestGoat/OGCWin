# ==========================================
#        OGC Windows Utility Launcher
#              By Honest Goat
#               Version: 0.5
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

# OGCWin folder definitions
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$downloadsFolder = "$parentFolder\downloads"
$configsFolder = "$parentFolder\configs"
$tempFolder = "$parentFolder\temp"
$scriptsFolder = "$parentFolder\scripts"
$utilitiesFolder = "$parentFolder\utilities"
$backupFolder = "$parentFolder\backups"
$registryBackup = "$backupFolder\registry"
$binDir = "$parentFolder\bin"
$desktopProfiles = "$parentFolder\backups\desktop profiles"
$powerProfiles = "$parentFolder\backups\power profiles"
$driverBackups = "$parentFolder\backups\drivers"

# Filename definitions
$ogclaunch = "$scriptsFolder\launch.ps1"
$ogcwinbat = "$parentFolder\OGCWin.bat"
$ogcmode = "$scriptsFolder\OGCMode.ps1"
$ogcwin = "$scriptsFolder\OGCWin.ps1"
$ogcwiz11 = "$scriptsFolder\OGCWiz11.ps1"
$sysinfo = "$scriptsFolder\sysinfo.ps1"
$progsavebackup = "$utilitiesFolder\progsave-backup.ps1"
$emailBackup = "$utilitiesFolder\email-backup.ps1"
$desktopLayout = "$utilitiesFolder\desktop-layout.ps1"

# Config URLs & Paths
$urlsConfigPath = "$configsFolder\urls.cfg"
$urlsConfigUrl = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/urls.cfg"
$versionLocal = "$configsFolder\version.cfg"
$versionOnline = "https://raw.githubusercontent.com/HonestGoat/OGCWin/main/configs/version.cfg"

# Dependency Paths
$vclibsPath = "$downloadsFolder\Microsoft.VCLibs.x64.14.00.Desktop.appx"
$xamlPath = "$downloadsFolder\Microsoft.UI.Xaml.2.8_8.2501.31001.0_x64.appx"

# Desktop shortcut path and icon
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "OGC Windows Utility.lnk")
$ogcIcon = "C:\Windows\System32\shell32.dll,272"

# Folder structure
$folders = @($parentFolder, $backupFolder, $registryBackup, $downloadsFolder, $configsFolder, $tempFolder, $scriptsFolder, $utilitiesFolder, $logFolder, $binDir, $desktopProfiles, $powerProfiles, $driverBackups)

# ==========================================
#             FUNCTIONS
# ==========================================

function Show-Progress {
    param (
        [string]$Message
    )
    for ($i = 1; $i -le 100; $i += 10) {
        Write-Progress -Activity $Message -Status "$i% Complete" -PercentComplete $i
        Start-Sleep -Milliseconds 300
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)] [string]$Message,
        [Parameter(Mandatory=$true)] [ValidateSet("SUCCESS","FAILURE","INFO","WARNING","ERROR")] [string]$Status,
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

function Get-WindowsVersion {
    $winVer = (Get-CimInstance Win32_OperatingSystem).Caption
    Write-Log "Detected OS: $winVer"
    
    if ($winVer -match "Windows 10 Home" -or $winVer -match "Windows 10 Pro") {
        Write-Host "Windows 10 detected." -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        Write-Host "Windows 10 is no longer supported by the OGC Windows Utility." -ForegroundColor Red
        Write-Host "Some features may not work and may corrupt system files or delete personal data." -ForegroundColor Red
        Write-Host "Continue at your own risk." -ForegroundColor Red
        Start-Sleep -Seconds 5
        Write-Host "Running in LEGACY mode..." -ForegroundColor Cyan
        Write-Log "Running in LEGACY mode (Windows 10)."
        return "Windows10"
    } elseif ($winVer -match "Windows 11 Home" -or $winVer -match "Windows 11 Pro") {
        Write-Host "Running in Windows 11 mode." -ForegroundColor Cyan
        Write-Log "Running in Windows 11 mode."
        return "Windows11"
    } else {
        Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
        Write-Log "Unsupported Windows Version: $winVer. Exiting." "ERROR"
        Start-Sleep -Seconds 2
        exit
    }
}

# Function to check if an exclusion exists in Windows Defender
function Test-ExclusionSet {
    param ([string]$path)
    $existingExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    return $existingExclusions -contains $path
}

# Function to refresh Environment Variables in the current session without restarting
function Update-SessionEnvironment {
    try {
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = $machinePath + ";" + $userPath
        Write-Log "Session environment variables updated."
    } catch {
        Write-Log "Failed to update session environment variables: $_" "ERROR"
    }
}

function Get-Url {
    param ($key)
    try {
        $configData = Get-Content -Path $script:urlsConfigPath -ErrorAction Stop | Where-Object { $_ -match "=" }
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
            Write-Log "URL key '$key' not found in urls.cfg" "ERROR"
            return $null
        }
    } catch {
        Write-Log "Failed to read URLs config: $_" "ERROR"
        return $null
    }
}

# Load URLs from urls.cfg and always update files from GitHub
function Get-Scripts {
    $scripts = @{
        "OGClaunch" = $ogclaunch
        "OGCMode" = $ogcmode
        "OGCWin" = $ogcwin
        "OGCWiz11" = $ogcwiz11
        "OGCWinBat" = $ogcwinbat
        "SysInfo" = $sysinfo
        "ProgSaveBackup" = $progsavebackup
        "EmailBackup" = $emailBackup
        "DesktopLayout" = $desktopLayout
    }

    foreach ($script in $scripts.Keys) {
        try {
            $scriptPath = $scripts[$script]
            $scriptUrl = Get-Url $script

            if ($scriptUrl) {
                # Always redownload and overwrite the scripts silently
                Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$scriptPath`" `"$scriptUrl`"" -WindowStyle Hidden -Wait -ErrorAction Stop
                Write-Log "Downloaded/Updated script: $script"
            }
        } catch {
            Write-Log "Failed to download script '$script': $_" "ERROR"
        }
    }
}

# Function to create a desktop shortcut for OGCWin.bat
function New-Shortcut {
    param (
        [string]$TargetPath,
        [string]$ShortcutPath,
        [string]$Description,
        [string]$IconPath
    )

    try {
        if (-Not (Test-Path $ShortcutPath)) {
            $WScriptShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = $TargetPath
            $Shortcut.Description = $Description
            $Shortcut.IconLocation = $IconPath
            $Shortcut.Save()
            Write-Log "Desktop shortcut created at $ShortcutPath"
        } else {
            Write-Log "Desktop shortcut already exists."
        }
    } catch {
        Write-Log "Failed to create desktop shortcut: $_" "ERROR"
    }
}


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
    
    # Install Microsoft.VCLibs
    if (-not (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop")) {
        Write-Host "Downloading and Installing Microsoft.VCLibs.140.00.UWPDesktop..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$script:vclibsPath`" `"$vclibsUrl`"" -NoNewWindow -Wait -ErrorAction Stop
            Add-AppxPackage -Path $script:vclibsPath -ErrorAction Stop
            Write-Log "Installed Microsoft.VCLibs.140.00.UWPDesktop"
        } catch {
            Write-Log "Failed to install Microsoft.VCLibs: $_" "ERROR"
        }
    }

    # Install Microsoft.UI.Xaml
    if (-not (Test-AppxInstalled "Microsoft.UI.Xaml.2.8")) {
        Write-Host "Downloading and Installing Microsoft.UI.Xaml.2.8..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$script:xamlPath`" `"$xamlUrl`"" -NoNewWindow -Wait -ErrorAction Stop
            Add-AppxPackage -Path $script:xamlPath -ErrorAction Stop
            Write-Log "Installed Microsoft.UI.Xaml.2.8"
        } catch {
            Write-Log "Failed to install Microsoft.UI.Xaml: $_" "ERROR"
        }
    }

    # Install WinGet
    if (-not (Test-WinGet)) {
        Write-Host "Downloading and Installing WinGet..." -ForegroundColor Yellow
        try {
            $latestRelease = Invoke-RestMethod -Uri $wingetApiUrl -ErrorAction Stop
            $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }
            $wingetUrl = $wingetAsset.browser_download_url
            $wingetPath = "$script:downloadsFolder\$($wingetAsset.name)"

            Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$wingetPath`" `"$wingetUrl`"" -NoNewWindow -Wait -ErrorAction Stop
            Add-AppxPackage -Path $wingetPath -ErrorAction Stop
            Write-Log "Installed WinGet"
        } catch {
            Write-Log "Failed to install WinGet: $_" "ERROR"
        }
    }

    # Confirm installations
    if (Test-AppxInstalled "Microsoft.VCLibs.140.00.UWPDesktop" -and `
        Test-AppxInstalled "Microsoft.UI.Xaml.2.8" -and `
        Test-WinGet) {
        Write-Host "All dependencies installed successfully." -ForegroundColor Green
        try {
            Remove-Item -Path "$script:downloadsFolder\*" -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned up download folder."
        } catch {
            Write-Log "Failed to cleanup downloads folder: $_" "WARNING"
        }
    } else {
        Write-Host "Some dependencies failed to install." -ForegroundColor Red
        Write-Log "Dependency installation check failed." "ERROR"
    }
}


# ==========================================
#        INSTALLATION & SETUP
# ==========================================

# Display Banner
Write-Color "=======================================" -ForegroundColor DarkBlue
Write-Color "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Color "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Color "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Color "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Color "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Color "                                       " -ForegroundColor Cyan
Write-Color "     OGC Windows Utility Launcher      " -ForegroundColor Yellow
Write-Color "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Color "        Created by Honest Goat         " -ForegroundColor Green
Write-Color "=======================================" -ForegroundColor DarkBlue
Start-Sleep -Seconds 1

Write-Log "Starting OGCWin Utility Launcher Setup."

# Check Windows Version
Get-WindowsVersion | Out-Null

# Ensure all necessary folders exist
foreach ($folder in $folders) {
    try {
        if (-not (Test-Path $folder)) { 
            New-Item -Path $folder -ItemType Directory -Force | Out-Null 
            Write-Log "Created directory: $folder"
        }
    } catch {
        Write-Log "Failed to create directory $folder : $_" "ERROR"
    }
}

# Add Windows Defender exclusion for OGCWin parent folder only
if (-Not (Test-ExclusionSet $parentFolder)) {
    try {
        Add-MpPreference -ExclusionPath "$parentFolder" -ErrorAction Stop
        Write-Log "Added Windows Defender exclusion for $parentFolder"
    } catch {
        Write-Log "Failed to add Windows Defender exclusion: $_" "ERROR"
    }
}

# Download config files (Always overwrite to ensure updates)
try {
    if (Test-Path $urlsConfigPath) {
        Write-Host "Updating OGCWin..." -ForegroundColor Yellow
        Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait -ErrorAction Stop
        Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$versionLocal`" `"$versionOnline`"" -NoNewWindow -Wait -ErrorAction Stop
        Write-Log "Updated config files."
    } else {
        Write-Host "Downloading OGCWin..." -ForegroundColor Yellow
        Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$urlsConfigPath`" `"$urlsConfigUrl`"" -NoNewWindow -Wait -ErrorAction Stop
        Start-Process -FilePath "curl.exe" -ArgumentList "-s -L -o `"$versionLocal`" `"$versionOnline`"" -NoNewWindow -Wait -ErrorAction Stop
        Start-Sleep -Seconds 1
        Write-Host "Installing OGCWin..." -ForegroundColor Yellow
        Write-Log "Downloaded initial config files."
    }
} catch {
    Write-Log "Failed to download config files: $_" "ERROR"
}

# Call function to update scripts
Get-Scripts

# Check for dependencies for OGCWin
Start-Sleep -Seconds 1
Write-Host "Checking for OGCWin dependencies..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

# Winget installation check
if (-not (Test-WinGet)) {
    Write-Host "WinGet is not installed. Attempting to install..." -ForegroundColor Yellow
    Write-Log "WinGet missing. Starting installation."
    Install-WinGet
    Start-Sleep -Seconds 2
    
    Update-SessionEnvironment
    Start-Sleep -Seconds 1

    if (-not (Test-WinGet)) {
        Write-Host "WinGet installation failed." -ForegroundColor Red
        Write-Host "Please manually install WinGet from the Microsoft Store and retart the Utility." -ForegroundColor Red
        Write-Host "https://apps.microsoft.com/store/detail/9NBLGGH4NNS1" -ForegroundColor Magenta
        Write-Host "Exiting Utility..." -ForegroundColor Red
        Write-Log "WinGet installation failed. Exiting." "ERROR"
        Start-Sleep -Seconds 3
        exit
    }
} else {
    Write-Host "All required dependencies are already installed." -ForegroundColor Green
    Write-Log "WinGet is already installed."
}

# Fastfetch installation check
try {
    if (-not (Get-Command "fastfetch" -ErrorAction SilentlyContinue)) {
        Write-Host "Fastfetch is not installed. Attempting to install..." -ForegroundColor Yellow
        Write-Log "Fastfetch missing. Attempting install."
        winget install --id Fastfetch-cli.Fastfetch --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity *>$null
        Update-SessionEnvironment
        Start-Sleep -Seconds 1

        if (-not (Get-Command "fastfetch" -ErrorAction SilentlyContinue)) {
            Write-Host "Fastfetch installation failed." -ForegroundColor Red
            Write-Host "Please manually install Fastfetch and restart the Utility." -ForegroundColor Red
            Write-Host "Exiting Utility..." -ForegroundColor Red
            Write-Log "Fastfetch installation failed. Exiting." "ERROR"
            Start-Sleep -Seconds 3
            exit
        }
        Write-Log "Fastfetch installed successfully."
    } else {
        Write-Host "Fastfetch is already installed." -ForegroundColor Green
        Write-Log "Fastfetch is already installed."
    }
} catch {
    Write-Log "Error during Fastfetch check/install: $_" "ERROR"
}

Write-Host "All dependencies installed." -ForegroundColor Green
Start-Sleep -Seconds 1
Write-Host ""

# Create the shortcut with the Blue Windows icon
New-Shortcut -TargetPath $ogcwinbat -ShortcutPath $desktopPath -Description "Launch OGC Windows Utility" -IconPath $ogcIcon

# Setup complete.
Write-Host "OGCWin setup complete. In the future you can launch OGCWin from the desktop shortcut." -ForegroundColor Green
Write-Log "OGCWin setup complete."
Start-Sleep -Seconds 5

# ==========================================
#        LAUNCH OGCWin MODE SELECTOR
# ==========================================

Clear-Host
try {
    Write-Log "Launching OGCMode: $ogcmode"
    & $ogcmode
} catch {
    Write-Log "Failed to launch OGCMode script: $_" "ERROR"
    Write-Host "Failed to launch OGCMode. Please check logs." -ForegroundColor Red
    Start-Sleep -Seconds 5
}