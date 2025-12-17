# ==========================================
#       OGC New Windows Setup Wizard
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

# Define Local Paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$configsFolder = Join-Path $parentFolder "configs"
$scriptsFolder = Join-Path $parentFolder "scripts"
$oneDriveUserPath = "$env:UserProfile\OneDrive"


# Configuration
$ConfigPath = Join-Path $configsFolder "urls.cfg"
$Urls = @{}

# Files and Shortcuts
$ogcwinbat = Join-Path $parentFolder "OGCWin.bat"
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "OGC Windows Utility.lnk")


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
    Write-Host "`n[$Message Complete]" -ForegroundColor Green
}

# --- Logging Function ---
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

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [string]$Type = "DWord" # Default to DWord
    )
    
    # Normalize path: Convert "HKLM\Software" to "HKLM:\Software" for PowerShell
    if ($Path -match "^HK(LM|CU|CR|U|CC)\\") {
        $Path = $Path -replace "^HK(LM|CU|CR|U|CC)\\", "HK`$1:\" 
    }

    try {
        if (-Not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        switch ($Type) {
            "REG_DWORD" { $Type = "DWord" }
            "REG_SZ"    { $Type = "String" }
            "REG_BINARY"{ $Type = "Binary" }
        }

        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    } catch {
        # Fallback to reg.exe if PowerShell fails
        # FIX: Escaped trailing backslash in regex and escaped $1 in replacement string
        $regPath = $Path -replace "^HK(LM|CU|CR|U|CC):\\", "HK`$1\"
        $regType = "REG_DWORD" # Default fallback
        if ($Type -eq "String") { $regType = "REG_SZ" }
        if ($Type -eq "Binary") { $regType = "REG_BINARY" }
        
        try {
            Start-Process -FilePath "reg.exe" -ArgumentList "add `"$regPath`" /v `"$Name`" /t $regType /d `"$Value`" /f" -NoNewWindow -Wait -ErrorAction Stop
        } catch {
            Write-Host "Failed to set $Name at $Path. Error: $_" -ForegroundColor Red
        }
    }
}

function Disable-Service {
    param ([string]$serviceName)
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $serviceName -StartupType Disabled
            Write-Host "Service '$serviceName' disabled." -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable service '$serviceName'." -ForegroundColor Red
        }
    } else {
        Write-Host "Service '$serviceName' not found." -ForegroundColor Yellow
    }
}

function Disable-ScheduledTask {
    param ([string]$taskName, [string]$taskPath = "")
    
    # Handle calls that pass a full path in the first arg or name+path
    if ($taskPath -eq "" -and $taskName -match "\") {
        try {
            schtasks /Change /TN "$taskName" /Disable | Out-Null
            Write-Host "Scheduled Task '$taskName' disabled." -ForegroundColor Green
            return
        } catch {}
    }

    if ($taskPath) {
        if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null
            Write-Host "Scheduled Task '$taskName' disabled." -ForegroundColor Green
        } else {
             Write-Host "Scheduled Task '$taskName' not found." -ForegroundColor Yellow
        }
    } else {
         try {
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-Host "Scheduled Task '$taskName' disabled." -ForegroundColor Green
         } catch {
            Write-Host "Scheduled Task '$taskName' not found or failed." -ForegroundColor Yellow
         }
    }
}

function Remove-AppxPackageAllUsers {
    param (
        [string]$PackageName
    )
    # Remove for current user
    Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
    # Remove for all users
    Get-AppxPackage -AllUsers -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    # Remove provisioned package
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$PackageName*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

function Test-AppInstallation {
    param ([string]$AppName)
    return ($null -ne (Get-AppxPackage -Name $AppName -AllUsers -ErrorAction SilentlyContinue))
}

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

# ==========================================
#             FUNCTIONS
# ==========================================

function New-RestorePoint {
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "       Creating System Restore Point   " -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan

    try {
        # Check if running in a VM
        $sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        $isVM = $sysInfo.Model -match "Virtual|VMware|VirtualBox|Hyper-V|KVM"
        
        if ($isVM) {
            Write-Host "Notice: Virtual Machine environment detected." -ForegroundColor Yellow
        }

        # Check if System Restore is enabled on C:, if not, enable it
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $restoreStatus) {
            Write-Host "System Restore is currently disabled. Attempting to enable..." -ForegroundColor Yellow
            Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
            Write-Host "Success: System Restore enabled." -ForegroundColor Green
        }
        
        # Attempt to create restore point
        Checkpoint-Computer -Description "OGC Wizard Pre-Cleanup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        # Verify success
        Write-Host "Success: Restore point 'OGC Wizard Pre-Cleanup' created." -ForegroundColor Green
        Add-Content -Path $logFile -Value "$(Get-Date) - INFO: System Restore Point created successfully." -ErrorAction SilentlyContinue

    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "WARNING: Could not create a System Restore Point." -ForegroundColor Red
        Write-Host "Error Details: $errorMessage" -ForegroundColor Yellow
        
        # Log the error
        Add-Content -Path $logFile -Value "$(Get-Date) - ERROR: Failed to create Restore Point. Details: $errorMessage" -ErrorAction SilentlyContinue
        
        # Ask user how to proceed
        Write-Host ""
        Write-Host "Would you like to continue anyway? (Y/N)" -ForegroundColor White
        $response = Read-Host "Choice"

        if ($response -match "N|n") {
            Write-Host "Aborting operation and returning to menu..." -ForegroundColor Red
            Start-Sleep -Seconds 2
            if (Test-Path $ogcmode) {
                & $ogcmode
                exit # Ensure the script stops here
            } else {
                Write-Host "Error: Could not find OGCMode.ps1 at $ogcmode" -ForegroundColor Red
                return
            }
        } else {
            Write-Host "User opted to continue without a Restore Point..." -ForegroundColor Gray
            Add-Content -Path $logFile -Value "$(Get-Date) - WARNING: User opted to continue without Restore Point." -ErrorAction SilentlyContinue
        }
    }
    Write-Host ""
}

function Install-Driver {
    param ([string]$DriverURL, [string]$DriverPath, [string]$InstallArgs)
    Write-Host "Downloading driver from $DriverURL ..." -ForegroundColor Cyan
    Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$DriverPath`" `"$DriverURL`"" -NoNewWindow -Wait
    if (Test-Path $DriverPath) {
        Write-Host "Download complete. Installing driver..." -ForegroundColor Green
        Start-Process -FilePath $DriverPath -ArgumentList $InstallArgs -NoNewWindow -Wait
        Remove-Item -Path $DriverPath -Force
        Write-Host "Driver installed successfully." -ForegroundColor Green
    } else { Write-Host "Failed to download the driver." -ForegroundColor Red }
}

# --- Module Functions ---

function Invoke-TelemetrySetup {
    Write-Host "Disabling Telemetry, Tracking, and Data Collection..." -ForegroundColor Magenta
    
    # Disable Telemetry in Registry
    $telemetryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    )

    foreach ($key in $telemetryKeys) {
        Set-RegistryValue -Path $key -Name "AllowTelemetry" -Value 0
        Set-RegistryValue -Path $key -Name "PublishUserActivities" -Value 0
    }
    Write-Host "Registry telemetry settings updated." -ForegroundColor Green

    # Disable Windows Tracking Services
    Write-Host "Disabling Tracking Services..." -ForegroundColor Magenta
    $trackingServices = @(
        "DiagTrack", "dmwappushservice", "Wecsvc", "WerSvc", "PcaSvc", "TrkWks", "lfsvc", "MapsBroker"
    )
    foreach ($service in $trackingServices) { Disable-Service -serviceName $service }
    Write-Host "Tracking Services Disabled." -ForegroundColor Green

    # Disable Microsoft Data Collection Scheduled Tasks
    Write-Host "Disabling Microsoft Data Collection Scheduled Tasks..." -ForegroundColor Magenta
    $schedulePath = "\Microsoft\Windows\Application Experience"
    $tasks = @("Microsoft Compatibility Appraiser", "ProgramDataUpdater", "StartupAppTask")
    foreach ($task in $tasks) { 
        # Using specific logic for path
        if (Get-ScheduledTask -TaskName $task -TaskPath $schedulePath -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $task -TaskPath $schedulePath | Out-Null
            Write-Host "Scheduled Task '$task' disabled." -ForegroundColor Green
        } else {
            Write-Host "Scheduled Task '$task' not found." -ForegroundColor Yellow
        }
    }
    Write-Host "Telemetry Scheduled Tasks Disabled." -ForegroundColor Green

    # Disable Cortana via Group Policy
    Write-Host "Disabling Cortana via Group Policy..." -ForegroundColor Yellow
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
    Write-Host "Cortana disabled via Group Policy." -ForegroundColor Green

    # Stop and Kill Cortana Process
    Write-Host "Stopping and killing Cortana processes..." -ForegroundColor Yellow
    Stop-Process -Name "Cortana" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "SearchUI" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Uninstall Cortana
    Write-Host "Uninstalling Cortana..." -ForegroundColor Yellow
    Remove-AppxPackageAllUsers -PackageName "Microsoft.549981C3F5F10"
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Cortana*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    Write-Host "Cortana uninstalled successfully." -ForegroundColor Green

    # Remove Remaining Cortana Directories
    Write-Host "Removing leftover Cortana folders..." -ForegroundColor Yellow
    Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.549981C3F5F10" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Cortana" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:APPDATA\Microsoft\Cortana" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove Cortana from Startup and Registry
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Cortana" /f 2>$null
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Cortana" /f 2>$null
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null
    reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null

    # Block Cortana
    Write-Host "Preventing Cortana from reinstalling..." -ForegroundColor Yellow
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Cortana" -Name "DisableCortana" -Value 1
    Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Search" -Name "AllowCortana" -Value 0
    Write-Host "Cortana is blocked from reinstalling." -ForegroundColor Green

    # Disable Location Tracking
    Write-Host "Disabling Location Tracking..." -ForegroundColor Magenta
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLocation" -Value 0
    Write-Host "Location Tracking Disabled." -ForegroundColor Green
}

function Invoke-JunkRemoval {
    Write-Host "Disabling all tips, suggestions and advertisements." -ForegroundColor Magenta 
    
    # Disable Windows Welcome Experience & Tailored Experiences
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
    
    # Disable App Suggestions & Tips
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
    
    # Disable Ads in File Explorer & Notifications
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0
    
    # Disable various SubscribedContent
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353702Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0

    # Lock Screen
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0
    
    # Consumer Features (Candy Crush etc)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1

    # Notifications
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.MicrosoftAccount" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\WindowsUpdateClient" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\OneDrive" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\OfficeHub" -Name "Enabled" -Value 0

    # Ink Workspace
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "SuggestedAppsEnabled" -Value 0

    Write-Host "Tips and suggestions have now been disabled." -ForegroundColor Green
    Start-Sleep -Seconds 1
    Write-Host "Your privacy has been enhanced. Tracking, telemetry, data collection and suggestions have been disabled!" -ForegroundColor Green
}

function Invoke-DNSBlocking {
    $blockTelemetry = Read-Host "Do you want to block major Microsoft tracking and telemetry domains? [Recommended] (y/n)"
    if ($blockTelemetry -eq "y") {
        Write-Host "Blocking Telemetry Domains via Hosts File..." -ForegroundColor Magenta

        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $backupPath = "$hostsPath.bak"
        $tempFolder = "$env:TEMP\hosts.temp"

        $telemetryDomains = @(
            "vortex.data.microsoft.com", "settings-win.data.microsoft.com", "telemetry.microsoft.com",
            "watson.telemetry.microsoft.com", "telemetry.appex.bing.net", "telemetry.urs.microsoft.com",
            "settings-sandbox.data.microsoft.com", "statsfe2.ws.microsoft.com", "diagnostics.support.microsoft.com",
            "feedback.windows.com", "rad.msn.com", "ad.doubleclick.net", "ads.msn.com"
        )

        # Temporarily disable Windows Defender real-time protection
        Write-Host "Temporarily disabling Windows Defender real-time protection..." -ForegroundColor Yellow
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

        # Kill locking processes
        $processesToKill = @("MpCmdRun", "MsMpEng", "smartscreen", "MicrosoftEdge", "msedge", "browser_broker")
        foreach ($proc in $processesToKill) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
        
        # Take ownership
        Write-Host "Taking ownership of the hosts file..." -ForegroundColor Yellow
        takeown /f $hostsPath /a > $null
        icacls $hostsPath /grant Administrators:F /c /l /q > $null

        # Backup
        if (-Not (Test-Path $backupPath)) { Copy-Item -Path $hostsPath -Destination $backupPath -Force }

        try { $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop } catch {
            Write-Host "ERROR: Failed to read the hosts file." -ForegroundColor Red; return
        }

        # Create Temp
        Copy-Item -Path $hostsPath -Destination $tempFolder -Force

        foreach ($domain in $telemetryDomains) {
            $entry = "0.0.0.0 $domain"
            if ($hostsContent -notcontains $entry) {
                Write-Host "Adding $domain to hosts file..." -ForegroundColor Green
                Add-Content -Path $tempFolder -Value $entry
            } else {
                Write-Host "$domain is already present." -ForegroundColor Yellow
            }
        }

        Move-Item -Path $tempFolder -Destination $hostsPath -Force

        # Restore Defender
        Write-Host "Re-enabling Windows Defender real-time protection..." -ForegroundColor Yellow
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

        Write-Host "Telemetry domains have been blocked via the hosts file." -ForegroundColor Green
    } else {
        Write-Host "Skipping the blocking of telemetry domains." -ForegroundColor Cyan
    }
}

function Invoke-SecurityEnhancement {
    Write-Host "Configuring Adobe Acrobat Reader Protected View to 'All Files'..." -ForegroundColor Cyan
    Set-RegistryValue -Path "HKCU:\Software\Adobe\Acrobat Reader\DC\Privileged" -Name "bProtectedMode" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Adobe\Acrobat Reader\DC\Privileged" -Name "bProtectedView" -Value 2
    Write-Host "Adobe Acrobat Reader Protected View set to 'All Files'." -ForegroundColor Green

    Write-Host "Disabling Wi-Fi Sense and auto-connect to open networks..." -ForegroundColor Cyan
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseCredShared" -Value 0
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseOpen" -Value 0
    Write-Host "Wi-Fi Sense disabled." -ForegroundColor Green

    Write-Host "Setting User Account Control (UAC) to default level..." -ForegroundColor Cyan
    $uacRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegistryValue -Path $uacRegPath -Name "EnableLUA" -Value 1
    Set-RegistryValue -Path $uacRegPath -Name "ConsentPromptBehaviorAdmin" -Value 5
    Set-RegistryValue -Path $uacRegPath -Name "PromptOnSecureDesktop" -Value 1
    Write-Host "UAC set to default." -ForegroundColor Green

    Write-Host "Checking Secure Boot status..." -ForegroundColor Cyan
    try {
        $sbStatus = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sbStatus) {
            Write-Host "Secure Boot is enabled." -ForegroundColor Green
        } else {
            Write-Host "!! Secure Boot is DISABLED. Please enable it in BIOS !!" -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
    } catch {
        # Fallback to registry check
        $secureBootState = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "SecureBootEnabled" -ErrorAction SilentlyContinue
        if ($secureBootState -and $secureBootState.SecureBootEnabled -eq 1) {
             Write-Host "Secure Boot is enabled (Registry Check)." -ForegroundColor Green
        } elseif ($secureBootState -and $secureBootState.SecureBootEnabled -eq 0) {
             Write-Host "!! Secure Boot is DISABLED (Registry Check). Please enable it in BIOS !!" -ForegroundColor Red
             Start-Sleep -Seconds 3
        } else {
             Write-Host "Could not determine Secure Boot status." -ForegroundColor Yellow
        }
    }

    Write-Host "Disabling SMBv1 Protocol..." -ForegroundColor Magenta
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
    Write-Host "SMBv1 Protocol disabled." -ForegroundColor Green

    Write-Host "Disabling the built-in Administrator account..." -ForegroundColor Cyan
    if ((Get-LocalUser -Name "Administrator").Enabled) {
        Disable-LocalUser -Name "Administrator"
        Write-Host "Built-in Administrator account has been disabled." -ForegroundColor Green
    } else {
        Write-Host "Built-in Administrator account is already disabled." -ForegroundColor Yellow
    }

    Write-Host "Enabling verbose logon messages..." -ForegroundColor Cyan
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1
    Write-Host "Verbose logon messages enabled." -ForegroundColor Green

    Write-Host "Security configurations have been applied successfully." -ForegroundColor Green
}

function Invoke-BloatwareRemoval {
    $removeBloatware = Read-Host "Do you want to remove preinstalled advertising apps and bloatware? [Recommended] (y/n)"
    if ($removeBloatware -eq "y") {
        Write-Host "Removing Preinstalled Advertising Apps..." -ForegroundColor Magenta
        $crapware = @(
            "LinkedInforWindows", "Microsoft.3DBuilder", "Microsoft.BingWeather", "Microsoft.GetHelp",
            "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftStickyNotes", "Microsoft.MicrosoftWhiteboard",
            "Microsoft.MixedReality.Portal", "Microsoft.News", "Microsoft.Office.OneNote", "Microsoft.OneConnect",
            "Microsoft.OneNote", "Microsoft.Paint3D", "Microsoft.People", "Microsoft.Print3D", "Microsoft.ScreenSketch",
            "Microsoft.SkypeApp", "Microsoft.Todos", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera",
            "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.WindowsCommunicationsApps"
        )

        foreach ($app in $crapware) {
            $removed = $false
            if (Test-AppInstallation $app) {
                Remove-AppxPackageAllUsers $app
                $removed = $true
            } else {
                # Fallback checks (DISM/Provisioned) handled in Remove-AppxPackageAllUsers mostly, but checking logic
                $dismOutput = dism /Online /Remove-ProvisionedAppxPackage /PackageName:$app /Quiet 2>&1
                if ($dismOutput -match "successfully removed") { $removed = $true }
            }
            if ($removed) { Write-Host "$app successfully removed." -ForegroundColor Green }
        }
        Write-Host "Preinstalled advertising apps and bloatware removed." -ForegroundColor Green
    } else {
        Write-Host "Skipping bloatware removal." -ForegroundColor Cyan
    }

    $disableBingSearch = Read-Host "Do you want to disable Bing Search integration in the Start Menu? [Recommended] (y/n)"
    if ($disableBingSearch -match "^[Yy]$") {
        Write-Host "Disabling Bing Search in the Start Menu..." -ForegroundColor Yellow
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
        Write-Host "Bing Search integration disabled." -ForegroundColor Green
    } else {
        Write-Host "Keeping Bing Search enabled." -ForegroundColor Cyan
    }
}

function Invoke-YourPhoneSetup {
    $useYourPhone = Read-Host "Do you want to use the 'Your Phone' app to integrate your phone with Windows? (y/n)"
    $yourPhoneInstalled = Get-AppxPackage -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue

    if ($useYourPhone -eq "y") {
        if ($yourPhoneInstalled) {
            Write-Host "'Your Phone' app is already installed." -ForegroundColor Green
        } else {
            Write-Host "Installing 'Your Phone' app..." -ForegroundColor Yellow
            try {
                winget install --id Microsoft.YourPhone -e --silent --accept-package-agreements --accept-source-agreements
                Write-Host "'Your Phone' app installed successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to install 'Your Phone' app. Error: $_" -ForegroundColor Red
            }
        }
    } elseif ($useYourPhone -eq "n") {
        if ($yourPhoneInstalled) {
            Write-Host "Removing 'Your Phone' app..." -ForegroundColor Magenta
            Remove-AppxPackageAllUsers "Microsoft.YourPhone"
            Write-Host "'Your Phone' app removed." -ForegroundColor Green
        } else {
            Write-Host "'Your Phone' app is not installed." -ForegroundColor Cyan
        }
    }
}

# ==========================================
#             FUNCTIONS
# ==========================================

function Invoke-XboxSetup {
    Write-Host "Initializing Xbox Services..." -ForegroundColor Cyan
    $ErrorActionPreference = "Stop"
    $mod = "XboxSetup"

    # App Definitions
    $coreApps = @{
        "Microsoft.XboxIdentityProvider" = "Microsoft.XboxIdentityProvider"; "Microsoft.Xbox.TCUI" = "Microsoft.Xbox.TCUI"
        "Microsoft.GamingServices" = "9NZKPSTSNW4P"; "Microsoft.GamingApp" = "9MWPM2CQNLHN"
    }
    $barApps = @{
        "Microsoft.XboxGamingOverlay" = "9NMPJ99VJMLH"; "Microsoft.XboxGameOverlay" = "Microsoft.XboxGameOverlay"
        "Microsoft.XboxSpeechToTextOverlay" = "Microsoft.XboxSpeechToTextOverlay"
    }

    # -- Internal Helpers --

    function Test-XboxAppInstalled { param([string]$Name) return [bool](Get-AppxPackage -Name $Name -ErrorAction SilentlyContinue) }

    function Install-XboxApp {
        param([string]$Name, [string]$ID)
        Write-Host "Processing: $Name..." -ForegroundColor DarkGray
        
        if (Test-XboxAppInstalled $Name) {
            Write-Log -Message "$Name is already good to go." -Status "INFO" -Module $mod
            return
        }

        # Method 1: Local Registration (Offline)
        try {
            $pkg = Get-AppxPackage -AllUsers -Name $Name -ErrorAction SilentlyContinue
            if ($pkg) {
                Add-AppxPackage -Register "$($pkg.InstallLocation)\AppxManifest.xml" -DisableDevelopmentMode -ForceApplicationShutdown
                Write-Host "  -> Found local files and hooked them up." -ForegroundColor Green
                Write-Log -Message "Restored $Name from local files." -Status "SUCCESS" -Module $mod
                return
            }
        } catch { Write-Log -Message "Couldn't restore $Name locally. Trying download..." -Status "WARNING" -Module $mod }

        # Method 2: Winget Download (Silent)
        try {
            if ($ID -match "^[0-9A-Z]{12}$") {
                Write-Host "  -> Downloading fresh copy (Silent)..." -ForegroundColor Yellow
                Start-Process -FilePath "winget" -ArgumentList "install --id $ID --source msstore --accept-package-agreements --accept-source-agreements --silent" -Wait -NoNewWindow
                
                if (Test-XboxAppInstalled $Name) {
                    Write-Host "  -> Install success." -ForegroundColor Green
                    Write-Log -Message "Freshly installed $Name from server." -Status "SUCCESS" -Module $mod
                } else { throw "Download finished but app is missing." }
            } else {
                Write-Host "  -> No download ID available." -ForegroundColor Red
                Write-Log -Message "Skipped download for $Name (No ID)." -Status "FAILURE" -Module $mod
            }
        } catch {
            Write-Host "  -> Failed to install." -ForegroundColor Red
            Write-Log -Message "Could not install $Name. $_" -Status "FAILURE" -Module $mod
        }
    }

    function Remove-XboxApp {
        param([string]$Name)
        try {
            if (Test-XboxAppInstalled $Name) {
                Get-AppxPackage -AllUsers -Name $Name | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                Write-Host "  -> Trashed: $Name" -ForegroundColor Magenta
                Write-Log -Message "Removed $Name." -Status "SUCCESS" -Module $mod
            }
        } catch { Write-Log -Message "Had trouble removing $Name." -Status "FAILURE" -Module $mod }
    }

    # -- Phase 1: Core Services --
    Write-Host "`n--- PHASE 1: Core Xbox & Gaming Services ---" -ForegroundColor White
    Write-Host "Required for Game Pass and logging into games." -ForegroundColor Gray
    
    if ((Read-Host "Install/Keep Core Xbox Services? (y/n)") -match "^[Yy]") {
        Write-Log -Message "User chose to keep Core Services." -Status "INFO" -Module $mod
        
        # Start Services
        Write-Host "Revving up services..." -ForegroundColor Cyan
        try {
            $svcs = "GamingServices*", "XboxGipSvc", "XboxNetApiSvc", "XblAuthManager", "XblGameSave"
            Get-Service -Name $svcs -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
            Get-Service -Name $svcs -ErrorAction SilentlyContinue | Start-Service
            Write-Log -Message "Core services running." -Status "SUCCESS" -Module $mod
        } catch { Write-Log -Message "Hiccup starting core services." -Status "WARNING" -Module $mod }

        # Install Apps
        foreach ($k in $coreApps.Keys) { Install-XboxApp -Name $k -ID $coreApps[$k] }

    } else {
        Write-Log -Message "User chose to kill Core Services." -Status "INFO" -Module $mod
        Write-Host "Nuking Core Features..." -ForegroundColor Magenta

        # Stop Services
        $svcs = "GamingServices", "GamingServicesNet", "XboxGipSvc", "XboxNetApiSvc", "XblAuthManager", "XblGameSave"
        foreach ($s in $svcs) { 
            try { Stop-Service $s -Force -EA 0; Set-Service $s -StartupType Disabled -EA 0 } catch {} 
        }

        # Remove Apps & Clean Up
        foreach ($k in $coreApps.Keys) { Remove-XboxApp -Name $k }
        
        $regs = "HKCU\Software\Microsoft\Xbox", "HKCU\Software\Microsoft\GamingServices", "HKLM\SOFTWARE\Microsoft\GamingServices"
        foreach ($r in $regs) { try { Remove-Item "Registry::$r" -Recurse -Force -EA 0 } catch {} }
        
        $dirs = "$env:LOCALAPPDATA\Packages\Microsoft.GamingApp*", "$env:LOCALAPPDATA\Microsoft\Xbox", "$env:ProgramData\Microsoft\Xbox"
        foreach ($d in $dirs) { if (Test-Path $d) { Remove-Item $d -Recurse -Force -EA 0 } }
    }

    # -- Phase 2: Game Bar --
    Write-Host "`n--- PHASE 2: Game Bar & Overlays ---" -ForegroundColor White
    Write-Host "The 'Win+G' overlay and screen recorder." -ForegroundColor Gray

    if ((Read-Host "Install/Keep Game Bar? (y/n)") -match "^[Yy]") {
        Write-Log -Message "User chose to keep Game Bar." -Status "INFO" -Module $mod
        
        # Enable Reg
        try {
            New-ItemProperty "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 1 -PropertyType DWORD -Force -EA 0 | Out-Null
            New-ItemProperty "HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -PropertyType DWORD -Force -EA 0 | Out-Null
            Write-Log -Message "GameDVR turned on in registry." -Status "SUCCESS" -Module $mod
        } catch { Write-Log -Message "Couldn't flip GameDVR registry switch." -Status "FAILURE" -Module $mod }

        foreach ($k in $barApps.Keys) { Install-XboxApp -Name $k -ID $barApps[$k] }

    } else {
        Write-Log -Message "User chose to kill Game Bar." -Status "INFO" -Module $mod
        Write-Host "Removing Game Bar..." -ForegroundColor Magenta

        # Disable Reg
        try {
            New-ItemProperty "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWORD -Force -EA 0 | Out-Null
            New-ItemProperty "HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWORD -Force -EA 0 | Out-Null
        } catch {}

        foreach ($k in $barApps.Keys) { Remove-XboxApp -Name $k }

        $regs = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "HKCU\Software\Microsoft\GameBar"
        foreach ($r in $regs) { try { Remove-Item "Registry::$r" -Recurse -Force -EA 0 } catch {} }
    }

    Write-Host "`nXbox settings updated." -ForegroundColor Green
    Write-Log -Message "Xbox setup finished." -Status "INFO" -Module $mod
    Start-Sleep -Seconds 2
}    

function Invoke-OneDriveRemoval {
    
    
    # Check if OneDrive is effectively installed (Folder exists or Process exists)
    $isInstalled = (Test-Path $oneDriveUserPath) -or (Get-Process "OneDrive" -ErrorAction SilentlyContinue)

    if ($isInstalled) {
        # --- REMOVAL MODE ---
        Write-Color "Microsoft OneDrive detected." "Cyan"
        $choice = Read-Host "Do you want to copy your personal files to local folders and forcefully REMOVE OneDrive? (y/n)"
        if ($choice -ne "y") { return }

        Write-Color "INITIALIZING REMOVAL PROTOCOL..." "Magenta"
        Write-Log "Starting OneDrive Removal Protocol." "INFO"

        # 1. Stop Processes (Forcefully)
        Write-Color "Stopping OneDrive and Explorer services to release file locks..." "Yellow"
        Write-Log "Terminating processes." "INFO"
        
        try {
            Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
            taskkill /F /IM OneDrive.exe > $null 2>&1
            Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        } catch {
            Write-Log "Error stopping processes: $_" "ERROR"
        }

        # 2. Data Migration (Robocopy Copy Mode)
        Write-Color "Migrating files to local user folders..." "Cyan"
        
        $migrationSuccess = $true
        
        # Physical folder mapping for Migration (Source -> Destination)
        # We only move the actual data containers here, registry names are handled later.
        $physicalFolderMap = @{
            "Desktop"   = "$env:UserProfile\Desktop"
            "Documents" = "$env:UserProfile\Documents"
            "Pictures"  = "$env:UserProfile\Pictures"
            "Music"     = "$env:UserProfile\Music"
            "Videos"    = "$env:UserProfile\Videos"
            "Downloads" = "$env:UserProfile\Downloads"
        }

        # Backup leftovers location
        $leftoverBackup = "$backupFolder\Onedrive Files"
        if (!(Test-Path $leftoverBackup)) { New-Item -Path $leftoverBackup -ItemType Directory -Force | Out-Null }

        foreach ($folderName in $physicalFolderMap.Keys) {
            $source = "$oneDriveUserPath\$folderName"
            $dest = $physicalFolderMap[$folderName]

            if (Test-Path $source) {
                Write-Host "Migrating $folderName..." -ForegroundColor Gray
                Write-Log "Robocopy Start: $source -> $dest" "INFO"
                
                # Create destination if missing
                if (!(Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }

                # Robocopy /E (Recurse) /COPY:DAT (Data/Attributes/Time) /R:3 /W:3 (Retry/Wait) /NP (No Progress) /NFL /NDL (No File/Dir List)
                $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList "`"$source`" `"$dest`" /E /COPY:DAT /R:3 /W:3 /NP /NFL /NDL" -NoNewWindow -PassThru -Wait
                
                # Robocopy Exit Codes: 0-7 are success/partial success. 8+ is failure.
                if ($proc.ExitCode -ge 8) {
                    Write-Color "CRITICAL ERROR COPYING $folderName. Aborting." "Red"
                    Write-Log "Robocopy Failed for $folderName. Exit Code: $($proc.ExitCode)" "ERROR"
                    $migrationSuccess = $false
                    break
                }
            }
        }

        # 3. Handle Leftovers
        if ($migrationSuccess) {
            Write-Host "Backing up remaining OneDrive files..." -ForegroundColor Gray
            Write-Log "Scanning for leftovers in root OneDrive folder." "INFO"
            
            # Get all items in OneDrive root that match the known folder names so we can EXCLUDE them
            $excludedNames = $physicalFolderMap.Keys
            
            # Robocopy Root -> Backup, excluding the standard folders we already moved
            $argsList = "`"$oneDriveUserPath`" `"$leftoverBackup`" /E /COPY:DAT /XD $($excludedNames -join ' ') /R:3 /W:3 /NP /NFL /NDL"
            $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $argsList -NoNewWindow -PassThru -Wait
            
            if ($proc.ExitCode -ge 8) {
                Write-Color "Error backing up leftover files." "Red"
                Write-Log "Robocopy Leftovers Failed. Exit Code: $($proc.ExitCode)" "ERROR"
                $migrationSuccess = $false
            }
        }

        # 4. Verification and Revert/Commit
        if (-not $migrationSuccess) {
            Write-Color "DATA MIGRATION FAILED. REVERTING CHANGES..." "Red"
            Write-Log "Migration failed. Restarting Explorer. No uninstalls performed." "CRITICAL"
            Start-Process "explorer.exe"
            Write-Host "Explorer restarted. OneDrive was NOT removed to ensure data safety." -ForegroundColor Yellow
            Write-Host "Check logs at: $logFile" -ForegroundColor Yellow
            return
        }

        Write-Color "Data migration verified successfully." "Green"
        Write-Log "Data migration success. Proceeding to Uninstall." "INFO"

        # 5. Update Registry (Shell Folders)
        Write-Host "Restoring Windows Shell Folders to defaults..." -ForegroundColor Cyan
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        
        # Extended list of registry keys including legacy names
        $shellFolders = @{
            "Desktop"     = "$env:USERPROFILE\Desktop"
            "Documents"   = "$env:USERPROFILE\Documents"
            "Personal"    = "$env:USERPROFILE\Documents"
            "Downloads"   = "$env:USERPROFILE\Downloads"
            "Music"       = "$env:USERPROFILE\Music"
            "My Music"    = "$env:USERPROFILE\Music"
            "Pictures"    = "$env:USERPROFILE\Pictures"
            "My Pictures" = "$env:USERPROFILE\Pictures"
            "Videos"      = "$env:USERPROFILE\Videos"
            "My Video"    = "$env:USERPROFILE\Videos"
        }

        foreach ($key in $shellFolders.Keys) {
            $defaultPath = $shellFolders[$key]
            # Ensure the target path exists before setting registry
            if (!(Test-Path $defaultPath)) { New-Item -Path $defaultPath -ItemType Directory -Force | Out-Null }
            
            Set-ItemProperty -Path $regPath -Name $key -Value $defaultPath -Force -ErrorAction SilentlyContinue
        }

        # 6. Uninstall and Cleanup
        Write-Host "Uninstalling OneDrive application..." -ForegroundColor Cyan
        
        $uninstallStrings = @(
            "$env:SystemRoot\System32\OneDriveSetup.exe",
            "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        )
        foreach ($exe in $uninstallStrings) {
            if (Test-Path $exe) {
                Start-Process -FilePath $exe -ArgumentList "/uninstall" -NoNewWindow -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
        }
        
        # Winget / Appx cleanup
        try { winget uninstall --id Microsoft.OneDrive --silent --accept-package-agreements --accept-source-agreements > $null 2>&1 } catch {}
        Remove-AppxPackageAllUsers "Microsoft.OneDrive"

        # Registry Cleanup
        reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f 2>$null
        reg delete "HKCU\Software\Microsoft\OneDrive" /f 2>$null
        
        # Disable via Policy
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force

        # 7. Final Folder Cleanup (Destruction)
        # Only delete if migration was marked success
        if (Test-Path $oneDriveUserPath) {
            Write-Host "Removing old OneDrive folder..." -ForegroundColor Gray
            Remove-Item -Path $oneDriveUserPath -Recurse -Force -ErrorAction SilentlyContinue
        }

        # Restart Explorer to apply registry changes
        Start-Process "explorer.exe"
        Write-Color "ONEDRIVE REMOVED AND DATA MIGRATED SUCCESSFULLY." "Green"
        Write-Log "OneDrive removal complete." "INFO"
        Start-Sleep -Seconds 3

    } else {
        # --- INSTALLATION MODE ---
        Write-Color "OneDrive is NOT installed." "Yellow"
        $choice = Read-Host "Do you want to INSTALL OneDrive and set it as default? (y/n)"
        if ($choice -ne "y") { return }

        Write-Color "DOWNLOADING AND INSTALLING ONEDRIVE..." "Magenta"
        Write-Log "Starting OneDrive Installation." "INFO"

        $setupPath = "$downloadsFolder\OneDriveSetup.exe"
        try {
            Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=823054" -OutFile $setupPath
            Start-Process -FilePath $setupPath -ArgumentList "/silent" -Wait -NoNewWindow
        } catch {
            Write-Color "Download or Install failed." "Red"
            Write-Log "Install failed: $_" "ERROR"
            return
        }

        # Remove the Disable Policy
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue

        # Update Registry to point to OneDrive
        Write-Host "Updating User Shell Folders to OneDrive..." -ForegroundColor Cyan
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $odMap = @{
            "Desktop"   = "$env:UserProfile\OneDrive\Desktop"
            "Documents" = "$env:UserProfile\OneDrive\Documents"
            "Pictures"  = "$env:UserProfile\OneDrive\Pictures"
            "Personal"  = "$env:UserProfile\OneDrive\Documents" # Personal is Docs
        }

        foreach ($key in $odMap.Keys) {
            # Create folder if it doesn't exist yet (OneDrive might take a moment to sync)
            if (!(Test-Path $odMap[$key])) { New-Item -Path $odMap[$key] -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name $key -Value $odMap[$key] -Force -ErrorAction SilentlyContinue
        }

        Write-Color "ONEDRIVE INSTALLED SUCCESSFULLY." "Green"
        Write-Log "OneDrive install complete." "INFO"
        
        # Restart explorer to refresh icons
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Start-Process "explorer.exe"
    }
}

function Invoke-TeamsRemoval {
    $removeTeams = Read-Host "Do you want to completely remove Microsoft Teams? [Recommended] (y/n)"
    if ($removeTeams -eq "y") {
        Write-Host "FORCEFULLY REMOVING MICROSOFT TEAMS..." -ForegroundColor Magenta
        $teamsProcesses = @("Teams", "Teams.exe", "Update.exe", "TeamsMachineUninstaller", "msteams")
        foreach ($proc in $teamsProcesses) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2

        winget source remove msstore > $null 2>&1
        try { winget uninstall --id Microsoft.Teams --silent --accept-source-agreements > $null 2>&1 } catch {}
        winget source reset --force > $null 2>&1
        Remove-AppxPackageAllUsers "MicrosoftTeams"

        $teamsInstallerPath = "C:\Program Files (x86)\Teams Installer\Teams.exe"
        if (Test-Path $teamsInstallerPath) { Start-Process -FilePath $teamsInstallerPath -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue }

        $teamsFolders = @(
            "$env:LOCALAPPDATA\Microsoft\Teams", "$env:APPDATA\Microsoft\Teams", "$env:ProgramData\Microsoft\Teams",
            "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe", "$env:ProgramFiles\Microsoft\Teams", "$env:ProgramFiles (x86)\Microsoft\Teams",
            "$env:USERPROFILE\AppData\Local\Microsoft\Teams", "$env:USERPROFILE\AppData\Roaming\Microsoft\Teams", "$env:ProgramFiles\Common Files\Microsoft Teams", "C:\ProgramData\Microsoft\Teams"
        )
        foreach ($folder in $teamsFolders) { if (Test-Path $folder) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } }

        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Teams" /f 2>$null
        reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Teams" /f 2>$null

        $teamsRegistryKeys = @("HKCU\Software\Microsoft\Office\Teams", "HKCU\Software\Microsoft\Teams", "HKLM\Software\Microsoft\Teams", "HKLM\Software\WOW6432Node\Microsoft\Teams", "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams", "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams")
        foreach ($key in $teamsRegistryKeys) { reg delete $key /f 2>$null }

        Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1

        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Office\Teams" -Name "PreventTeamsInstallation" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Teams" -Name "PreventTeamsAutoInstall" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\WOW6432Node\Policies\Microsoft\Office\Teams" -Name "PreventTeamsInstallation" -Value 1
        
        Write-Host "MICROSOFT TEAMS HAS BEEN COMPLETELY REMOVED!" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Keeping Microsoft Teams." -ForegroundColor Cyan
    }
}

function Invoke-AIRemoval {
    $removeCopilot = Read-Host "Do you want to completely remove Microsoft Copilot? [Recommended] (y/n)"
    if ($removeCopilot -eq "y") {
        Write-Host "FORCEFULLY REMOVING MICROSOFT COPILOT..." -ForegroundColor Magenta
        Write-Log -Message "Starting Microsoft Copilot removal."
        
        try {
            Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "AllowNewsAndInterests" -Value 0
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "AllowCopilotInWindows" -Value 0
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "EnableCopilotButton" -Value 0
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Copilot" -Name "DisableCopilot" -Value 1
        } catch {
            Write-Log -Message "Error setting Copilot registry policies: $($_.Exception.Message)" -Type "ERROR"
        }

        $copilotProcesses = @("Copilot", "Copilot.exe", "AI.exe", "CopilotRuntime", "CopilotBackground", "Microsoft365Copilot", "Microsoft365Copilot.exe")
        foreach ($proc in $copilotProcesses) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
        
        try { 
            winget uninstall --id "Microsoft.Copilot" --silent --accept-source-agreements *>$null 
            winget uninstall --id "Microsoft.365.Copilot" --silent --accept-source-agreements *>$null 
        } catch {
            Write-Log -Message "Winget uninstall encountered an issue or app not found." -Type "INFO"
        }
        
        $copilotPackages = @("Microsoft.Windows.AI.Copilot", "Microsoft.Copilot", "Microsoft.365.Copilot")
        foreach ($package in $copilotPackages) { try { Remove-AppxPackageAllUsers $package } catch { Write-Log -Message "Failed to remove Appx: $package" -Type "INFO" } }

        $officeUninstallPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
        if (Test-Path $officeUninstallPath) { 
            try { 
                Start-Process -FilePath $officeUninstallPath -ArgumentList "/uninstall Copilot /quiet /norestart" -NoNewWindow -Wait -ErrorAction Stop 
            } catch {
                Write-Log -Message "Office C2R uninstall command failed: $($_.Exception.Message)" -Type "ERROR"
            } 
        }

        try {
            $msiCopilot = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Copilot%'" -ErrorAction SilentlyContinue
            if ($msiCopilot) { foreach ($app in $msiCopilot) { $app.Uninstall() } }
        } catch {
            Write-Log -Message "MSI uninstall failed: $($_.Exception.Message)" -Type "ERROR"
        }

        $copilotFolders = @("$env:LOCALAPPDATA\Packages\Microsoft.Windows.AI.Copilot", "$env:ProgramData\Microsoft\Windows\AI\Copilot", "$env:APPDATA\Microsoft\Copilot", "$env:ProgramFiles\Microsoft\Copilot", "$env:ProgramFiles (x86)\Microsoft\Copilot", "C:\ProgramData\Microsoft\Copilot")
        foreach ($folder in $copilotFolders) { if (Test-Path $folder) { try { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } catch {} } }

        try {
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
            reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
            $copilotRegistryKeys = @("HKCU\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Copilot", "HKCU\Software\Microsoft\Office\Copilot", "HKLM\Software\Microsoft\Office\Copilot")
            foreach ($key in $copilotRegistryKeys) { reg delete $key /f 2>$null }
        } catch {
            Write-Log -Message "Registry cleanup error: $($_.Exception.Message)" -Type "ERROR"
        }
        
        Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden

        Write-Host "MICROSOFT COPILOT HAS BEEN COMPLETELY REMOVED!" -ForegroundColor Green
        Write-Log -Message "Microsoft Copilot removed successfully."
    } else {
        Write-Host "Keeping Microsoft Copilot." -ForegroundColor Cyan
    }

    $removeRecall = Read-Host "Do you want to remove Microsoft Recall? [Recommended] (y/n)"
    if ($removeRecall.ToLower() -match "^y") {
        Write-Host "Disabling Microsoft Recall..." -ForegroundColor Magenta
        Write-Log -Message "Starting Microsoft Recall disablement."
        
        try {
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableWindowsAI" -Value 1
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableLogging" -Value 1
            Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableMemorySnapshots" -Value 1
            Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSearchIndexing" -Value 1
            
            # Fixed Null Argument error by using Set-ItemProperty instead of Start-Process reg.exe
            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run") {
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Recall" -Value "" -ErrorAction SilentlyContinue
            }

            $tasks = @("Microsoft\Windows\AI\Recall", "Microsoft\Windows\AI\RecallIndexing")
            foreach ($task in $tasks) {
                try { schtasks /Change /TN $task /Disable *>$null } catch { Write-Log -Message "Task $task not found or could not be disabled." -Type "INFO" }
            }
            
            Start-Process -FilePath "gpupdate" -ArgumentList "/force" -NoNewWindow -Wait
            Write-Host "Microsoft Recall fully disabled." -ForegroundColor Green
            Write-Log -Message "Microsoft Recall disabled successfully."
        } catch {
            Write-Log -Message "Error during Recall disablement: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Keeping Microsoft Recall." -ForegroundColor Cyan
    }
}

function Invoke-UIAndTaskbarSetup {
    $win10look = Read-Host "Do you want Windows 11 to look and feel like Windows 10? [Recommended] (y/n)"
    if ($win10look -eq "y") {
        Write-Host "Applying Windows 10 UI tweaks..." -ForegroundColor Magenta
        Write-Log -Message "Starting Windows 10 UI conversion."
        
        try {
            # Align Taskbar to Left
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0
            
            # Restore Classic Context Menu (Win 10 Style)
            $clsidPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
            if (-not (Test-Path $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
            if (-not (Test-Path "$clsidPath\InprocServer32")) { New-Item -Path "$clsidPath\InprocServer32" -Force | Out-Null }
            Set-ItemProperty -Path "$clsidPath\InprocServer32" -Name "(Default)" -Value "" -Force
            
            # Open Explorer to 'This PC' instead of 'Home'
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1
            
            # Disable Snap Assist Flyout (Optional but helps Win10 feel)
            Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "EnableSnapAssistFlyout" -Value 0
            
            Write-Host "Windows 10 UI tweaks applied successfully." -ForegroundColor Green
            Write-Log -Message "Windows 10 UI tweaks applied (Taskbar Left, Classic Context Menu)."
        } catch {
            Write-Log -Message "Error applying Windows 10 UI tweaks: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Skipping Windows 10 UI tweaks." -ForegroundColor Cyan
    }

    $debloatTaskbar = Read-Host "Do you want to debloat the taskbar (Remove Search, Widgets, Store)? [Recommended] (y/n)"
    if ($debloatTaskbar -eq "y") {
        Write-Host "Removing unnecessary taskbar icons..." -ForegroundColor Magenta
        Write-Log -Message "Starting Taskbar debloat."

        try {
            # Remove Task View, Search, and People
            Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
            Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0
            Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Value 0
            
            # Disable Widgets (TaskbarDa) and Feeds
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2

            # Teams/Chat Detection and Removal
            $teamsCheck = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue
            if ($teamsCheck) {
                Write-Log -Message "Teams/Chat detected. Hiding icon."
                Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0
                Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name "ChatIcon" -Value 3
            }

            # Unpin Store from Taskbar
            $taskbarStore = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Store.lnk"
            if (Test-Path $taskbarStore) { Remove-Item $taskbarStore -Force -ErrorAction SilentlyContinue }
            Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1

            # Remove Widget/News Apps
            $bloatApps = @("MicrosoftWindows.Client.WebExperience", "Microsoft.BingNews", "Microsoft.BingWeather")
            foreach ($app in $bloatApps) { try { Remove-AppxPackageAllUsers $app } catch { Write-Log -Message "Could not remove $app (may not exist)" -Type "INFO" } }

            Write-Host "Taskbar cleaned successfully." -ForegroundColor Green
            Write-Log -Message "Taskbar debloat completed."
        } catch {
            Write-Log -Message "Error during Taskbar debloat: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Skipping taskbar debloating." -ForegroundColor Cyan
    }

    $enableDarkMode = Read-Host "Do you want to enable Dark Mode? [Recommended] (y/n)"
    if ($enableDarkMode -eq "y") {
        Write-Host "Enabling Dark Mode..." -ForegroundColor Magenta
        try {
            $personalizePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $personalizePath -Name "SystemUsesLightTheme" -Value 0 -ErrorAction SilentlyContinue
            
            if (Test-Path "HKCU:\Software\Microsoft\Office\16.0\Common") {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common" -Name "UI Theme" -Value 4 -Type DWord -ErrorAction SilentlyContinue
            }
            Write-Log -Message "Dark mode enabled."
        } catch {
            Write-Log -Message "Error enabling Dark Mode: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Dark Mode not enabled." -ForegroundColor Cyan
    }
    
    # Restart Explorer to apply UI changes immediately
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

function Invoke-SystemOptimizations {
    $debloatEdge = Read-Host "Do you want to remove Edge's forced features? [Recommended] (y/n)"
    if ($debloatEdge -eq "y") {
        Write-Host "Disabling Edge forced features..." -ForegroundColor Magenta
        try {
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RestorePdfAssociationsEnabled" -Value 0
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0
            Write-Host "Edge features disabled!" -ForegroundColor Green
            Write-Log -Message "Edge forced features disabled."
        } catch {
            Write-Log -Message "Error disabling Edge features: $($_.Exception.Message)" -Type "ERROR"
        }
    }

    $gameOptimizations = Read-Host "Do you want to enable gaming features like Game Mode, VRR, HAGS? [Recommended for Gamers] (y/n)"
    if ($gameOptimizations -match "^[Yy]$") {
        Write-Host "Applying gaming optimizations..." -ForegroundColor Magenta
        try {
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GraphicsSettings" -Name "HwSchMode" -Value 2
            
            $vrrSupported = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -ErrorAction SilentlyContinue
            if ($null -ne $vrrSupported) {
                 Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -Value 1
            }
            Write-Host "Gaming features enabled!" -ForegroundColor Cyan
            Write-Log -Message "Gaming optimizations (GameMode, HAGS, VRR) applied."
        } catch {
            Write-Log -Message "Error applying gaming optimizations: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Skipping gaming optimizations." -ForegroundColor Cyan
    }

    $usbsuspend = Read-Host "Do you intend to use controllers or joysticks? [Recommended] (y/n)"
    if ($usbsuspend -match "^[Yy]$") {
        Write-Host "Disabling Selective USB Suspend..."
        try {
            powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
            Write-Log -Message "USB Selective Suspend disabled."
        } catch {
            Write-Log -Message "Error disabling USB Suspend: $($_.Exception.Message)" -Type "ERROR"
        }
    }

    $gameCompat = Read-Host "Enable Game Compatibility Mode (Long Paths + 3GB RAM support)? [Recommended - Helps older games] (y/n)"
    if ($gameCompat -match "^[Yy]$") {
        Write-Host "Enabling Game Compatibility features..." -ForegroundColor Magenta
        try {
            # Enable Long Paths
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1 -Force
            # Enable >3GB RAM for Win32 Apps
            Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set IncreaseUserVA 3072" -NoNewWindow -Wait
            
            Write-Host "Game Compatibility features enabled." -ForegroundColor Green
            Write-Log -Message "Game Compatibility (LongPaths, IncreaseUserVA) enabled."
        } catch {
            Write-Log -Message "Error enabling Game Compatibility: $($_.Exception.Message)" -Type "ERROR"
        }
    }

    $disableMemoryIsolation = Read-Host "Do you want to disable Memory Core Isolation for better gaming performance? [Recommended] (y/n)"
    if ($disableMemoryIsolation -match "^[Yy]$") {
        Write-Host "Disabling Memory Core Isolation..." -ForegroundColor Magenta
        try {
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0
            Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0
            
            # Disable Boot Hypervisor
            Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set hypervisorlaunchtype off" -NoNewWindow -Wait
            
            # Suppress "Device Security" Nags
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Value 1
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device Security" -Name "DisableDeviceSecurityUI" -Value 1
            
            Write-Host "Memory Core Isolation disabled (Restart required)." -ForegroundColor Yellow
            Write-Log -Message "Memory Core Isolation disabled and notifications suppressed."
        } catch {
            Write-Log -Message "Error disabling Memory Core Isolation: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Write-Host "Keeping Memory Core Isolation enabled." -ForegroundColor Cyan
    }

    Write-Host "Restarting Windows Explorer to apply changes..." -ForegroundColor Cyan
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
    Write-Host "Windows Explorer Restarted." -ForegroundColor Green
    
    # Desktop Shortcut
    try {
        New-Shortcut -TargetPath $script:ogcwinbat -ShortcutPath $script:desktopPath -Description "Launch OGC Windows Utility" -IconPath "C:\Windows\System32\shell32.dll,272"
        Write-Log -Message "Desktop shortcut created/updated."
    } catch {
        Write-Log -Message "Error creating desktop shortcut: $($_.Exception.Message)" -Type "ERROR"
    }
    Clear-Host
}

function Invoke-SoftwareInstallation {
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "        OGC Windows 11 Utility         " -ForegroundColor Yellow
    Write-Host "     Software Installation Wizard      " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "" 

    Write-Log "Starting Software Installation Wizard..." "INFO"

    # Internal helper to keep code clean and handle logging uniformly
    function Install-App {
        param([string]$Name, [string]$Id)
        Write-Host "Installing $Name..." -ForegroundColor Magenta
        Write-Log "Attempting to install $Name ($Id)" "INFO"
        try {
            # Renamed $args to $wingetArgs to avoid conflict with reserved automatic variables
            $wingetArgs = "install --id $Id --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
            $process = Start-Process -FilePath "winget" -ArgumentList $wingetArgs -Wait -NoNewWindow -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Host "$Name successfully installed." -ForegroundColor Green
                Write-Log "Successfully installed $Name" "INFO"
            } else {
                throw "Winget returned exit code $($process.ExitCode)"
            }
        }
        catch {
            Write-Host "Failed to install $Name. Check logs." -ForegroundColor Red
            Write-Log "Failed to install $Name. Error: $_" "ERROR"
        }
    }

    # ==========================================
    #             GAMING SECTION
    # ==========================================
    $installGamingApps = Read-Host "Do you want to install gaming apps? (y/n)"
    if ($installGamingApps -eq "y") {
        
        # Value Add: Visual C++ Check
        $installVCRedist = Read-Host "Do you want to update Visual C++ Redists (Required for most games)? (y/n)"
        if ($installVCRedist -eq "y") {
            Install-App -Name "Visual C++ 2015-2022 Redistributable" -Id "Microsoft.VCRedist.2015+.x64"
        }

        $apps = @{
            "Steam" = "Valve.Steam"; 
            "Epic Games Launcher" = "EpicGames.EpicGamesLauncher"; 
            "GOG Galaxy" = "GOG.Galaxy";
            "Discord" = "Discord.Discord"; 
            "Medal" = "Medal.TV"
        }
        
        # Use GetEnumerator to properly access Key (Name) and Value (ID)
        foreach ($app in $apps.GetEnumerator()) {
             $appName = $app.Key
             $appId = $app.Value
             if ((Read-Host "Do you want to install $appName? (y/n)") -eq "y") {
                 Install-App -Name $appName -Id $appId
             }
        }
        Write-Host "Gaming app installation process completed." -ForegroundColor Green
    }

    # ==========================================
    #         GAMING UTILITIES SECTION
    # ==========================================
    $installGamingUtilities = Read-Host "Do you want to install gaming and monitoring utilities? (y/n)"
    if ($installGamingUtilities -eq "y") {
        $utils = @{
            "HWiNFO" = "REALiX.HWiNFO"; 
            "MSI Afterburner" = "MSI.Afterburner"; 
            "RivaTuner Statistics Server (RTSS)" = "Guru3D.RTSS";
            "CPU-Z" = "CPUID.CPU-Z"; 
            "GPU-Z" = "TechPowerUp.GPU-Z"
        }
        foreach ($util in $utils.GetEnumerator()) {
            $utilName = $util.Key
            $utilId = $util.Value
            if ((Read-Host "Do you want to install $utilName? (y/n)") -eq "y") {
                Install-App -Name $utilName -Id $utilId
            }
        }
        Write-Host "Gaming and monitoring utilities installation completed." -ForegroundColor Green
    }

    # ==========================================
    #             BROWSER SECTION
    # ==========================================
    $installBrowser = Read-Host "Do you want to install a web browser? (y/n)"
    if ($installBrowser -eq "y") {
        
        # Define available browsers
        $browserList = @{
            "1" = @{ Name="Firefox"; Id="Mozilla.Firefox" };
            "2" = @{ Name="Brave"; Id="Brave.Brave" };
            "3" = @{ Name="Opera GX"; Id="Opera.OperaGX" };
            "4" = @{ Name="Chrome"; Id="Google.Chrome" };
            "5" = @{ Name="Edge"; Id="Microsoft.Edge" }
        }

        # Function to handle selection logic
        function Select-Browser {
            param ($promptText)
            Write-Host $promptText -ForegroundColor Cyan
            Write-Host "1. Firefox"
            Write-Host "2. Brave"
            Write-Host "3. Opera GX"
            Write-Host "4. Chrome"
            Write-Host "5. Edge"
            Write-Host "N. Skip"
            return Read-Host "Enter choice"
        }

        # --- Primary Browser ---
        $choice = Select-Browser "Select your PRIMARY browser to install:"
        $primaryBrowserName = $null

        if ($browserList.ContainsKey($choice)) {
            $selection = $browserList[$choice]
            Install-App -Name $selection.Name -Id $selection.Id
            $primaryBrowserName = $selection.Name
            
            # --- Set Default Browser Logic ---
            if ($primaryBrowserName -ne "Edge") {
                $setDefault = Read-Host "Do you want to set $primaryBrowserName as your default browser? (y/n)"
                if ($setDefault -eq "y") {
                    Write-Host "Instructions:" -ForegroundColor Yellow
                    Write-Host "1. Windows Settings will open to 'Default Apps'."
                    Write-Host "2. Find '$primaryBrowserName' in the list."
                    Write-Host "3. Click 'Set Default'."
                    Write-Host "Press Enter to open Settings..." -NoNewline
                    Read-Host
                    Start-Process "ms-settings:defaultapps"
                    Write-Log "User prompted to set $primaryBrowserName as default." "INFO"
                }
            }
        } elseif ($choice -ne "N") {
            Write-Host "Invalid selection." -ForegroundColor Red
        }

        # --- Edge Removal Logic ---
        # Only offer if they didn't pick Edge as primary
        if ($choice -ne "5" -and $choice -ne "N") {
            $removeEdge = Read-Host "Do you want to remove/disable Microsoft Edge? (y/n)"
            if ($removeEdge -eq "y") {
                Write-Host "WARNING: Removing Edge is mostly safe, but may break Windows Widgets, Copilot, and Web Search in Start Menu." -ForegroundColor Yellow
                $confirmEdge = Read-Host "Are you sure? (y/n)"
                if ($confirmEdge -eq "y") {
                    Write-Log "Attempting to remove Microsoft Edge." "INFO"
                    Write-Host "Locating Edge Installer..." -ForegroundColor Magenta
                    try {
                        # Method 1: Locate Setup.exe (Redundancy for Winget failure)
                        $edgeInstaller = Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Filter "setup.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                        
                        if ($edgeInstaller) {
                            Write-Host "Running Edge Uninstaller..." -ForegroundColor Magenta
                            Start-Process -FilePath $edgeInstaller.FullName -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -NoNewWindow
                            Write-Log "Executed Edge setup.exe uninstall command." "INFO"
                        } else {
                            Write-Log "Edge setup.exe not found." "WARNING"
                        }

                        # Method 2: Winget (Backup)
                        Install-App -Name "Edge Uninstall (Winget)" -Id "Microsoft.Edge" 

                        # Method 3: Clean up Shortcuts & Prevent Background Run
                        Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue
                        Remove-Item "$env:Public\Desktop\Microsoft Edge.lnk" -ErrorAction SilentlyContinue
                        
                        # Disable Edge Background processes via Registry
                        $edgeReg = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
                        if (!(Test-Path $edgeReg)) { New-Item -Path $edgeReg -Force | Out-Null }
                        Set-ItemProperty -Path $edgeReg -Name "BackgroundModeEnabled" -Value 0
                        Set-ItemProperty -Path $edgeReg -Name "StartupBoostEnabled" -Value 0
                        
                        Write-Host "Edge removal/disable tasks completed." -ForegroundColor Green
                    } catch {
                        Write-Log "Error during Edge removal: $_" "ERROR"
                    }
                }
            }
        }

        # --- Secondary Browser ---
        $installSecond = Read-Host "Do you want to install an ADDITIONAL browser? (y/n)"
        if ($installSecond -eq "y") {
            $choice2 = Select-Browser "Select your SECONDARY browser:"
            if ($browserList.ContainsKey($choice2)) {
                $selection2 = $browserList[$choice2]
                if ($selection2.Name -eq $primaryBrowserName) {
                    Write-Host "You already installed this browser." -ForegroundColor Yellow
                } else {
                    Install-App -Name $selection2.Name -Id $selection2.Id
                }
            }
        }
    }
    
    # ==========================================
    #             OFFICE SECTION
    # ==========================================
    Write-Host "Choose an office suite to install:" -ForegroundColor Cyan
    Write-Host "1. Microsoft Office (Microsoft 365/2021)"
    Write-Host "2. LibreOffice"
    Write-Host "3. OpenOffice"
    Write-Host "4. No Office Suite (Remove all)"
    Write-Host "N. Skip this section"
    $officeChoice = Read-Host "Enter your choice (1/2/3/4/N)"
    
    $selectedOffice = ""

    switch ($officeChoice) {
        "1" { 
            Install-App -Name "Microsoft Office" -Id "Microsoft.Office.Desktop" # Using Desktop ID usually better for 365
            Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub"
            $selectedOffice = "Microsoft"
        }
        "2" { 
            Install-App -Name "LibreOffice" -Id "TheDocumentFoundation.LibreOffice"
            Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub"
            $selectedOffice = "Libre"
        }
        "3" { 
            Install-App -Name "OpenOffice" -Id "Apache.OpenOffice"
            Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub"
            $selectedOffice = "Open"
        }
        "4" { $selectedOffice = "None" }
        "N" { $selectedOffice = "Skip" }
    }

    # --- Office Cleanup Logic ---
    if ($selectedOffice -ne "Skip") {
        # Define potential clutter
        $officeApps = @("Microsoft.Office.Desktop", "Microsoft.Office.OneNote", "Microsoft.OfficeHub", "Microsoft.MicrosoftOfficeHub", "Microsoft.OutlookForWindows")
        
        # If they chose a specific suite, ask to clean others?
        if ($selectedOffice -ne "None") {
            $doCleanup = Read-Host "Do you want to remove other Office suites/hubs to prevent conflicts? (y/n)"
            if ($doCleanup -eq "y") {
                Write-Host "Cleaning up conflicting Office apps..." -ForegroundColor Magenta
                foreach ($app in $officeApps) {
                    try {
                        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                        Write-Log "Removed AppxPackage: $app" "INFO"
                    } catch {}
                }
            }
        } elseif ($selectedOffice -eq "None") {
            # Full Nuke
            Write-Host "Removing all Office-related software..." -ForegroundColor Magenta
            foreach ($app in $officeApps) { Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
            
            # Remove folders
            $officeFolders = @(
                "$env:ProgramFiles\Microsoft Office", 
                "$env:ProgramFiles (x86)\Microsoft Office", 
                "$env:LOCALAPPDATA\Microsoft\Office", 
                "$env:APPDATA\Microsoft\Office"
            )
            foreach ($folder in $officeFolders) { 
                if (Test-Path $folder) { 
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue 
                    Write-Log "Removed folder: $folder" "INFO"
                } 
            }
            Write-Host "Office cleanup complete." -ForegroundColor Green
        }
    }

    # --- Telemetry & Nags (Runs if MS Office is installed or detected) ---
    $msOfficeDetected = (Test-Path "HKLM:\SOFTWARE\Microsoft\Office") -or ($selectedOffice -eq "Microsoft")
    
    if ($msOfficeDetected) {
        $disableTelemetry = Read-Host "Do you want to disable MS Office Telemetry, Data Collection, and Advertising Nags? (y/n)"
        if ($disableTelemetry -eq "y") {
            Write-Host "Applying Office Privacy tweaks..." -ForegroundColor Magenta
            try {
                $telemetryKeys = @(
                    "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry",
                    "HKCU:\Software\Microsoft\Office\16.0\Common\Feedback",
                    "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy"
                )

                # 1. Disable Telemetry via Registry
                foreach ($key in $telemetryKeys) {
                    if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                }
                
                # SendTelemetry = 1 (Disable), DisableTelemetry = 1
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Value 1 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Privacy" -Name "DisconnectedState" -Value 2 -ErrorAction SilentlyContinue
                
                # 2. Disable "Whats New" and Upsell Nags
                $commonKey = "HKCU:\Software\Microsoft\Office\16.0\Common\General"
                if (!(Test-Path $commonKey)) { New-Item -Path $commonKey -Force | Out-Null }
                Set-ItemProperty -Path $commonKey -Name "ShownFirstRunOptin" -Value 1 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $commonKey -Name "Skype4B" -Value 0 -ErrorAction SilentlyContinue

                Write-Host "Office Telemetry and Nags disabled." -ForegroundColor Green
                Write-Log "Applied MS Office Telemetry and Nag registry blocks." "INFO"
            } catch {
                Write-Log "Failed to apply Office telemetry tweaks: $_" "ERROR"
            }
        }
    }
}

function Invoke-DriverInstallation {
    Write-Log "Starting Driver Installation module..." "INFO"

    # ==========================================
    #          GRAPHICS DRIVER SECTION
    # ==========================================
    $installGPUDrivers = Read-Host "Do you want to install graphics drivers? (y/n)"
    if ($installGPUDrivers -eq "y") {
        try {
            # Hardware Detection
            Write-Host "`n--- Detecting Hardware ---" -ForegroundColor Cyan
            $cpuInfo = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
            $gpuInfo = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
            
            Write-Host "Detected CPU: $cpuInfo" -ForegroundColor Yellow
            Write-Host "Detected GPU(s): $($gpuInfo -join ', ')" -ForegroundColor Yellow
            Write-Host "--------------------------`n" -ForegroundColor Cyan

            Write-Host "Select your GPU brand to install drivers:" -ForegroundColor Cyan
            Write-Host "1. NVIDIA"
            Write-Host "2. AMD"
            Write-Host "3. Intel"
            Write-Host "N. Skip"
            $gpuChoice = Read-Host "Enter the number of your choice (1/2/3/N)"

            switch ($gpuChoice) {
                "1" { 
                    # NVIDIA Logic
                    Write-Log "User selected NVIDIA drivers." "INFO"
                    Write-Host "`n[WARNING] NVIDIA GeForce Experience (GFE)" -ForegroundColor Red
                    Write-Host "GFE contains comprehensive data collection/telemetry that tracks usage." -ForegroundColor Gray
                    Write-Host "It can also impact gaming performance." -ForegroundColor Gray
                    Write-Host "If you use GFE for game recording (ShadowPlay), consider using 'Medal.tv' or 'Steam Game Recording'." -ForegroundColor Green
                    Write-Host "OGC Utility can auto-update drivers without GFE." -ForegroundColor Green
                    
                    $installGFE = Read-Host "Do you want to install GeForce Experience? (y/n)"
                    
                    $nvidiaUrl = Get-Url "DriverNvidia"
                    $nvidiaPath = "$tempFolder\NVIDIA-Driver.exe"
                    
                    Write-Host "Downloading NVIDIA Drivers..." -ForegroundColor Cyan
                    Invoke-WebRequest -Uri $nvidiaUrl -OutFile $nvidiaPath
                    
                    Write-Host "Installing NVIDIA Drivers..." -ForegroundColor Cyan
                    # Standard silent install (-s) often forces GFE. 
                    $process = Start-Process -FilePath $nvidiaPath -ArgumentList "-s" -Wait -PassThru
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log "NVIDIA driver installed successfully." "INFO"
                    } else {
                        Write-Log "NVIDIA driver install returned exit code: $($process.ExitCode)" "WARNING"
                    }

                    if ($installGFE -ne "y") {
                        Write-Host "Removing GeForce Experience references..." -ForegroundColor Yellow
                        # Attempt to stop GFE services immediately so they don't run
                        $gfeServices = @("NvContainerLocalSystem", "NvContainerNetworkService", "NvTelemetryContainer")
                        foreach ($svc in $gfeServices) {
                            Get-Service $svc -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
                            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
                        }
                    }
                }
                "2" { 
                    # AMD Logic
                    Write-Log "User selected AMD drivers." "INFO"
                    $amdUrl = Get-Url "DriverAmd"
                    $amdPath = "$tempFolder\AMD-Driver.exe"
                    
                    Write-Host "Downloading AMD Drivers..." -ForegroundColor Cyan
                    Invoke-WebRequest -Uri $amdUrl -OutFile $amdPath
                    
                    Write-Host "Installing AMD Drivers..." -ForegroundColor Cyan
                    $process = Start-Process -FilePath $amdPath -ArgumentList "/INSTALL /SILENT" -Wait -PassThru
                     if ($process.ExitCode -eq 0) {
                        Write-Log "AMD driver installed successfully." "INFO"
                    } else {
                        Write-Log "AMD driver install returned exit code: $($process.ExitCode)" "WARNING"
                    }
                }
                "3" {
                    # Intel Logic
                    Write-Log "User selected Intel drivers." "INFO"
                    Write-Host "Select Intel Graphics Type:" -ForegroundColor Cyan
                    Write-Host "1. Intel Arc (Dedicated Graphics)"
                    Write-Host "2. Integrated Graphics (iGPU)"
                    $intelType = Read-Host "Choice (1/2)"

                    if ($intelType -eq "1") {
                        # Arc (Dedicated)
                        $arcUrl = Get-Url "DriverIntelArc"
                        $arcPath = "$tempFolder\Intel-Arc-Driver.exe"
                        Write-Host "Downloading Intel Arc Drivers..." -ForegroundColor Cyan
                        Invoke-WebRequest -Uri $arcUrl -OutFile $arcPath
                        Write-Host "Installing Intel Arc Drivers..." -ForegroundColor Cyan
                        Start-Process -FilePath $arcPath -ArgumentList "-s" -Wait
                    }
                    elseif ($intelType -eq "2") {
                        # Integrated Logic
                        Write-Host "Select your CPU Generation:" -ForegroundColor Cyan
                        Write-Host "1. Intel Core Ultra (Use Arc Driver)"
                        Write-Host "2. 11th Gen to 14th Gen"
                        Write-Host "3. 7th Gen to 10th Gen"
                        $genChoice = Read-Host "Choice (1/2/3)"

                        if ($genChoice -eq "1") {
                            # Core Ultra uses Arc Driver
                            $arcUrl = Get-Url "DriverIntelArc"
                            $arcPath = "$tempFolder\Intel-Arc-Driver.exe"
                            Write-Host "Downloading Intel Core Ultra Drivers..." -ForegroundColor Cyan
                            Invoke-WebRequest -Uri $arcUrl -OutFile $arcPath
                            Write-Host "Installing Intel Core Ultra Drivers..." -ForegroundColor Cyan
                            Start-Process -FilePath $arcPath -ArgumentList "-s" -Wait
                        }
                        elseif ($genChoice -eq "2") {
                            # 11th-14th Gen
                            $hdUrl = Get-Url "DriverIntelHd"
                            $hdPath = "$tempFolder\Intel-HD-Driver.exe"
                            Write-Host "Downloading Intel UHD/Iris Drivers (11th-14th Gen)..." -ForegroundColor Cyan
                            Invoke-WebRequest -Uri $hdUrl -OutFile $hdPath
                            Write-Host "Installing Intel Drivers..." -ForegroundColor Cyan
                            Start-Process -FilePath $hdPath -ArgumentList "-s" -Wait
                        }
                        elseif ($genChoice -eq "3") {
                            # 7th-10th Gen
                            $oldUrl = Get-Url "DriverIntelOld"
                            $oldPath = "$tempFolder\Intel-Old-Driver.exe"
                            Write-Host "Downloading Legacy Intel Drivers (7th-10th Gen)..." -ForegroundColor Cyan
                            Invoke-WebRequest -Uri $oldUrl -OutFile $oldPath
                            Write-Host "Installing Legacy Intel Drivers..." -ForegroundColor Cyan
                            Start-Process -FilePath $oldPath -ArgumentList "-s" -Wait
                        }
                    }
                }
            }
        
            # Telemetry Cleanup Prompt
            if ($gpuChoice -in "1","2","3") {
                Write-Host "`nTelemetry/Data Collection" -ForegroundColor Magenta
                Write-Host "It is highly recommended to disable telemetry to improve privacy and performance." -ForegroundColor Gray
                $disableTele = Read-Host "Do you want to disable telemetry for the installed drivers? (y/n)"
                
                if ($disableTele -eq "y") {
                    Write-Log "Starting Telemetry cleanup." "INFO"
                    Write-Host "Scanning for telemetry services..." -ForegroundColor Magenta
                    
                    # NVIDIA Telemetry
                    if (Get-Service "NvTelemetryContainer" -ErrorAction SilentlyContinue) {
                        Write-Host "Disabling NVIDIA telemetry..." -ForegroundColor Cyan
                        foreach ($s in @("NvTelemetryContainer", "NvContainerLocalSystem", "NvContainerNetworkService")) { 
                            Stop-Service $s -Force -ErrorAction SilentlyContinue
                            Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
                        }
                        foreach ($t in @("\NvTmMon", "\NvTmRep", "\NvTmRepOnLogon")) { 
                            Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue 
                        }
                        if (Test-Path "HKLM:\Software\NVIDIA Corporation\Global\NvTelemetry") {
                            Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\NvTelemetry" -Name "EnableTelemetry" -Value 0 -ErrorAction SilentlyContinue
                        }
                        Write-Log "NVIDIA telemetry disabled." "INFO"
                    }

                    # AMD Telemetry
                    if (Get-Service "AMD External Events Utility" -ErrorAction SilentlyContinue) {
                        Write-Host "Disabling AMD telemetry..." -ForegroundColor Cyan
                        Stop-Service "AMD External Events Utility" -Force -ErrorAction SilentlyContinue
                        Set-Service "AMD External Events Utility" -StartupType Disabled -ErrorAction SilentlyContinue
                        if (Test-Path "HKLM:\Software\AMD\CN") {
                            Set-ItemProperty -Path "HKLM:\Software\AMD\CN" -Name "UserExperienceProgram" -Value 0 -ErrorAction SilentlyContinue
                        }
                        Write-Log "AMD telemetry disabled." "INFO"
                    }

                    # Intel Telemetry
                    if (Get-Service "Intel(R) Surrey City Program" -ErrorAction SilentlyContinue) {
                         Write-Host "Disabling Intel telemetry..." -ForegroundColor Cyan
                         Stop-Service "Intel(R) Surrey City Program" -Force -ErrorAction SilentlyContinue
                         Set-Service "Intel(R) Surrey City Program" -StartupType Disabled -ErrorAction SilentlyContinue
                         Write-Log "Intel telemetry disabled." "INFO"
                    }
                }
            }

        } catch {
            Write-Log "Critical error in Graphics Driver section: $_" "ERROR"
            Write-Host "An error occurred installing graphics drivers. Check log for details." -ForegroundColor Red
        }
    }

    # ==========================================
    #           CHIPSET DRIVER SECTION
    # ==========================================
    $installChipset = Read-Host "`nDo you want to install Motherboard Chipset drivers? (y/n)"
    if ($installChipset -eq "y") {
        try {
            Write-Host "Select Chipset Manufacturer:" -ForegroundColor Cyan
            Write-Host "1. Intel (INF Update Utility)"
            Write-Host "2. AMD (Chipset Software)"
            $chipChoice = Read-Host "Choice (1/2)"

            if ($chipChoice -eq "1") {
                Write-Log "User selected Intel Chipset." "INFO"
                $chipUrl = Get-Url "DriverChipsetIntel"
                $chipPath = "$tempFolder\Intel-Chipset.exe"
                
                Write-Host "Downloading Intel Chipset Drivers..." -ForegroundColor Cyan
                Invoke-WebRequest -Uri $chipUrl -OutFile $chipPath
                
                Write-Host "Installing Intel Chipset INF..." -ForegroundColor Cyan
                Start-Process -FilePath $chipPath -ArgumentList "-install -restart" -Wait
                Write-Log "Intel Chipset installed." "INFO"
            }
            elseif ($chipChoice -eq "2") {
                Write-Log "User selected AMD Chipset." "INFO"
                $chipUrl = Get-Url "DriverChipsetAmd"
                $chipPath = "$tempFolder\AMD-Chipset.exe"
                
                Write-Host "Downloading AMD Chipset Drivers..." -ForegroundColor Cyan
                Invoke-WebRequest -Uri $chipUrl -OutFile $chipPath
                
                Write-Host "Installing AMD Chipset..." -ForegroundColor Cyan
                Start-Process -FilePath $chipPath -ArgumentList "/INSTALL /SILENT" -Wait
                Write-Log "AMD Chipset installed." "INFO"
            }
        } catch {
            Write-Log "Error in Chipset Driver section: $_" "ERROR"
            Write-Host "An error occurred installing chipset drivers." -ForegroundColor Red
        }
    }
}


# ==========================================
#        SELF-REPAIR & VALIDATION
# ==========================================

if (-not (Test-Path $ConfigPath)) {
    Write-Host "CRITICAL: Configuration missing. Initiating repair..." -ForegroundColor Red
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
#          MAIN PROGRAM
# ==========================================

# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "        OGC Windows 11 Utility         " -ForegroundColor Yellow
Write-Host "     Fresh Windows Install Wizard      " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "" 

Write-Host "Welcome to the OGC Fresh Windows Setup Wizard!" -ForegroundColor Cyan
Write-Host "" 
Write-Host "This utility will help you optimize your Windows installation by:" -ForegroundColor Yellow
Write-Host "- Removing unnecessary bloatware and preinstalled apps" -ForegroundColor Green
Write-Host "- Disabling telemetry, tracking, and data collection" -ForegroundColor Green
Write-Host "- Customizing Windows settings for a better gaming experience" -ForegroundColor Green
Write-Host "- Improving privacy and performance" -ForegroundColor Green
Write-Host "- Allow you to remove or install common applications." -ForegroundColor Green
Write-Host "" 
Write-Host "! For optimal performance and privacy, apply settings marked as [Recommended] !" -ForegroundColor Magenta
Write-Host "" 
Write-Host " THIS UTILITY WILL MAKE CHANGES TO YOUR SYSTEM, " -ForegroundColor Red
Write-Host "  BUT NO CRITICAL FUNCTIONALITY WILL BE LOST.   " -ForegroundColor Red
Write-Host "" 
Write-Host "!!! Please read each prompt carefully before proceeding !!!" -ForegroundColor Magenta
Write-Host "" 

# Pre-check for open work
Write-Host "ATTENTION: This process involves restarting system components (Explorer)." -ForegroundColor Yellow
Write-Host "Please SAVE all open documents and CLOSE other applications before continuing." -ForegroundColor Yellow
$saveWork = Read-Host "Have you saved your work and are ready to proceed? (y/n)"
if ($saveWork -ne "y") {
    Write-Host "Please save your work and run the script again." -ForegroundColor Cyan
    exit
}
Write-Host "" 

$continueScript = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue"

if ($continueScript -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}

Write-Host "NOTE: During the process, Windows Explorer may restart, causing this window to lose focus." -ForegroundColor DarkYellow
Write-Host "If the wizard appears to pause, please CLICK on this window to ensure it has focus." -ForegroundColor DarkYellow
Write-Host "" 
Start-Sleep -Seconds 3
# --- CREATE RESTORE POINT ---
New-RestorePoint

# --- RUN MODULES ---
try { Invoke-TelemetrySetup } catch { Write-Log "Telemetry Module Error: $_" "ERROR" }
try { Invoke-JunkRemoval } catch { Write-Log "Junk Removal Error: $_" "ERROR" }
try { Invoke-DNSBlocking } catch { Write-Log "DNS Block Error: $_" "ERROR" }
try { Invoke-SecurityEnhancement } catch { Write-Log "Security Module Error: $_" "ERROR" }
try { Invoke-BloatwareRemoval } catch { Write-Log "Bloatware Module Error: $_" "ERROR" }
try { Invoke-YourPhoneSetup } catch { Write-Log "Phone Module Error: $_" "ERROR" }
# try { Invoke-XboxSetup } catch { Write-Log "Xbox Module Error: $_" "ERROR" }
try { Invoke-OneDriveRemoval } catch { Write-Log "OneDrive Module Error: $_" "ERROR" }
try { Invoke-TeamsRemoval } catch { Write-Log "Teams Module Error: $_" "ERROR" }
try { Invoke-AIRemoval } catch { Write-Log "AI Module Error: $_" "ERROR" }
try { Invoke-UIAndTaskbarSetup } catch { Write-Log "UI Module Error: $_" "ERROR" }
try { Invoke-SystemOptimizations } catch { Write-Log "Optimization Module Error: $_" "ERROR" }
try { Invoke-SoftwareInstallation } catch { Write-Log "Software Module Error: $_" "ERROR" }

try {
    if ($Urls.ContainsKey("DriverNvidia")) {
        Invoke-DriverInstallation 
    }
} catch { Write-Log "Driver Module Error: $_" "ERROR" }

# Final Restart Logic
Stop-Process -Name explorer -Force
Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
Start-Sleep -Seconds 1
Clear-Host
Start-Sleep -Seconds 1
Clear-Host
Write-Host "" 
Write-Host "" 
Write-Host "===========================================" -ForegroundColor Green
Write-Host "  OGC New Windows Wizard is complete!      " -ForegroundColor Cyan
Write-Host "  Enjoy your optimized Windows experience. " -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Green
Write-Host "" 
Write-Host "" 
Write-Host "It is highly recommended to restart your PC to properly apply all the changes." -ForegroundColor Yellow
$restartChoice = Read-Host "Restart now? (Y/N)"

if ($restartChoice -match "^[Yy]$") {
    Write-Host "Restarting now..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    shutdown /r /t 0
} else {
    Write-Host "You can restart later. Exiting..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    $host.UI.RawUI.FlushInputBuffer()
    Stop-Process -Id $PID -Force
}