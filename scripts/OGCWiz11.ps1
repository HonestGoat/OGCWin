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

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [string]$Type = "DWord" # Default to DWord
    )
    
    # Normalize path: Convert "HKLM\Software" to "HKLM:\Software" for PowerShell
    if ($Path -match "^HK(LM|CU|CR|U|CC)\") {
        $Path = $Path -replace "^HK(LM|CU|CR|U|CC)\", "HK`$1:\" 
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
        $regPath = $Path -replace "^HK(LM|CU|CR|U|CC):\", "HK$1\"
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

function New-RestorePoint {
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "       Creating System Restore Point   " -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    try {
        # Check if System Restore is enabled
        Get-ComputerRestorePoint -LastStatus -ErrorAction SilentlyContinue | Out-Null
        
        # Attempt to create
        Checkpoint-Computer -Description "OGC Wizard Pre-Cleanup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "Success: Restore point 'OGC Wizard Pre-Cleanup' created." -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not create a System Restore Point." -ForegroundColor Yellow
        Write-Host "Ensure System Restore is enabled on your C: drive." -ForegroundColor Yellow
        Write-Host "Error Details: $_" -ForegroundColor Red
        Start-Sleep -Seconds 2
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
            "Microsoft.SkypeApp", "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera",
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

function Invoke-XboxSetup {
    $requiredXboxApps = @{
        "Microsoft.Xbox.TCUI" = "Microsoft.Xbox.TCUI"; "Microsoft.XboxApp" = "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay" = "Microsoft.XboxGameOverlay"; "Microsoft.XboxGamingOverlay" = "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider" = "Microsoft.XboxIdentityProvider"; "Microsoft.XboxSpeechToTextOverlay" = "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.XboxConsoleCompanion" = "Microsoft.XboxConsoleCompanion"; "Microsoft.GamingApp" = "9MWPM2CQNLHN"
        "Microsoft.GamingServices" = "9NZKPSTSNW4P"
    }

    $anyXboxInstalled = $false
    foreach ($app in $requiredXboxApps.Keys) { if (Test-AppInstallation $app) { $anyXboxInstalled = $true; break } }

    $useXbox = Read-Host "Do you want to use Xbox features, including Game Pass and Windows Game Bar? (y/n)"

    if ($useXbox -match "^[Nn]$") {
        if ($anyXboxInstalled) {
            Write-Host "Removing all Xbox apps and features..." -ForegroundColor Magenta
            $xboxProcesses = @("GameBar", "XboxApp", "XboxGameOverlay", "GamingServices")
            foreach ($proc in $xboxProcesses) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
            Get-Service -Name "*Xbox*" | Stop-Service -Force -ErrorAction SilentlyContinue
            Get-Service -Name "*GamingServices*" | Stop-Service -Force -ErrorAction SilentlyContinue

            foreach ($app in $requiredXboxApps.Keys) { Remove-AppxPackageAllUsers $app }

            $xboxRegistryKeys = @("HKCU\Software\Microsoft\Xbox", "HKCU\Software\Microsoft\GamingServices", "HKLM\Software\Microsoft\GamingServices", "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "HKCU\Software\Microsoft\GameBar")
            foreach ($key in $xboxRegistryKeys) { reg delete $key /f 2>$null }

            schtasks /Delete /TN "Microsoft\XblGameSave\XblGameSaveTask" /F 2>$null
            schtasks /Delete /TN "Microsoft\Xbox\XblGameSaveTask" /F 2>$null
            schtasks /Delete /TN "Microsoft\Xbox\XblNetworkMonitorTask" /F 2>$null

            $xboxFolders = @(
                "$env:LOCALAPPDATA\Packages\Microsoft.XboxApp*", "$env:LOCALAPPDATA\Microsoft\XboxGameOverlay",
                "$env:LOCALAPPDATA\Microsoft\Xbox", "$env:ProgramData\Microsoft\Xbox", "$env:APPDATA\Microsoft\Xbox",
                "$env:ProgramFiles\WindowsApps\Microsoft.XboxGamingOverlay*", "$env:ProgramFiles\WindowsApps\Microsoft.XboxGameOverlay*",
                "$env:ProgramFiles\WindowsApps\Microsoft.GamingApp*"
            )
            foreach ($folder in $xboxFolders) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue }

            Get-Service -Name "*Xbox*" | Set-Service -StartupType Disabled
            Get-Service -Name "*GamingServices*" | Set-Service -StartupType Disabled
            Write-Host "ALL Xbox apps, services, and features have been **COMPLETELY REMOVED**!" -ForegroundColor Green
        } else {
             Write-Host "Xbox features were already removed." -ForegroundColor Cyan
        }
    } else {
        Write-Host "Checking for missing Xbox features and installing them if needed..." -ForegroundColor Cyan
        if (-not (Test-AppInstallation "Microsoft.WindowsStore")) {
             Write-Host "Microsoft Store is missing! Reinstalling it first..." -ForegroundColor Yellow
             Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "Microsoft.WindowsStore"} | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppxManifest.xml"}
             Start-Sleep -Seconds 5
        }
        foreach ($app in $requiredXboxApps.Keys) {
            if (-not (Test-AppInstallation $app)) {
                Write-Host "Installing missing Xbox feature: $app ..." -ForegroundColor Magenta
                Try {
                    $appLocation = (Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $app }).InstallLocation
                    if ($appLocation) { Add-AppxPackage -DisableDevelopmentMode -Register "$appLocation\AppxManifest.xml" } else { Throw "Loc not found" }
                } Catch {
                    $wingetID = $requiredXboxApps[$app]
                    Try {
                        if ($wingetID -match "^[0-9A-Z]{12}$") { Start-Process -FilePath "ms-windows-store://pdp/?productid=$wingetID" } 
                        else { winget install --id "$wingetID" --silent --accept-package-agreements --accept-source-agreements }
                    } Catch { Start-Process -FilePath "ms-windows-store://pdp/?productid=$wingetID" }
                }
            }
        }
        Get-Service -Name "*Xbox*" | Set-Service -StartupType Automatic -ErrorAction SilentlyContinue
        try { Get-Service -Name "*GamingServices*" | Set-Service -StartupType Automatic -ErrorAction Stop } catch {}
        Write-Host "Xbox features are installed and enabled." -ForegroundColor Green
    }
}

function Invoke-OneDriveRemoval {
    $removeOneDrive = Read-Host "Do you want to completely remove Microsoft OneDrive? [Recommended] (y/n)"
    if ($removeOneDrive -eq "y") {
        Write-Host "FORCEFULLY REMOVING MICROSOFT ONEDRIVE..." -ForegroundColor Magenta
        Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        $oneDriveExecutables = @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")
        $oneDriveUninstalled = $false
        foreach ($exe in $oneDriveExecutables) {
            if (Test-Path $exe) {
                try { Start-Process -FilePath $exe -ArgumentList "/uninstall" -NoNewWindow -Wait -WindowStyle Hidden -ErrorAction Stop; $oneDriveUninstalled=$true; break } catch {}
            }
        }
        if (-not $oneDriveUninstalled) { try { winget uninstall --id Microsoft.OneDrive --silent --accept-package-agreements --accept-source-agreements > $null 2>&1 } catch {} }
        Remove-AppxPackageAllUsers "Microsoft.OneDrive"

        # Backup files
        $oneDriveUserFolder = "$env:UserProfile\OneDrive"
        $backupFolder = "$env:UserProfile\Onedrive Files"
        if (Test-Path $oneDriveUserFolder) {
            $oneDriveSubfolders = @("Attachments", "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")
            foreach ($folder in $oneDriveSubfolders) {
                $sourcePath = "$oneDriveUserFolder\$folder"; $destinationPath = "$env:UserProfile\$folder"
                if (Test-Path $sourcePath) {
                    New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
                    robocopy "$sourcePath" "$destinationPath" /E /MOVE /COPY:DAT /R:3 /W:3 /NFL /NDL /NJH /NJS
                }
            }
            if ((Get-ChildItem -Path $oneDriveUserFolder -Recurse -ErrorAction SilentlyContinue).Count -gt 0) {
                New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
                robocopy "$oneDriveUserFolder" "$backupFolder" /E /MOVE /COPY:DAT /R:3 /W:3 /NFL /NDL /NJH /NJS
            }
        }

        # Cleanup
        $oneDriveFolders = @("$oneDriveUserFolder", "$env:LocalAppData\Microsoft\OneDrive", "$env:ProgramData\Microsoft OneDrive", "$env:SystemDrive\OneDriveTemp")
        foreach ($folder in $oneDriveFolders) { if (Test-Path $folder) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } }

        reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f 2>$null
        reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f 2>$null
        reg delete "HKCU\Software\Microsoft\OneDrive" /f 2>$null
        reg delete "HKLM\Software\Microsoft\OneDrive" /f 2>$null
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1

        schtasks /Delete /TN "OneDrive Standalone Update Task-S-1-5-21" /F 2>$null
        schtasks /Delete /TN "OneDrive Per-Machine Standalone Update Task" /F 2>$null
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f 2>$null

        # Restore Shell Folders
        $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $folders = @{
            "Desktop"="$env:USERPROFILE\Desktop"; "Documents"="$env:USERPROFILE\Documents"; "Personal"="$env:USERPROFILE\Documents"
            "Downloads"="$env:USERPROFILE\Downloads"; "Music"="$env:USERPROFILE\Music"; "My Music"="$env:USERPROFILE\Music"
            "Pictures"="$env:USERPROFILE\Pictures"; "My Pictures"="$env:USERPROFILE\Pictures"; "Videos"="$env:USERPROFILE\Videos"; "My Video"="$env:USERPROFILE\Videos"
        }
        foreach ($folder in $folders.Keys) {
            $defaultPath = $folders[$folder]
            if (!(Test-Path $defaultPath)) { New-Item -Path $defaultPath -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path $registryPath -Name $folder -Value $defaultPath -Force
        }

        Write-Host "ONEDRIVE HAS BEEN COMPLETELY REMOVED!" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Keeping Microsoft OneDrive." -ForegroundColor Cyan
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
        
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "AllowNewsAndInterests" -Value 0
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "AllowCopilotInWindows" -Value 0
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Dsh" -Name "EnableCopilotButton" -Value 0
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0

        $copilotProcesses = @("Copilot", "Copilot.exe", "AI.exe", "CopilotRuntime", "CopilotBackground", "Microsoft365Copilot", "Microsoft365Copilot.exe")
        foreach ($proc in $copilotProcesses) { Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
        
        try { winget uninstall --id "Microsoft.Copilot" --silent --accept-source-agreements > $null 2>&1; winget uninstall --id "Microsoft.365.Copilot" --silent --accept-source-agreements > $null 2>&1 } catch {}
        
        $copilotPackages = @("Microsoft.Windows.AI.Copilot", "Microsoft.Copilot", "Microsoft.365.Copilot")
        foreach ($package in $copilotPackages) { Remove-AppxPackageAllUsers $package }

        $officeUninstallPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
        if (Test-Path $officeUninstallPath) { try { Start-Process -FilePath $officeUninstallPath -ArgumentList "/uninstall Copilot /quiet /norestart" -NoNewWindow -Wait -ErrorAction SilentlyContinue } catch {} }

        # MSI Removal
        $msiCopilot = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Copilot%'" -ErrorAction SilentlyContinue
        if ($msiCopilot) { foreach ($app in $msiCopilot) { try { $app.Uninstall() } catch {} } }

        $copilotFolders = @("$env:LOCALAPPDATA\Packages\Microsoft.Windows.AI.Copilot", "$env:ProgramData\Microsoft\Windows\AI\Copilot", "$env:APPDATA\Microsoft\Copilot", "$env:ProgramFiles\Microsoft\Copilot", "$env:ProgramFiles (x86)\Microsoft\Copilot", "C:\ProgramData\Microsoft\Copilot")
        foreach ($folder in $copilotFolders) { if (Test-Path $folder) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } }

        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
        reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
        
        $copilotRegistryKeys = @("HKCU\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Copilot", "HKCU\Software\Microsoft\Office\Copilot", "HKLM\Software\Microsoft\Office\Copilot")
        foreach ($key in $copilotRegistryKeys) { reg delete $key /f 2>$null }

        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Copilot" -Name "DisableCopilot" -Value 1
        
        Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden

        Write-Host "MICROSOFT COPILOT HAS BEEN COMPLETELY REMOVED!" -ForegroundColor Green
    } else {
        Write-Host "Keeping Microsoft Copilot." -ForegroundColor Cyan
    }

    $removeRecall = Read-Host "Do you want to remove Microsoft Recall? [Recommended] (y/n)"
    if ($removeRecall.ToLower() -match "^y") {
        Write-Host "Disabling Microsoft Recall..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableWindowsAI" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableLogging" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows AI" -Name "DisableMemorySnapshots" -Value 1
        Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableSearchIndexing" -Value 1
        Start-Process -FilePath "reg.exe" -ArgumentList "add", "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Recall", "/t", "REG_SZ", "/d", "", "/f" -NoNewWindow -Wait
        schtasks /Change /TN "Microsoft\Windows\AI\Recall" /Disable
        schtasks /Change /TN "Microsoft\Windows\AI\RecallIndexing" /Disable
        gpupdate /force
        Write-Host "Microsoft Recall fully disabled." -ForegroundColor Green
    } else {
        Write-Host "Keeping Microsoft Recall." -ForegroundColor Cyan
    }
}

function Invoke-UIAndTaskbarSetup {
    $win10look = Read-Host "Do you want Windows 11 to look and feel like Windows 10? [Recommended] (y/n)"
    if ($win10look -eq "y") {
        Write-Host "Applying UI tweaks..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_ShowClassicMode" -Value 1
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0
        Start-Process -FilePath "reg.exe" -ArgumentList "add", "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}", "/f" -NoNewWindow -Wait
        Start-Process -FilePath "reg.exe" -ArgumentList "add", "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32", "/ve", "/t", "REG_SZ", "/d", "", "/f" -NoNewWindow -Wait
        Write-Host "Windows UI tweaks applied successfully." -ForegroundColor Green
    } else {
        Write-Host "Skipping Windows 10 UI tweaks." -ForegroundColor Cyan
    }

    $debloatTaskbar = Read-Host "Do you want to debloat the taskbar and remove unnecessary icons, including News, Weather, Widgets, and Microsoft Store? [Recommended] (y/n)"
    if ($debloatTaskbar -eq "y") {
        Write-Host "Removing unnecessary taskbar icons..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Value 0
        # Tray icons 2 rows (binary) - preserving logic
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" -Name "Settings" -Value ([byte[]](0x30,0x00,0x00,0x00,0xFE,0xFF,0xFF,0xFF,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -Force
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1

        # Disable Widgets
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0
        Get-Service -Name "Widgets" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Service -Name $_.Name -Force; Set-Service -Name $_.Name -StartupType Disabled }
        Remove-AppxPackageAllUsers "MicrosoftWindows.Client.WebExperience"

        # Remove News and Interests
        Remove-AppxPackageAllUsers "Microsoft.BingNews"
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0

        # Unpin Store
        $taskbarLayout = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Store.lnk"
        if (Test-Path $taskbarLayout) { Remove-Item $taskbarLayout -Force -ErrorAction SilentlyContinue }
        Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value 1
        
        Remove-AppxPackageAllUsers "Microsoft.BingWeather"
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2

    } else {
        Write-Host "Skipping taskbar debloating." -ForegroundColor Cyan
    }

    $enableDarkMode = Read-Host "Do you want to enable Dark Mode for Windows and supported applications? [Recommended] (y/n)"
    if ($enableDarkMode -eq "y") {
        Write-Host "Enabling Dark Mode..." -ForegroundColor Magenta
        $personalizePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $personalizePath -Name "SystemUsesLightTheme" -Value 0 -ErrorAction SilentlyContinue
        
        if (Test-Path "HKCU:\Software\Microsoft\Office\16.0\Common") {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common" -Name "UI Theme" -Value 4 -Type DWord -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Dark Mode not enabled." -ForegroundColor Cyan
    }
}

function Invoke-SystemOptimizations {
    $debloatEdge = Read-Host "Do you want to remove Edges forced features? [Recommended] (y/n)"
    if ($debloatEdge -eq "y") {
        Write-Host "Disabling Edge forced features..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RestorePdfAssociationsEnabled" -Value 0
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0
        Write-Host "Edge features disabled!" -ForegroundColor Green
    }

    $gameOptimizations = Read-Host "Do you want to enable gaming features like Game Mode, VRR, HAGS (GPU Scheduling)? [Recommended for Gamers] (y/n)"
    if ($gameOptimizations -match "^[Yy]$") {
        Write-Host "Applying gaming optimizations..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GraphicsSettings" -Name "HwSchMode" -Value 2
        
        $vrrSupported = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -ErrorAction SilentlyContinue
        if ($null -ne $vrrSupported) {
             Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -Value 1
        }
        Write-Host "All selected gaming features have been enabled!" -ForegroundColor Cyan
    } else {
        Write-Host "Skipping gaming optimizations." -ForegroundColor Cyan
    }

    $usbsuspend = Read-Host "Do you intend to use controllers or joysticks with your games? [Recommended] (y/n)"
    if ($usbsuspend -match "^[Yy]$") {
        Write-Host "Disabling Selective USB Suspend.."
        powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    }

    $disableMemoryIsolation = Read-Host "Do you want to disable Memory Core Isolation for better gaming performance? (Recommended) (y/n)"
    if ($disableMemoryIsolation -match "^[Yy]$") {
        Write-Host "Disabling Memory Core Isolation and Related Features..." -ForegroundColor Magenta
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0
        bcdedit /set hypervisorlaunchtype off
        Write-Host "Memory Core Isolation disabled. Restart required." -ForegroundColor Yellow
    } else {
        Write-Host "Keeping Memory Core Isolation enabled." -ForegroundColor Cyan
    }

    Write-Host "Restarting Windows Explorer to apply changes..." -ForegroundColor Cyan
    Stop-Process -Name explorer -Force
    Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
    Write-Host "Windows Explorer Restarted." -ForegroundColor Green
    
    # Desktop Shortcut
    New-Shortcut -TargetPath $script:ogcwinbat -ShortcutPath $script:desktopPath -Description "Launch OGC Windows Utility" -IconPath "C:\Windows\System32\imageres.dll,97"
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

    $installGamingApps = Read-Host "Do you want to install gaming apps like Steam, Epic, GOG, Discord, and Medal? (y/n)"
    if ($installGamingApps -eq "y") {
        $apps = @{
            "Steam" = "Valve.Steam"; "Epic Games Launcher" = "EpicGames.EpicGamesLauncher"; "GOG Galaxy" = "GOG.Galaxy"
            "Discord" = "Discord.Discord"; "Medal" = "Medal.TV"
        }
        foreach ($key in $apps.Keys) {
             if ((Read-Host "Do you want to install $key? (y/n)") -eq "y") {
                 Write-Host "Installing $key..." -ForegroundColor Magenta
                 winget install $apps[$key] --silent --accept-package-agreements --accept-source-agreements
             }
        }
        Write-Host "Gaming app installation process completed." -ForegroundColor Green
    }

    $installGamingUtilities = Read-Host "Do you want to install gaming and monitoring utilities? (y/n)"
    if ($installGamingUtilities -eq "y") {
        $utils = @{
            "HWiNFO" = "REALiX.HWiNFO"; "MSI Afterburner" = "MSI.Afterburner"; "RivaTuner Statistics Server (RTSS)" = "Guru3D.RTSS"
            "CPU-Z" = "CPUID.CPU-Z"; "GPU-Z" = "TechPowerUp.GPU-Z"
        }
        foreach ($key in $utils.Keys) {
            if ((Read-Host "Do you want to install $key? (y/n)") -eq "y") {
                Write-Host "Installing $key..." -ForegroundColor Magenta
                winget install $utils[$key] --silent --accept-package-agreements --accept-source-agreements
            }
        }
        Write-Host "Gaming and monitoring utilities installation completed." -ForegroundColor Green
    }

    $installBrowser = Read-Host "Do you want to install a web browser? (y/n)"
    if ($installBrowser -eq "y") {
        Write-Host "Select a browser to install..." -ForegroundColor Cyan
        Write-Host "1. Firefox"; Write-Host "2. Brave"; Write-Host "3. Opera GX"; Write-Host "4. Chrome"; Write-Host "5. Edge (Already Installed)"; Write-Host "6. Skip Browser Installation"
        
        $browser = Read-Host "Enter the number corresponding to your browser choice"
        switch ($browser) {
            "1" { winget install Mozilla.Firefox; Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue }
            "2" { winget install Brave.Brave; Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue }
            "3" { winget install Opera.OperaGX; Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue }
            "4" { winget install Google.Chrome; Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" -ErrorAction SilentlyContinue }
            "5" { Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 1 }
            "6" { Write-Host "Skipping browser installation." -ForegroundColor Cyan }
            default { Write-Host "Invalid selection." -ForegroundColor Red }
        }
    }
    
    # Office Section
    Write-Host "Choose an office suite to install or remove Office Hub and other office software:" -ForegroundColor Cyan
    Write-Host "1. Microsoft Office"; Write-Host "2. LibreOffice"; Write-Host "3. OpenOffice"; Write-Host "4. No Office Suite (Remove all office software)"; Write-Host "5. Skip this section"
    $officeChoice = Read-Host "Enter your choice (1/2/3/4/5)"

    if ($officeChoice -eq "1") { winget install --id Microsoft.Office --silent --accept-package-agreements --accept-source-agreements; Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub" }
    elseif ($officeChoice -eq "2") { winget install --id TheDocumentFoundation.LibreOffice --silent --accept-package-agreements --accept-source-agreements; Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub" }
    elseif ($officeChoice -eq "3") { winget install --id Apache.OpenOffice --silent --accept-package-agreements --accept-source-agreements; Remove-AppxPackageAllUsers "Microsoft.MicrosoftOfficeHub" }
    elseif ($officeChoice -eq "4") {
        Write-Host "Removing all Office-related software..." -ForegroundColor Magenta
        $officeApps = @("Microsoft.Office.Desktop", "Microsoft.Office.OneNote", "Microsoft.OfficeHub", "Microsoft.MicrosoftOfficeHub", "Microsoft.Office", "TheDocumentFoundation.LibreOffice", "Apache.OpenOffice", "Microsoft.OutlookForWindows", "Microsoft.OutlookWebApp", "Microsoft.Office.OneDriveSync")
        foreach ($app in $officeApps) { Remove-AppxPackageAllUsers $app }
        $officeFolders = @("$env:ProgramFiles\Microsoft Office", "$env:ProgramFiles (x86)\Microsoft Office", "$env:LOCALAPPDATA\Microsoft\OneDrive", "$env:LOCALAPPDATA\Microsoft\Office", "$env:APPDATA\Microsoft\Office", "$env:ProgramFiles\LibreOffice", "$env:ProgramFiles (x86)\LibreOffice", "$env:ProgramFiles\OpenOffice", "$env:ProgramFiles (x86)\OpenOffice")
        foreach ($folder in $officeFolders) { if (Test-Path $folder) { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } }
        $officeRegKeys = @("HKCU:\Software\Microsoft\Office", "HKCU:\Software\Microsoft\Outlook", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office")
        foreach ($regKey in $officeRegKeys) { if (Test-Path $regKey) { Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue } }
        Write-Host "All Office-related software has been removed." -ForegroundColor Green
    }
}

function Invoke-DriverInstallation {
    $installGPUDrivers = Read-Host "Do you want to install graphics drivers? (y/n)"
    if ($installGPUDrivers -eq "y") {
        Write-Host "Select your GPU brand to install drivers:" -ForegroundColor Cyan
        Write-Host "1. NVIDIA"; Write-Host "2. AMD"; Write-Host "3. Intel"; Write-Host "4. Skip"
        $gpuChoice = Read-Host "Enter the number of your choice (1/2/3/4)"

        switch ($gpuChoice) {
            "1" { Install-Driver -DriverURL $Urls["DriverNvidia"] -DriverPath "$env:TEMP\NVIDIA-Driver.exe" -InstallArgs "-s" }
            "2" { Install-Driver -DriverURL $Urls["DriverAmd"] -DriverPath "$env:TEMP\AMD-Driver.exe" -InstallArgs "/INSTALL /SILENT" }
            "3" {
                 $intelChoice = Read-Host "1. Intel HD (Integrated) or 2. Intel Arc (Dedicated)? (1/2)"
                 if ($intelChoice -eq "1") { Install-Driver -DriverURL $Urls["DriverIntelHd"] -DriverPath "$env:TEMP\Intel-HD-Driver.exe" -InstallArgs "-s" }
                 elseif ($intelChoice -eq "2") { Install-Driver -DriverURL $Urls["DriverIntelArc"] -DriverPath "$env:TEMP\Intel-Arc-Driver.exe" -InstallArgs "-s" }
            }
        }
    }
    
    # GPU Telemetry Removal
    Write-Host "Checking installed GPU drivers for telemetry removal..." -ForegroundColor Magenta
    $installedDrivers = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name
    if ($installedDrivers -match "NVIDIA") {
        Write-Host "Disabling NVIDIA telemetry..." -ForegroundColor Cyan
        foreach ($s in @("NvTelemetryContainer", "NvContainerLocalSystem", "NvContainerNetworkService")) { Disable-Service $s }
        foreach ($t in @("\NvTmMon", "\NvTmRep", "\NvTmRepOnLogon")) { Disable-ScheduledTask -taskName $t }
        Set-RegistryValue -path "HKLM:\Software\NVIDIA Corporation\Global\NvTelemetry" -name "EnableTelemetry" -value 0
        if (Test-Path "C:\Program Files\NVIDIA Corporation\GeForce Experience") { Set-RegistryValue -path "HKLM:\Software\NVIDIA Corporation\Global\GeForce Experience" -name "EnableCEIP" -value 0 }
    }
    if ($installedDrivers -match "AMD") {
        Write-Host "Disabling AMD telemetry..." -ForegroundColor Cyan
        Set-RegistryValue -path "HKLM:\Software\AMD\CN" -name "UserExperienceProgram" -value 0
        Disable-Service "AMD External Events Utility"
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
Write-Host "If the script appears to pause, please CLICK on this window to ensure it has focus." -ForegroundColor DarkYellow
Write-Host "" 
Start-Sleep -Seconds 3
# --- CREATE RESTORE POINT ---
New-RestorePoint

# --- RUN MODULES ---
Invoke-TelemetrySetup
Invoke-JunkRemoval
Invoke-DNSBlocking
Invoke-SecurityEnhancement
Invoke-BloatwareRemoval
Invoke-YourPhoneSetup
Invoke-XboxSetup
Invoke-OneDriveRemoval
Invoke-TeamsRemoval
Invoke-AIRemoval
Invoke-UIAndTaskbarSetup
Invoke-SystemOptimizations
Invoke-SoftwareInstallation
Invoke-DriverInstallation

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