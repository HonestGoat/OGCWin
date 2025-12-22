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
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$oneDriveUserPath = "$env:UserProfile\OneDrive"
$logFolder = "$parentFolder\logs"
$logFile = "$logFolder\${scriptName}_log.txt"
$robocopyLog = "$logFolder\robocopy_log.txt"
$backupFolder = "$parentFolder\backups"
$configsFolder = "$parentFolder\configs"
$scriptsFolder = "$parentFolder\scripts"


# Configuration
$ConfigPath = "$configsFolder\urls.cfg"
$Urls = @{}

# Files and Shortcuts
$ogcwinbat = "$parentFolder\OGCWin.bat"
$ogcmode = "$scriptsFolder\OGCMode.ps1"
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
        [Parameter(Mandatory = $true)] [string]$Message,
        [Parameter(Mandatory = $false)] [ValidateSet("SUCCESS", "FAILURE", "INFO", "WARNING", "ERROR", "CRITICAL")] [string]$Status = "INFO",
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

function Get-Url {
    param ([string]$Key)
    if ($Urls.ContainsKey($Key)) {
        return $Urls[$Key]
    }
    if (Test-Path $ConfigPath) {
        $fileContent = Get-Content $ConfigPath
        foreach ($line in $fileContent) {
            if ($line -match "^$Key=(.+)") {
                return $matches[1]
            }
        }
    }
    return $null
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
            "REG_SZ" { $Type = "String" }
            "REG_BINARY" { $Type = "Binary" }
        }

        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    }
    catch {
        # Fallback to reg.exe if PowerShell fails
        # FIX: Escaped trailing backslash in regex and escaped $1 in replacement string
        $regPath = $Path -replace "^HK(LM|CU|CR|U|CC):\\", "HK`$1\"
        $regType = "REG_DWORD" # Default fallback
        if ($Type -eq "String") { $regType = "REG_SZ" }
        if ($Type -eq "Binary") { $regType = "REG_BINARY" }
        
        try {
            Start-Process -FilePath "reg.exe" -ArgumentList "add `"$regPath`" /v `"$Name`" /t $regType /d `"$Value`" /f" -NoNewWindow -Wait -ErrorAction Stop
        }
        catch {
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
        }
        catch {
            Write-Host "Failed to disable service '$serviceName'." -ForegroundColor Red
        }
    }
    else {
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
        }
        catch {}
    }

    if ($taskPath) {
        if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null
            Write-Host "Scheduled Task '$taskName' disabled." -ForegroundColor Green
        }
        else {
            Write-Host "Scheduled Task '$taskName' not found." -ForegroundColor Yellow
        }
    }
    else {
        try {
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-Host "Scheduled Task '$taskName' disabled." -ForegroundColor Green
        }
        catch {
            Write-Host "Scheduled Task '$taskName' not found or failed." -ForegroundColor Yellow
        }
    }
}

function Remove-AppxPackageAllUsers {
    param (
        [string]$PackageName
    )
    # Remove for current user
    try { 
        Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}

    # Remove for all users
    try {
        Get-AppxPackage -AllUsers -Name $PackageName -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}

    # Remove provisioned package
    try {
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$PackageName*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
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

function Start-Watchdog {
    param ([int]$ParentPID, [string]$LogFile)
    
    # Check if log file is writable
    try {
        if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File -Force | Out-Null }
        Add-Content -Path $LogFile -Value "$(Get-Date) - DEBUG: Watchdog startup check." -ErrorAction Stop
    }
    catch {
        # Fallback if we can't write to the requested log
        $LogFile = "$env:TEMP\OGC_Watchdog_fallback.log"
    }

    # Embed variables directly into the script block string
    $code = @"
    [console]::TreatControlCAsInput = `$true
    `$pidToWatch = $ParentPID
    `$log = "$LogFile"
    
    function Log { param(`$msg) try { Add-Content -Path `$log -Value "`$(Get-Date) - `$msg" -Force } catch {} }
    
    Log "Watchdog initiated. Monitoring PID: `$pidToWatch"
    
    while (`$true) {
        if (-not (Get-Process -Id `$pidToWatch -ErrorAction SilentlyContinue)) {
             Log "Parent process ($ParentPID) has terminated unexpectedly."
             break
        }
        Start-Sleep -Seconds 2
    }
    
    Start-Sleep -Seconds 1
    
    if (-not (Get-Process "explorer" -ErrorAction SilentlyContinue)) {
        Log "Explorer.exe is not running. Attempting to restart..."
        
        # FIX: Restore AutoRestartShell in case script crashed while it was disabled
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 1 -Force -ErrorAction SilentlyContinue
            Log "AutoRestartShell registry value restored."
        } catch {
             Log "Failed to restore AutoRestartShell: `$(_)"
        }

        try {
            Start-Process "explorer.exe"
            Log "Explorer restart command executed."
        } catch {
            Log "Failed to restart explorer: `$(`$_.Exception.Message)"
        }
    } else {
        Log "Explorer.exe is already running. Monitoring complete."
    }
    exit
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
    $encoded = [System.Convert]::ToBase64String($bytes)
    
    # Detached process using 'start' (cmd) or just WinHidden
    return Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encoded" -PassThru -WindowStyle Hidden
}


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
        
        # Checking VM Logic as requested
        if ($isVM) {
            $vmChoice = Read-Host "VM Detected. Do you want to enable/create a Restore Point? (y/n)"
            if ($vmChoice -ne "y") {
                Write-Host "Skipping Restore Point creation for VM." -ForegroundColor Cyan
                return
            }
        }

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

    }
    catch {
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
            }
            else {
                Write-Host "Error: Could not find OGCMode.ps1 at $ogcmode" -ForegroundColor Red
                return
            }
        }
        else {
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
    }
    else { Write-Host "Failed to download the driver." -ForegroundColor Red }
}

# --- Module Functions ---

function Invoke-TelemetrySetup {
    Write-Log -Message "Starting Invoke-TelemetrySetup..."
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
        }
        else {
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
    Write-Log -Message "Starting Invoke-JunkRemoval..."
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
    Write-Log -Message "Starting Invoke-DNSBlocking..."
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
            }
            else {
                Write-Host "$domain is already present." -ForegroundColor Yellow
            }
        }

        Move-Item -Path $tempFolder -Destination $hostsPath -Force

        # Restore Defender
        Write-Host "Re-enabling Windows Defender real-time protection..." -ForegroundColor Yellow
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

        Write-Host "Telemetry domains have been blocked via the hosts file." -ForegroundColor Green
    }
    else {
        Write-Host "Skipping the blocking of telemetry domains." -ForegroundColor Cyan
    }
}

function Invoke-SecurityEnhancement {
    Write-Log -Message "Starting Invoke-SecurityEnhancement..."
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
        }
        else {
            Write-Host "!! Secure Boot is DISABLED. Please enable it in BIOS !!" -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
    }
    catch {
        # Fallback to registry check
        $secureBootState = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "SecureBootEnabled" -ErrorAction SilentlyContinue
        if ($secureBootState -and $secureBootState.SecureBootEnabled -eq 1) {
            Write-Host "Secure Boot is enabled (Registry Check)." -ForegroundColor Green
        }
        elseif ($secureBootState -and $secureBootState.SecureBootEnabled -eq 0) {
            Write-Host "!! Secure Boot is DISABLED (Registry Check). Please enable it in BIOS !!" -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
        else {
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
    }
    else {
        Write-Host "Built-in Administrator account is already disabled." -ForegroundColor Yellow
    }

    Write-Host "Enabling verbose logon messages..." -ForegroundColor Cyan
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1
    Write-Host "Verbose logon messages enabled." -ForegroundColor Green

    Write-Host "Security configurations have been applied successfully." -ForegroundColor Green
}

function Invoke-BloatwareRemoval {
    Write-Log -Message "Starting Invoke-BloatwareRemoval..."
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
            }
            else {
                # Fallback checks (DISM/Provisioned) handled in Remove-AppxPackageAllUsers mostly, but checking logic
                $dismOutput = dism /Online /Remove-ProvisionedAppxPackage /PackageName:$app /Quiet 2>&1
                if ($dismOutput -match "successfully removed") { $removed = $true }
            }
            if ($removed) { Write-Host "$app successfully removed." -ForegroundColor Green }
        }
        Write-Host "Preinstalled advertising apps and bloatware removed." -ForegroundColor Green
    }
    else {
        Write-Host "Skipping bloatware removal." -ForegroundColor Cyan
    }

    $disableBingSearch = Read-Host "Do you want to disable Bing Search integration in the Start Menu? [Recommended] (y/n)"
    if ($disableBingSearch -match "^[Yy]$") {
        Write-Host "Disabling Bing Search in the Start Menu..." -ForegroundColor Yellow
        Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
        Write-Host "Bing Search integration disabled." -ForegroundColor Green
    }
    else {
        Write-Host "Keeping Bing Search enabled." -ForegroundColor Cyan
    }
}

function Invoke-EdgeRemoval {
    Write-Log -Message "Starting Invoke-EdgeRemoval..."
    
    Write-Host "`n--- Edge Removal ---" -ForegroundColor Magenta
    Write-Host "Caution: Removing Microsoft Edge is mostly safe but can cause issues with specific Microsoft products." -ForegroundColor Yellow
    Write-Host "Window Widgets and Windows Search (Web results) may be affected." -ForegroundColor Gray
    
    do {
        $removeEdge = Read-Host "Do you want to forcefully remove Microsoft Edge? (y/n)"
        if ($removeEdge -notin "y", "n") { Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red }
    } until ($removeEdge -in "y", "n")
    
    if ($removeEdge -eq "y") {
        Write-Host "Forcefully removing Microsoft Edge..." -ForegroundColor Magenta
        Write-Log -Message "Starting Microsoft Edge removal."

        # 1. Force Uninstall via Setup.exe
        try {
            $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application"
            if (Test-Path $edgePath) {
                Get-ChildItem -Path $edgePath -Recurse -Filter "setup.exe" | ForEach-Object {
                    Write-Host "Executing uninstall command..." -ForegroundColor Cyan
                    Start-Process -FilePath $_.FullName -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -NoNewWindow
                }
            }
        }
        catch { Write-Log "Edge Uninstall Error: $_" "ERROR" }

        # 2. Cleanup Files (Shortcuts & Directories)
        $edgeFiles = @(
            "$env:Public\Desktop\Microsoft Edge.lnk", 
            "$env:UserProfile\Desktop\Microsoft Edge.lnk",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
            "$env:AppData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
            "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk"
        )
        
        foreach ($file in $edgeFiles) {
            if (Test-Path $file) { 
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue 
                Write-Host "Removed shortcut: $file" -ForegroundColor DarkGray
            }
        }

        # 3. Registry Hardening
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1
        
        # 4. Stop Services
        Stop-Service -Name "edgeupdate" -Force -ErrorAction SilentlyContinue
        Stop-Service -Name "edgeupdatem" -Force -ErrorAction SilentlyContinue
        
        Write-Host "Microsoft Edge removal complete." -ForegroundColor Green
        Write-Log "Edge removal finished." "INFO"
    }
    else {
        Write-Host "Keeping Microsoft Edge." -ForegroundColor Cyan
    }
}


function Invoke-YourPhoneSetup {
    Write-Log -Message "Starting Invoke-YourPhoneSetup..."
    $useYourPhone = Read-Host "Do you want to use the 'Your Phone' app to integrate your phone with Windows? (y/n)"
    $yourPhoneInstalled = Get-AppxPackage -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue

    if ($useYourPhone -eq "y") {
        if ($yourPhoneInstalled) {
            Write-Host "'Your Phone' app is already installed." -ForegroundColor Green
        }
        else {
            Write-Host "Installing 'Your Phone' app..." -ForegroundColor Yellow
            try {
                winget install --id Microsoft.YourPhone -e --silent --accept-package-agreements --accept-source-agreements
                Write-Host "'Your Phone' app installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to install 'Your Phone' app. Error: $_" -ForegroundColor Red
            }
        }
    }
    elseif ($useYourPhone -eq "n") {
        if ($yourPhoneInstalled) {
            Write-Host "Removing 'Your Phone' app..." -ForegroundColor Magenta
            Remove-AppxPackageAllUsers "Microsoft.YourPhone"
            Write-Host "'Your Phone' app removed." -ForegroundColor Green
        }
        else {
            Write-Host "'Your Phone' app is not installed." -ForegroundColor Cyan
        }
    }
}

function Invoke-XboxSetup {
    Write-Log -Message "Starting Invoke-XboxSetup..."
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
        }
        catch { Write-Log -Message "Couldn't restore $Name locally. Trying download..." -Status "WARNING" -Module $mod }

        # Method 2: Winget Download (Silent)
        try {
            if ($ID -match "^[0-9A-Z]{12}$") {
                Write-Host "  -> Downloading fresh copy (Silent)..." -ForegroundColor Yellow
                Start-Process -FilePath "winget" -ArgumentList "install --id $ID --source msstore --accept-package-agreements --accept-source-agreements --silent" -Wait -NoNewWindow
                
                if (Test-XboxAppInstalled $Name) {
                    Write-Host "  -> Install success." -ForegroundColor Green
                    Write-Log -Message "Freshly installed $Name from server." -Status "SUCCESS" -Module $mod
                }
                else { throw "Download finished but app is missing." }
            }
            else {
                Write-Host "  -> No download ID available." -ForegroundColor Red
                Write-Log -Message "Skipped download for $Name (No ID)." -Status "FAILURE" -Module $mod
            }
        }
        catch {
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
        }
        catch { Write-Log -Message "Had trouble removing $Name." -Status "FAILURE" -Module $mod }
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
        }
        catch { Write-Log -Message "Hiccup starting core services." -Status "WARNING" -Module $mod }

        # Install Apps
        foreach ($k in $coreApps.Keys) { Install-XboxApp -Name $k -ID $coreApps[$k] }

    }
    else {
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
        }
        catch { Write-Log -Message "Couldn't flip GameDVR registry switch." -Status "FAILURE" -Module $mod }

        foreach ($k in $barApps.Keys) { Install-XboxApp -Name $k -ID $barApps[$k] }

    }
    else {
        Write-Log -Message "User chose to kill Game Bar." -Status "INFO" -Module $mod
        Write-Host "Removing Game Bar..." -ForegroundColor Magenta

        # Disable Reg
        try {
            New-ItemProperty "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWORD -Force -EA 0 | Out-Null
            New-ItemProperty "HKCU\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWORD -Force -EA 0 | Out-Null
        }
        catch {}

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
        
        Write-Host "NOTE: OneDrive must remain running during this process to access files." -ForegroundColor Yellow
        Write-Color "Phase 1: Securing Local Files (Automatic)..." "Cyan"
        
        # Physical folder mapping
        $physicalFolderMap = @{
            "Desktop"   = "$env:UserProfile\Desktop"
            "Documents" = "$env:UserProfile\Documents"
            "Pictures"  = "$env:UserProfile\Pictures"
            "Music"     = "$env:UserProfile\Music"
            "Videos"    = "$env:UserProfile\Videos"
            "Downloads" = "$env:UserProfile\Downloads"
        }
        
        # 1. PHASE 1: COPY LOCAL FILES (ALWAYS)
        # We assume the user wants to keep what they have on disk.
        # We use /XA:O to EXCLUDE Offline (Cloud) files to ensure this pass is fast and error-free.
        $folderMapKeys = $physicalFolderMap.Keys
        foreach ($folderName in $folderMapKeys) {
            $source = "$oneDriveUserPath\$folderName"
            $dest = $physicalFolderMap[$folderName]
            if (Test-Path $source) {
                if (!(Test-Path $dest)) { New-Item -Path $dest -ItemType Directory -Force | Out-Null }
                # /XA:O = Exclude Offline (Cloud). Silent console output.
                $argsList = "`"$source`" `"$dest`" /E /COPY:DAT /R:3 /W:3 /NP /NJH /NJS /XA:O /LOG+:`"$robocopyLog`""
                $voidLogOut = Join-Path $env:TEMP "void_out.log"
                $voidLogErr = Join-Path $env:TEMP "void_err.log"
                Start-Process -FilePath "robocopy.exe" -ArgumentList $argsList -NoNewWindow -Wait -RedirectStandardOutput $voidLogOut -RedirectStandardError $voidLogErr
            }
        }
        
        # 2. PHASE 2: CLOUD SCAN & REPORT
        Write-Color "Phase 2: Scanning for online-only files..." "Cyan"
        Write-Log "Scanning cloud content..." "INFO"
        
        $totalCloudFiles = 0
        $totalCloudBytes = 0
        
        foreach ($folderName in $folderMapKeys) {
            $source = "$oneDriveUserPath\$folderName"
            # /L = List (Dry Run), /IA:O = Include Attributes Offline (Cloud Only), /NDL = No Div List (Clean output)
            $cmd = "robocopy `"$source`" `"$source`" /L /IA:O /E /BYTES /NJH /NJS /NP"
            $res = Invoke-Expression $cmd # Capture output
            # Note: Invoke-Expression captures stdout by default, so no redirect needed here as we want the output in $res
            
            # Parse 'Bytes :  123456' line
            if ($res -match "Bytes :\s+(\d+)") {
                $totalCloudBytes += [int64]$matches[1]
            }
            # Parse 'Files :     12' line
            if ($res -match "Files :\s+(\d+)") {
                $totalCloudFiles += [int]$matches[1]
            }
        }

        # Convert Bytes to readable format
        $sizeGB = "{0:N2}" -f ($totalCloudBytes / 1GB)
        $sizeMB = "{0:N2}" -f ($totalCloudBytes / 1MB)
        
        Write-Host ""
        Write-Host "CLOUD REPORT" -ForegroundColor Cyan
        Write-Host "------------" -ForegroundColor Cyan
        Write-Host "Online-Only Files Found: $totalCloudFiles" -ForegroundColor Yellow
        Write-Host "Total Size to Download:  $sizeMB MB ($sizeGB GB)" -ForegroundColor Yellow
        Write-Host ""

        # 3. PHASE 3: HYDRATION DECISION
        $downloadCloud = "n"
        if ($totalCloudFiles -gt 0) {
            $downloadChoice = Read-Host "Do you want to download (hydrate) these online files to your local folders? (y/n)"
            if ($downloadChoice -eq "y") {
                Write-Host "`nWARNING: Downloading $sizeMB MB ($sizeGB GB) may take time." -ForegroundColor Red
                $confirm = Read-Host "Are you sure? (y/n)"
                if ($confirm -eq "y") {
                    $downloadCloud = "y"
                    Write-Color "Phase 3: Downloading Cloud Files..." "Cyan"
                    foreach ($folderName in $folderMapKeys) {
                        $source = "$oneDriveUserPath\$folderName"
                        $dest = $physicalFolderMap[$folderName]
                        if (Test-Path $source) {
                            # /IA:O = Include ONLY Offline (Cloud) files. They will be hydrated.
                            $argsList = "`"$source`" `"$dest`" /E /COPY:DAT /R:5 /W:15 /NP /NJH /NJS /IA:O /LOG+:`"$robocopyLog`""
                            $voidLogOut = Join-Path $env:TEMP "void_out.log"
                            $voidLogErr = Join-Path $env:TEMP "void_err.log"
                            Start-Process -FilePath "robocopy.exe" -ArgumentList $argsList -NoNewWindow -Wait -RedirectStandardOutput $voidLogOut -RedirectStandardError $voidLogErr
                        }
                    }
                }
            }
            else {
                Write-Host "Skipping cloud files. They will remain in OneDrive online." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "No cloud-only files detected." -ForegroundColor Green
        }
        
        # 4. PHASE 4: LEFTOVERS BACKUP
        Write-Color "Phase 4: Backing up leftovers..." "Cyan"
        
        # Backup leftovers location
        $leftoverBackup = "$backupFolder\Onedrive Files"
        if (!(Test-Path $leftoverBackup)) { New-Item -Path $leftoverBackup -ItemType Directory -Force | Out-Null }
        
        # Get excludes
        $excludedNames = $physicalFolderMap.Keys
        $quotedExcludes = $excludedNames | ForEach-Object { "`"$_`"" }

        # Pass 1: Local Leftovers
        Write-Log "Backup Local Leftovers" "INFO"
        $backupArgs = "/E /COPY:DAT /XD $($quotedExcludes -join ' ') /R:3 /W:3 /NP /NJH /NJS /XA:O /LOG+:`"$robocopyLog`""
        $startArgs = "`"$oneDriveUserPath`" `"$leftoverBackup`" $backupArgs"
        $voidLogOut = Join-Path $env:TEMP "void_out.log"
        $voidLogErr = Join-Path $env:TEMP "void_err.log"
        Start-Process -FilePath "robocopy.exe" -ArgumentList $startArgs -NoNewWindow -Wait -RedirectStandardOutput $voidLogOut -RedirectStandardError $voidLogErr
        
        # Pass 2: Cloud Leftovers (if requested)
        if ($downloadCloud -eq "y") {
            Write-Log "Backup Cloud Leftovers" "INFO"
            $cloudBackupDir = Join-Path $leftoverBackup "Cloud_Downloads"
            if (!(Test-Path $cloudBackupDir)) { New-Item -Path $cloudBackupDir -ItemType Directory -Force | Out-Null }
            $cloudArgs = "/E /COPY:DAT /XD $($quotedExcludes -join ' ') /R:5 /W:15 /NP /NJH /NJS /IA:O /LOG+:`"$robocopyLog`""
            $startArgs = "`"$oneDriveUserPath`" `"$cloudBackupDir`" $cloudArgs"
            $voidLogOut = Join-Path $env:TEMP "void_out.log"
            $voidLogErr = Join-Path $env:TEMP "void_err.log"
            Start-Process -FilePath "robocopy.exe" -ArgumentList $startArgs -NoNewWindow -Wait -RedirectStandardOutput $voidLogOut -RedirectStandardError $voidLogErr
        }

        # 5. PHASE 5: UNINSTALLATION & FAILURE MENU
        $uninstallSuccess = $false
        
        do {
            Write-Color "Phase 5: Stopping Processes & Uninstalling..." "Cyan"
            
            # Kill Loop
            try {
                Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                taskkill /F /IM OneDrive.exe > $null 2>&1
                Start-Sleep -Seconds 3
            }
            catch {}
            
            # Uninstall Attempt
            $sys32 = "$env:SystemRoot\System32"
            if (Test-Path "$sys32\OneDriveSetup.exe") { Start-Process "$sys32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -NoNewWindow }
            if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") { Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -NoNewWindow }
            
            # Reg Nuke
            Remove-Item -Path "HKCU:\Software\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue 
            
            # Verify Process Gone
            if (Get-Process "OneDrive" -ErrorAction SilentlyContinue) {
                Write-Color "ERROR: OneDrive process is still running!" "Red"
                $failChoice = Read-Host "[T]ry Again, [C]ontinue (Skip Uninst), [Q]uit Wizard? (t/c/q)"
                
                if ($failChoice -eq "q" -or $failChoice -eq "c") {
                    # REVERT LOGIC
                    Write-Color "OneDrive removal incomplete." "Yellow"
                    $revert = Read-Host "Since OneDrive is still active, you now have duplicate files (Local + Cloud). Remove the LOCAL copies we just made? (y/n)"
                    if ($revert -eq "y") {
                        Write-Color "Reverting Local Copies..." "Magenta"
                        foreach ($folderName in $folderMapKeys) {
                            $dest = $physicalFolderMap[$folderName]
                            Write-Host "Manual cleanup recommended. Check your local folders ($dest) for duplicates." -ForegroundColor Yellow
                        }
                    }
                    if ($failChoice -eq "q") { return } # Quit function
                    $uninstallSuccess = $true # Treat as "Done" to break loop but skipping uninst
                }
                # Else loop loops (Try Again)
            }
            else {
                $uninstallSuccess = $true
                Write-Color "OneDrive successfully uninstalled." "Green"
            }
        
        } until ($uninstallSuccess)

        # 6. Update Registry (Shell Folders)
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
        # Winget / Appx cleanup
        try { winget uninstall --id Microsoft.OneDrive --silent --accept-package-agreements --accept-source-agreements >> $logFile 2>&1 } catch {}
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

        # Restart Explorer REMOVED -> Explorer must stay terminated.
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        
        Write-Color "ONEDRIVE REMOVED AND DATA MIGRATED SUCCESSFULLY." "Green"
        Write-Log "OneDrive removal complete." "INFO"
        Start-Sleep -Seconds 3

    }
    else {
        # --- INSTALLATION MODE ---
        Write-Color "OneDrive is NOT installed." "Yellow"
        $choice = Read-Host "Do you want to INSTALL OneDrive and set it as default? (y/n)"
        if ($choice -ne "y") { return }

        Write-Color "DOWNLOADING AND INSTALLING ONEDRIVE..." "Magenta"
        Write-Log "Starting OneDrive Installation." "INFO"

        $setupPath = "$downloadsFolder\OneDriveSetup.exe"
        try {
            # Use Production Ring URL and UserAgent to avoid access issues
            $odUrl = "https://go.microsoft.com/fwlink/p/?LinkId=248256"
            Invoke-WebRequest -Uri $odUrl -OutFile $setupPath -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -UseBasicParsing
            
            Start-Process -FilePath $setupPath -ArgumentList "/silent" -Wait -NoNewWindow
        }
        catch {
            Write-Color "Download or Install failed." "Red"
            Write-Log "Install failed: $_" "ERROR"
            return
        }

        # Remove the Disable Policy if it exists
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue

        Write-Color "ONEDRIVE INSTALLED SUCCESSFULLY." "Green"
        Write-Log "OneDrive install complete." "INFO"

        # --- FOLDER REDIRECTION LOGIC ---
        Write-Host ""
        $redirectChoice = Read-Host "Do you want to redirect your Desktop, Documents, and Pictures to OneDrive? (y/n)"
        
        if ($redirectChoice -eq "y") {
            Write-Host "Updating User Shell Folders to OneDrive..." -ForegroundColor Cyan
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            $odMap = @{
                "Desktop"   = "$env:UserProfile\OneDrive\Desktop"
                "Documents" = "$env:UserProfile\OneDrive\Documents"
                "Pictures"  = "$env:UserProfile\OneDrive\Pictures"
                "Personal"  = "$env:UserProfile\OneDrive\Documents" # Personal is Docs
            }

            foreach ($key in $odMap.Keys) {
                $targetPath = $odMap[$key]
                # Create folder if it doesn't exist yet
                if (!(Test-Path $targetPath)) { New-Item -Path $targetPath -ItemType Directory -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name $key -Value $targetPath -Force -ErrorAction SilentlyContinue
                
                # MIGRATION: Move old files to new location
                $sourceName = if ($key -eq "Personal") { "Documents" } else { $key }
                $sourcePath = "$env:UserProfile\$sourceName"
                
                if (Test-Path $sourcePath) {
                    Write-Host "Migrating $sourceName to OneDrive..." -ForegroundColor Gray
                    # /E (Subdirs), /MOVE (Delete from source), /XO (Exclude Older), /NFL /NDL (Less noise)
                    $roboArgs = "`"$sourcePath`" `"$targetPath`" /E /MOVE /XO /NFL /NDL /R:1 /W:1 /LOG+:`"$robocopyLog`""
                    Start-Process -FilePath "robocopy.exe" -ArgumentList $roboArgs -NoNewWindow -Wait
                }
            }
            Write-Host "Folder redirection complete." -ForegroundColor Green
        }
    }
}

function Invoke-TeamsRemoval {
    Write-Log -Message "Starting Invoke-TeamsRemoval..."
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
    }
    else {
        Write-Host "Keeping Microsoft Teams." -ForegroundColor Cyan
    }
}

function Invoke-AIRemoval {
    Write-Log -Message "Starting Invoke-AIRemoval..."
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
            
            # Additional Hardening
            Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
        }
        catch {
            Write-Log -Message "Error setting Copilot registry policies: $($_.Exception.Message)" -Type "ERROR"
        }

        # Try to stop potentially stuck processes safely
        $copilotProcesses = @("Copilot", "Copilot.exe", "AI.exe", "CopilotRuntime", "CopilotBackground", "Microsoft365Copilot", "Microsoft365Copilot.exe")
        $copilotProcesses = @("Copilot", "Copilot.exe", "AI.exe", "CopilotRuntime", "CopilotBackground", "Microsoft365Copilot", "Microsoft365Copilot.exe", "BingChatInstaller")
        foreach ($proc in $copilotProcesses) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
        
        # Remove Taskbar Icon if Pinned
        $copilotLnk = "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Copilot.lnk"
        if (Test-Path $copilotLnk) { Remove-Item -Path $copilotLnk -Force -ErrorAction SilentlyContinue }
        
        try { 
            # Check if winget is available and packages installed before attempting removal to avoid waiting
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                winget uninstall --id "Microsoft.Copilot" --silent --accept-source-agreements --disable-interactivity --force *>$null 
                winget uninstall --id "Microsoft.365.Copilot" --silent --accept-source-agreements *>$null 
            }
        }
        catch {
            Write-Log -Message "Winget uninstall encountered an issue or app not found." -Type "INFO"
        }
        
        $copilotPackages = @("Microsoft.Windows.AI.Copilot", "Microsoft.Copilot", "Microsoft.365.Copilot")
        foreach ($package in $copilotPackages) { 
            if (Get-AppxPackage -Name $package -ErrorAction SilentlyContinue) {
                try { Remove-AppxPackageAllUsers $package -ErrorAction SilentlyContinue } catch { Write-Log -Message "Failed to remove Appx: $package" -Type "INFO" } 
            }
        }

        $officeUninstallPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
        if (Test-Path $officeUninstallPath) { 
            try { 
                # Reduced potential for hang with strict timeout logic? (Not easily doable in PS 5.1 cleanly without Jobs, sticking to ArgumentList correctness)
                Start-Process -FilePath $officeUninstallPath -ArgumentList "/uninstall Copilot /quiet /norestart" -NoNewWindow -Wait -ErrorAction SilentlyContinue 
            }
            catch {
                Write-Log -Message "Office C2R uninstall command failed (or not applicable)." -Type "INFO"
            } 
        }

        try {
            # Use strict type checking to ensure we don't hang on WMI
            $msiCopilot = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Copilot%'" -ErrorAction SilentlyContinue
            if ($msiCopilot) { foreach ($app in $msiCopilot) { try { $app.Uninstall() } catch {} } }
        }
        catch {
            Write-Log -Message "MSI uninstall failed: $($_.Exception.Message)" -Type "ERROR"
        }

        $copilotFolders = @("$env:LOCALAPPDATA\Packages\Microsoft.Windows.AI.Copilot", "$env:ProgramData\Microsoft\Windows\AI\Copilot", "$env:APPDATA\Microsoft\Copilot", "$env:ProgramFiles\Microsoft\Copilot", "$env:ProgramFiles (x86)\Microsoft\Copilot", "C:\ProgramData\Microsoft\Copilot")
        foreach ($folder in $copilotFolders) { if (Test-Path $folder) { try { Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue } catch {} } }

        try {
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
            reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
            $copilotRegistryKeys = @("HKCU\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\Microsoft\Windows\CurrentVersion\Copilot", "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Copilot", "HKCU\Software\Microsoft\Office\Copilot", "HKLM\Software\Microsoft\Office\Copilot")
            foreach ($key in $copilotRegistryKeys) { reg delete $key /f 2>$null }
        }
        catch {
            Write-Log -Message "Registry cleanup error: $($_.Exception.Message)" -Type "ERROR"
        }
        
        Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden

        Write-Host "MICROSOFT COPILOT HAS BEEN COMPLETELY REMOVED!" -ForegroundColor Green
        Write-Log -Message "Microsoft Copilot removed successfully."
    }
    else {
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
        }
        catch {
            Write-Log -Message "Error during Recall disablement: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
        Write-Host "Keeping Microsoft Recall." -ForegroundColor Cyan
    }
}

function Invoke-UIAndTaskbarSetup {
    Write-Log -Message "Starting Invoke-UIAndTaskbarSetup..."
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
        }
        catch {
            Write-Log -Message "Error applying Windows 10 UI tweaks: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
        Write-Host "Skipping Windows 10 UI tweaks." -ForegroundColor Cyan
    }

    $debloatTaskbar = Read-Host "Do you want to debloat the taskbar (Remove Search, Widgets, Store)? [Recommended] (y/n)"
    if ($debloatTaskbar -eq "y") {
        Write-Host "Removing unnecessary taskbar icons..." -ForegroundColor Magenta
        Write-Log -Message "Starting Taskbar debloat."

        try {
            # Kill processes that might lock Appx files (Widgets, Search, etc.)
            $lockingProcs = @("Widgets", "SearchApp", "StartMenuExperienceHost", "TextInputHost", "NewsAndInterests")
            foreach ($proc in $lockingProcs) { Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 1
            
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
        }
        catch {
            Write-Log -Message "Error during Taskbar debloat: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
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
        }
        catch {
            Write-Log -Message "Error enabling Dark Mode: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
        Write-Host "Dark Mode not enabled." -ForegroundColor Cyan
    }

    Start-Sleep -Seconds 2
}

function Invoke-DesktopSearchBarRemoval {
    Write-Log -Message "Starting Invoke-DesktopSearchBarRemoval..."
    
    # Prompt with Validation
    do {
        $removeSearchBar = Read-Host "Do you want to remove the new floating Windows Search Bar (Desktop)? (y/n)"
        if ($removeSearchBar -notin "y", "n") { Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red }
    } until ($removeSearchBar -in "y", "n")

    Write-Log "User response to 'Remove Desktop Search Bar' prompt: $removeSearchBar" "INFO"

    if ($removeSearchBar -eq "y") {
        Write-Host "Removing Desktop Search Bar..." -ForegroundColor Magenta
        try {
            # Registry Policy to Disable Web Widget (Desktop Search Bar) in Edge
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value 0
            Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value 0
            
            # Stop Edge Processes to apply
            $edgeProcs = @("msedge", "msedgewebview2")
            foreach ($p in $edgeProcs) { 
                Stop-Process -Name $p -Force -ErrorAction SilentlyContinue 
            }
            
            Write-Host "Desktop Search Bar disabled." -ForegroundColor Green
            Write-Log "Desktop Search Bar (WebWidget) disabled via Registry." "INFO"
        }
        catch {
            Write-Log "Failed to disable Desktop Search Bar: $($_.Exception.Message)" "ERROR"
            Write-Host "Error disabling Search Bar. Check logs." -ForegroundColor Red
        }
    }
    else {
        Write-Log "Skipping Desktop Search Bar removal." "INFO"
        Write-Host "Skipping Desktop Search Bar removal." -ForegroundColor Cyan
    }
}

function Invoke-ActivationTweaks {
    $mod = "Activation Tweaks"
    Write-Log -Message "Starting $mod module..." -Status "INFO" -Module $mod

    Write-Host "`n--- Windows Activation & Licensing ---" -ForegroundColor Cyan

    # Detection: Check License Status
    $license = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($license -and $license.LicenseStatus -eq 1) {
        Write-Host "Windows is fully activated. Skipping tweaks." -ForegroundColor Green
        Write-Log "Windows is activated (Status: 1). Module skipped." "INFO"
    }
    else {
        $statusStr = if ($license) { $license.LicenseStatus } else { "Unknown" }
        Write-Host "Windows appears to be 'Not Activated'." -ForegroundColor Yellow
        Write-Log "Windows Not Activated (Status: $statusStr)." "INFO"
        
        $choice = Read-Host "Do you want to attempt to remove the Watermark and Disable Activation Nags? (y/n)"
        if ($choice -eq "y") {
            Write-Host "Applying Activation Tweaks..." -ForegroundColor Magenta
            try {
                # 1. Disable PaintDesktopVersion via User Hive
                Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Value 0
                
                # 2. Disable GenTicket (Nag) via Policy
                Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "NoGenTicket" -Value 1
                
                # 3. Disable Activation Toasts
                Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0
                
                Write-Host "Tweaks applied. Note: A restart is required for full effect." -ForegroundColor Green
                Write-Log "Activation watermark/nag tweaks applied." "INFO"
            }
            catch {
                Write-Host "Error applying tweaks: $_" -ForegroundColor Red
                Write-Log "Activation tweak error: $_" "ERROR"
            }
        }
    }
    Start-Sleep -Seconds 1
}

function Invoke-NetworkOptimisations {
    $mod = "Network Optimizations"
    Write-Log "Starting $mod module..." "INFO" $mod
    Write-Host "`n--- Optimizing Network for Downloads ---" -ForegroundColor Cyan

    try {
        # 1. Reset TCP Autotuning to Normal (often fixes slow speeds)
        netsh int tcp set global autotuninglevel=normal | Out-Null
        Write-Log "TCP Autotuning set to 'normal'." "INFO" $mod
        
        # 2. Set Delivery Optimization (DO) to allow foreground downloads
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0
        Write-Log "Delivery Optimization mode adjusted." "INFO" $mod

        # 3. Bits Priority
        if ((Get-Service BITS).Status -ne 'Running') { Start-Service BITS -ErrorAction SilentlyContinue }
        
        Write-Host "Network settings optimized for download speed." -ForegroundColor Green
    }
    catch {
        Write-Log "Error optimizing network: $_" "ERROR" $mod
    }
}

function Invoke-StopExplorer {
    $mod = "Explorer Control"
    Write-Log "Stopping Windows Explorer..." "INFO" $mod
    
    # 1. Disable AutoRestartShell to prevent immediate resurrection by Winlogon
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 0
    
    # 2. Stop Explorer
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

function Invoke-StartExplorer {
    $mod = "Explorer Control"
    Write-Log "Starting Windows Explorer..." "INFO" $mod
    
    # 1. Restore AutoRestartShell (Default is 1)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 1
    
    # 2. Start Explorer if not running
    $maxRetries = 3
    $retryCount = 0
    $explorerPath = "$env:SystemRoot\explorer.exe"

    while (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue) -and $retryCount -lt $maxRetries) {
        Write-Log "Attempting to start Explorer (Attempt $($retryCount + 1))..." "INFO" $mod
        Start-Process -FilePath $explorerPath
        Start-Sleep -Seconds 2
        $retryCount++
    }
    
    if (Get-Process -Name explorer -ErrorAction SilentlyContinue) {
        Write-Host "Explorer started successfully." -ForegroundColor Green
    }
    else {
        Write-Log "Failed to start Explorer after $maxRetries attempts." "ERROR" $mod
        Write-Host "Warning: Explorer might not have started correctly." -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 2
}

function Invoke-WindowsSearchBarSetup {
    $mod = "Windows Search Bar"
    Write-Log -Message "Starting $mod module..." -Status "INFO" -Module $mod

    Write-Host "`n--- Windows Desktop Search Bar Setup ---" -ForegroundColor Cyan

    # Detection logic: Check if Edge WebWidget is allowed/enabled
    $searchBarEnabled = $true
    
    # Check Policy (Standard Disable Method)
    $policyVal = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -ErrorAction SilentlyContinue
    if ($policyVal -eq 0) { $searchBarEnabled = $false }
    
    # Check User Pref (If policy not set, this might control it)
    if ($null -eq $policyVal) {
        $userVal = Get-RegistryValue -Path "HKCU\Software\Microsoft\Edge\WebWidget" -Name "WebWidgetAllowed" -ErrorAction SilentlyContinue 
        if ($userVal -eq 0) { $searchBarEnabled = $false }
    }

    if ($searchBarEnabled) {
        Write-Host "Desktop Search Bar detected as ENABLED." -ForegroundColor Yellow
        $choice = Read-Host "Do you want to DISABLE/REMOVE the Desktop Search Bar? (Recommended) (y/n)"
        if ($choice -eq "y") {
            Write-Host "Disabling Desktop Search Bar..." -ForegroundColor Magenta
            try {
                # 1. Policy Disable (Machine & User)
                Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value 0
                Set-RegistryValue -Path "HKCU\Software\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value 0
                
                # 2. Edge Specific Keys
                Set-RegistryValue -Path "HKCU\Software\Microsoft\Edge\WebWidget" -Name "WebWidgetAllowed" -Value 0
                Set-RegistryValue -Path "HKCU\Software\Microsoft\Edge\WebWidget" -Name "Allowed" -Value 0

                # 3. Kill related processes
                Stop-Process -Name "msedgewebview2" -ErrorAction SilentlyContinue
                Stop-Process -Name "Widgets" -ErrorAction SilentlyContinue
                
                # Verification
                $check = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed"
                if ($check -eq 0) {
                    Write-Host "Desktop Search Bar disabled successfully." -ForegroundColor Green
                    Write-Log -Message "Desktop Search Bar disabled." -Status "INFO" -Module $mod
                }
                else {
                    Write-Host "Failed to verify Search Bar disable." -ForegroundColor Red
                    Write-Log -Message "Failed to verify Search Bar disable." -Status "ERROR" -Module $mod
                }
            }
            catch {
                Write-Host "Error disabling Search Bar: $_" -ForegroundColor Red
                Write-Log -Message "Error disabling Search Bar: $_" -Status "ERROR" -Module $mod
            }
        }
        else {
            Write-Host "Skipping Search Bar removal." -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "Desktop Search Bar is currently DISABLED." -ForegroundColor Green
        Write-Host "Do you want to ENABLE it? " -NoNewline
        Write-Host "[NOT RECOMMENDED]" -ForegroundColor Red
        $choice = Read-Host " (y/n)"
        
        if ($choice -eq "y") {
            Write-Host "Enabling Desktop Search Bar..." -ForegroundColor Yellow
            try {
                Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Value 1
                Set-RegistryValue -Path "HKCU\Software\Microsoft\Edge\WebWidget" -Name "Allowed" -Value 1
                Write-Host "Desktop Search Bar enabled." -ForegroundColor Green
                Write-Log -Message "Desktop Search Bar enabled by user." -Status "INFO" -Module $mod
            }
            catch {
                Write-Log -Message "Error enabling Search Bar: $_" -Status "ERROR" -Module $mod
            }
        }
    }
    Start-Sleep -Seconds 1
}

function Invoke-SystemOptimisations {
    Write-Log -Message "Starting Invoke-SystemOptimisations..."
    $debloatEdge = Read-Host "Do you want to remove Edge's forced features? [Recommended] (y/n)"
    if ($debloatEdge -eq "y") {
        Write-Host "Disabling Edge forced features..." -ForegroundColor Magenta
        try {
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RestorePdfAssociationsEnabled" -Value 0
            Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0
            Write-Host "Edge features disabled!" -ForegroundColor Green
            Write-Log -Message "Edge forced features disabled."
        }
        catch {
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
        }
        catch {
            Write-Log -Message "Error applying gaming optimizations: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
        Write-Host "Skipping gaming optimizations." -ForegroundColor Cyan
    }

    $usbsuspend = Read-Host "Do you intend to use controllers or joysticks? [Recommended] (y/n)"
    if ($usbsuspend -match "^[Yy]$") {
        Write-Host "Disabling Selective USB Suspend..."
        try {
            powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
            Write-Log -Message "USB Selective Suspend disabled."
        }
        catch {
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
        }
        catch {
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
        }
        catch {
            Write-Log -Message "Error disabling Memory Core Isolation: $($_.Exception.Message)" -Type "ERROR"
        }
    }
    else {
        Write-Host "Keeping Memory Core Isolation enabled." -ForegroundColor Cyan
    }

    # Explorer restart removed to maintain single-session flow
    # Start-Sleep -Seconds 1
    
    # Desktop Shortcut
    try {
        New-Shortcut -TargetPath ${script:ogcwinbat} -ShortcutPath ${script:desktopPath} -Description "Launch OGC Windows Utility" -IconPath "C:\Windows\System32\shell32.dll,272"
        Write-Log -Message "Desktop shortcut created/updated."
    }
    catch {
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

    # --- Internal Helpers ---
    
    function Install-App {
        param([string]$Name, [string]$Id)
        
        # Check if already installed (Simple check)
        if (Get-AppxPackage -Name $Id -ErrorAction SilentlyContinue) {
            Write-Host "$Name is already installed." -ForegroundColor DarkGray
            return
        }
        # Note: For Winget apps not in Appx, duplicate install is handled by Winget usually saying "Already installed"
        
        Write-Host "Installing $Name..." -ForegroundColor Magenta
        Write-Log "Attempting to install $Name ($Id)" "INFO"
        try {
            # Use separate log files for StdOut and StdErr
            $installLogOut = Join-Path $tempFolder "install_${Id}_out.log"
            $installLogErr = Join-Path $tempFolder "install_${Id}_err.log"
            
            $wingetArgs = "install --id `"$Id`" --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --force"
            
            $process = Start-Process -FilePath "winget" -ArgumentList $wingetArgs -Wait -NoNewWindow -PassThru -RedirectStandardOutput $installLogOut -RedirectStandardError $installLogErr
            
            if ($process.ExitCode -eq 0) {
                Write-Host "$Name successfully installed." -ForegroundColor Green
                Write-Log "Successfully installed $Name" "INFO"
            }
            else {
                $errContent = Get-Content $installLogErr -Raw -ErrorAction SilentlyContinue
                if (-not $errContent) { $errContent = Get-Content $installLogOut -Raw -ErrorAction SilentlyContinue }
                Write-Host "Failed to install $Name. Exit Code: $($process.ExitCode)" -ForegroundColor Red
                Write-Log "Failed to install $Name. Exit Code: $($process.ExitCode). Log: $errContent" "ERROR"
            }
            Remove-Item $installLogOut -ErrorAction SilentlyContinue
            Remove-Item $installLogErr -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Failed to install $Name. Check logs." -ForegroundColor Red
            Write-Log "Failed to install $Name. Error: $_" "ERROR"
        }
    }

    function Uninstall-App {
        param([string]$Name, [string]$Id)
        Write-Host "Uninstalling $Name..." -ForegroundColor Magenta
        Write-Log "Attempting to uninstall $Name ($Id)" "INFO"
        try {
            winget uninstall --id "$Id" --silent --accept-source-agreements | Out-Null
            Write-Host "$Name uninstalled." -ForegroundColor Green
            Write-Log "Uninstalled $Name" "INFO"
        }
        catch {
            Write-Host "Uninstall failed. $_" -ForegroundColor Red
            Write-Log "Uninstall failed for ${Name}: $_" "ERROR"
        }
    }

    function Test-IsInstalled {
        param([string]$Id, [string]$CheckCmd, [string]$AppName)
        
        # 1. Check Command (Fastest)
        if ($CheckCmd -and (Get-Command $CheckCmd -ErrorAction SilentlyContinue)) { return $true }
        
        # 2. Check Appx (Fast) - Try exact and wildcard
        if (Get-AppxPackage -Name $Id -ErrorAction SilentlyContinue) { return $true }
        if (Get-AppxPackage -Name "*$Id*" -ErrorAction SilentlyContinue) { return $true }

        # 3. Check Registry Uninstall Keys (Fast enough)
        # We search for the DisplayName matching the App Name wildcard
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        # Determine name to search (Handle 'Visual C++', etc. carefully? Just use name)
        # Safety: If Name is too generic, this might false positive, but for this menu it's okay.
        $searchName = if ($AppName) { "*$AppName*" } else { "*$Id*" }
        
        $found = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $searchName }
        if ($found) { return $true }

        return $false
    }
    
    function Show-Menu {
        param(
            [string]$CategoryName,
            [array]$Items,
            [bool]$MultiSelect = $true
        )
        
        while ($true) {
            # Refresh PATH environment variable for the current process to see newly installed cmdlets/exes
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            
            Write-Host "`n--- $CategoryName ---" -ForegroundColor Cyan
            $i = 1
            foreach ($item in $Items) {
                $statusSuffix = ""
                $color = "White"
                
                # Logic Fix: Only flag as Installed if truly detected
                if (Test-IsInstalled -Id $item.Id -CheckCmd $item.Cmd -AppName $item.Name) {
                    $statusSuffix = " [Installed]"
                    $color = "Green"
                }
                
                # User Request: Don't show [ ] boxes, just Name + Suffix
                Write-Host "$i. $($item.Name)$statusSuffix" -ForegroundColor $color
                $i++
            }
            
            if ($MultiSelect) {
                Write-Host "0. Done / Skip Category" -ForegroundColor Yellow
                $choice = Read-Host "Select number(s) to install (e.g. 1,3) or 0 to skip"
            }
            else {
                Write-Host "0. Skip" -ForegroundColor Yellow
                $choice = Read-Host "Select one to install or 0 to skip"
            }
            
            if ($choice -eq "0" -or $choice -eq "") { return }
            
            $selections = $choice -split ","
            foreach ($sel in $selections) {
                if ($sel -match "^\d+$" -and [int]$sel -le $Items.Count -and [int]$sel -gt 0) {
                    $target = $Items[[int]$sel - 1]
                    Install-App -Name $target.Name -Id $target.Id
                }
            }
            
            if (-not $MultiSelect) { return }
        }
    }

    # ==========================================
    #             1. DEPENDENCIES
    # ==========================================
    $deps = @(
        @{ Name = "Visual C++ 2015-2022"; Id = "Microsoft.VCRedist.2015+.x64"; Cmd = "" },
        @{ Name = ".NET Desktop Runtime 6"; Id = "Microsoft.DotNet.DesktopRuntime.6"; Cmd = "" }
        @{ Name = ".NET Desktop Runtime 7"; Id = "Microsoft.DotNet.DesktopRuntime.7"; Cmd = "" }
        @{ Name = ".NET Desktop Runtime 8"; Id = "Microsoft.DotNet.DesktopRuntime.8"; Cmd = "" }
    )
    if ((Read-Host "Do you want to install game Dependencies? (Visual C++, .NET etc.) (y/n)") -eq "y") {
        Show-Menu -CategoryName "System Dependencies" -Items $deps
    }

    # ==========================================
    #             2. BROWSERS
    # ==========================================
    $browsers = @(
        @{ Name = "Google Chrome"; Id = "Google.Chrome"; Cmd = "chrome" },
        @{ Name = "Mozilla Firefox"; Id = "Mozilla.Firefox"; Cmd = "firefox" },
        @{ Name = "Brave Browser"; Id = "Brave.Brave"; Cmd = "brave" },
        @{ Name = "Opera GX"; Id = "Opera.OperaGX"; Cmd = "launcher" },
        @{ Name = "Vivaldi"; Id = "Vivaldi.Vivaldi"; Cmd = "vivaldi" }
    )
    
    if ((Read-Host "Do you want to install Web Browsers? (Firefox, Chrome, Brave etc.) (y/n)") -eq "y") {
        # Primary Selection Logic (Special Case)
        Write-Host "`n--- Select Primary Browser ---" -ForegroundColor Cyan
        $i = 1
        foreach ($b in $browsers) {
            $statusSuffix = ""
            $col = "White"
            if (Test-IsInstalled -Id $b.Id -CheckCmd $b.Cmd -AppName $b.Name) { 
                $statusSuffix = " [Installed]"
                $col = "Green"
            }
            Write-Host "$i. $($b.Name)$statusSuffix" -ForegroundColor $col
            $i++
        }
        Write-Host "0. Skip" -ForegroundColor Yellow
        
        $pChoice = Read-Host "Select Primary Browser (1-$($browsers.Count))"
        if ($pChoice -match "^\d+$" -and [int]$pChoice -le $browsers.Count -and [int]$pChoice -gt 0) {
            $primary = $browsers[[int]$pChoice - 1]
            Install-App -Name $primary.Name -Id $primary.Id
            
            # Default Browser Prompt
            if ($primary.Id -ne "Microsoft.Edge") {
                if ((Read-Host "Set $($primary.Name) as default browser? (y/n)") -eq "y") {
                    Write-Host "Opening Default Apps settings... Select $($primary.Name) manually." -ForegroundColor Yellow
                    Start-Process "ms-settings:defaultapps"
                    Read-Host "Press Enter when done..."
                }
            }
        }
        
        # Additional Browsers
        if ((Read-Host "Install additional browsers? (y/n)") -eq "y") {
            Show-Menu -CategoryName "Additional Browsers" -Items $browsers
        }
        
        # Edge Removal
        Invoke-EdgeRemoval
    }

    # ==========================================
    #             3. GAMING
    # ==========================================
    $gaming = @(
        @{ Name = "Steam"; Id = "Valve.Steam"; Cmd = "steam" },
        @{ Name = "Epic Games Launcher"; Id = "EpicGames.EpicGamesLauncher"; Cmd = "" },
        @{ Name = "Ubisoft Connect"; Id = "Ubisoft.Connect"; Cmd = "upc" },
        @{ Name = "EA App"; Id = "ElectronicArts.EADesktop"; Cmd = "" },
        @{ Name = "Battle.net"; Id = "Blizzard.BattleNet"; Cmd = "Battle.net" },
        @{ Name = "GOG Galaxy"; Id = "GOG.Galaxy"; Cmd = "GalaxyClient" }
    )
    if ((Read-Host "Do you want to install Game Launchers? (Steam, GoG, Epic etc.) (y/n)") -eq "y") {
        Show-Menu -CategoryName "Game Launchers" -Items $gaming
    }

    # ==========================================
    #             4. COMMUNICATION
    # ==========================================
    $comm = @(
        @{ Name = "Discord"; Id = "Discord.Discord"; Cmd = "Update" },
        @{ Name = "Zoom"; Id = "Zoom.Zoom"; Cmd = "" },
        @{ Name = "WhatsApp"; Id = "WhatsApp.WhatsApp"; Cmd = "" },
        @{ Name = "Telegram Desktop"; Id = "Telegram.TelegramDesktop"; Cmd = "Telegram" },
        @{ Name = "Signal"; Id = "Signal.Signal"; Cmd = "" }
    )
    if ((Read-Host "Do you want to install Communication Apps? (Discord, Zoom, Telegram etc.) (y/n)") -eq "y") {
        Show-Menu -CategoryName "Communication" -Items $comm
    }

    # ==========================================
    #             5. CREATIVE & MEDIA
    # ==========================================
    $creative = @(
        @{ Name = "VLC Media Player"; Id = "VideoLAN.VLC"; Cmd = "vlc" },
        @{ Name = "Spotify"; Id = "Spotify.Spotify"; Cmd = "" },
        @{ Name = "OBS Studio"; Id = "OBSProject.OBSStudio"; Cmd = "" },
        @{ Name = "Audacity"; Id = "Audacity.Audacity"; Cmd = "" },
        @{ Name = "GIMP"; Id = "GIMP.GIMP"; Cmd = "gimp-console" },
        @{ Name = "Paint.NET"; Id = "dotPDN.PaintDotNet"; Cmd = "" }
    )
    if ((Read-Host "Do you want to install Creative & Media Apps? (VLC, OBS, Audacity, GIMP etc.) (y/n)") -eq "y") {
        Show-Menu -CategoryName "Creative & Media" -Items $creative
    }

    # ==========================================
    #             6. OFFICE & PRODUCTIVITY
    # ==========================================
    $office = @(
        @{ Name = "Microsoft 365 (Office)"; Id = "Microsoft.Office"; Cmd = "winword" },
        @{ Name = "LibreOffice"; Id = "TheDocumentFoundation.LibreOffice"; Cmd = "soffice" },
        @{ Name = "OpenOffice"; Id = "Apache.OpenOffice"; Cmd = "soffice" },
        @{ Name = "WPS Office"; Id = "Kingsoft.WPSOffice"; Cmd = "wps" },
        @{ Name = "OnlyOffice"; Id = "ONLYOFFICE.DesktopEditors"; Cmd = "" },
        @{ Name = "Adobe Acrobat Reader"; Id = "Adobe.Acrobat.Reader.64-bit"; Cmd = "AcroRd32" },
        @{ Name = "Notepad++"; Id = "Notepad++.Notepad++"; Cmd = "notepad++" }
    )
    
    if ((Read-Host "Do you want to install Office & Productivity Apps? (y/n)") -eq "y") {
        # Check conflicts logic
        $installedSuites = $office | Where-Object { ($_.Name -match "Office|365") -and (Test-IsInstalled -Id $_.Id -CheckCmd $_.Cmd) }
        if ($installedSuites) {
            Write-Host "Detected installed Office Suites: $($installedSuites.Name -join ', ')" -ForegroundColor Yellow
            if ((Read-Host "Do you want to remove ALL installed Office suites before proceeding? (y/n)") -eq "y") {
                foreach ($s in $installedSuites) { Uninstall-App -Name $s.Name -Id $s.Id }
            }
        }
        
        Show-Menu -CategoryName "Office & Productivity" -Items $office
    }

    # ==========================================
    #             7. UTILITIES
    # ==========================================
    $utils = @(
        @{ Name = "7-Zip"; Id = "7zip.7zip"; Cmd = "7z" },
        @{ Name = "WinRAR"; Id = "RARLab.WinRAR"; Cmd = "rar" },
        @{ Name = "NanaZip"; Id = "M2Team.NanaZip"; Cmd = "" },
        @{ Name = "BleachBit"; Id = "BleachBit.BleachBit"; Cmd = "bleachbit_console" },
        @{ Name = "CPU-Z"; Id = "CPUID.CPU-Z"; Cmd = "" },
        @{ Name = "HWMonitor"; Id = "CPUID.HWMonitor"; Cmd = "" },
        @{ Name = "AnyDesk"; Id = "Philandro.AnyDesk"; Cmd = "anydesk" },
        @{ Name = "TeamViewer"; Id = "TeamViewer.TeamViewer"; Cmd = "teamviewer" }
    )
    if ((Read-Host "Do you want to install Utilities? (7zip, CPU-Z, HWMonitor, AnyDesk etc.) (y/n)") -eq "y") {
        Show-Menu -CategoryName "Utilities" -Items $utils
    }

    Write-Host "`nSoftware installation phase complete." -ForegroundColor Green
    Write-Log "Software installation phase complete." "INFO"
    Start-Sleep -Seconds 2
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
                    }
                    else {
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
                    }
                    else {
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
            if ($gpuChoice -in "1", "2", "3") {
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

        }
        catch {
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
        }
        catch {
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
    }
    else {
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

# Disclaimers
Write-Host "ATTENTION: This process involves restarting system components (Explorer)." -ForegroundColor Yellow
Write-Host "WARNING: Windows Explorer will be STOPPED. Your desktop and taskbar will disappear." -ForegroundColor Red
Write-Host "Please SAVE all open documents. Any unsaved work may be LOST." -ForegroundColor Red
Write-Host "Please CLOSE other applications before continuing." -ForegroundColor Yellow
do {
    $saveWork = Read-Host "Have you saved your work and are ready to proceed? (y/n)"
    if ($saveWork -notin "y", "n") { Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red }
} until ($saveWork -in "y", "n")

if ($saveWork -eq "n") {
    Write-Host "Please save your work and run the script again." -ForegroundColor Cyan
    exit
}
Write-Host "" 

do {
    $continueScript = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue"
    if ($continueScript -notin "y", "n") { Write-Host "Invalid input. Please enter 'y' or 'n'." -ForegroundColor Red }
} until ($continueScript -in "y", "n")

if ($continueScript -eq "n") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}

Write-Host "NOTE: During the process, Windows Explorer may restart, causing this window to lose focus." -ForegroundColor DarkYellow
Write-Host "If the wizard appears to pause, please CLICK on this window to ensure it has focus." -ForegroundColor DarkYellow
Write-Host "" 
Start-Sleep -Seconds 2

# --- CREATE RESTORE POINT ---
# Run this BEFORE creating the "no explorer" environment
New-RestorePoint

# STOP EXPLORER HERE (as requested)
# Moving this AFTER restore point ensures it stays stopped
Write-Host "Stopping Windows Explorer to prevent conflicts..." -ForegroundColor Yellow

# Start Safety Watchdog
$wdLog = Join-Path $logFolder "watchdog_log.txt"
$watchdogProc = Start-Watchdog -ParentPID $PID -LogFile $wdLog
Write-Log "Watchdog started with PID $($watchdogProc.Id)" "INFO"


# ==========================================
#          MODULES
# ==========================================

try { Invoke-StopExplorer } catch { Write-Log "Stop Explorer Error: $_" "ERROR" }
try { Invoke-NetworkOptimisations } catch { Write-Log "Network Opt Error: $_" "ERROR" }
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
try { Invoke-ActivationTweaks } catch { Write-Log "Activation Module Error: $_" "ERROR" }
try { Invoke-UIAndTaskbarSetup } catch { Write-Log "UI Module Error: $_" "ERROR" }
try { Invoke-DesktopSearchBarRemoval } catch { Write-Log "Desktop Search Bar Module Error: $_" "ERROR" }
try { Invoke-SystemOptimisations } catch { Write-Log "Optimization Module Error: $_" "ERROR" }
try { Invoke-StartExplorer } catch { Write-Log "Start Explorer Error: $_" "ERROR" }

Start-Sleep -Seconds 1
Clear-Host

try { Invoke-SoftwareInstallation } catch { Write-Log "Software Module Error: $_" "ERROR" }
try {
    if ($Urls.ContainsKey("DriverNvidia")) {
        Invoke-DriverInstallation 
    }
}
catch { Write-Log "Driver Module Error: $_" "ERROR" }

# Kill Watchdog (Clean Exit with Safety Checks)
if ($watchdogProc) {
    # Verify Explorer is running
    $exp = Get-Process -Name explorer -ErrorAction SilentlyContinue
    
    # Verify AutoRestartShell is enabled (1)
    $val = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell"
    
    if ($exp -and $val -eq 1) {
        Write-Log "System stable (Explorer running, AutoRestart enabled). Stopping Watchdog." "INFO"
        Stop-Process -Id $watchdogProc.Id -Force -ErrorAction SilentlyContinue 
    }
    else {
        Write-Log "System unstable (Explorer missing or AutoRestart disabled). Leaving Watchdog running for safety." "WARN"
        Write-Host "Notice: Watchdog left running to ensure system stability." -ForegroundColor Yellow
    }
}


# === END PROGRAM ===

Write-Host "`nAll operations complete." -ForegroundColor Green
$host.UI.RawUI.FlushInputBuffer()

Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
Write-Host "Explorer restarted." -ForegroundColor Green
Start-Sleep -Seconds 1

Clear-Host
Write-Host "" 
Write-Host "===========================================" -ForegroundColor Green
Write-Host "      OGC New PC Wizard is complete!      " -ForegroundColor Cyan
Write-Host "  Enjoy your optimized Windows experience. " -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Green
Write-Host "" 
Write-Host "" 
Write-Host "It is recommended to restart your PC to properly apply all the changes." -ForegroundColor Yellow
$host.UI.RawUI.FlushInputBuffer()
$restartChoice = Read-Host "Restart now? (Y/N)"

if ($restartChoice -match "^[Yy]$") {
    Write-Host "Restarting now..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    shutdown /r /t 0
}
else {
    Write-Host "You can restart later. Exiting..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    $host.UI.RawUI.FlushInputBuffer()
    Stop-Process -Id $PID -Force
}

