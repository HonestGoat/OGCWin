# OGC New Windows Setup Wizard by Honest Goat
# Version: 0.1

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
$host.UI.RawUI.WindowTitle = "OGC New Windows Wizard"
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
Write-Host ""
Write-Host ""
# Welcome and Instructions
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

# Confirm User Wants to Continue
$continueScript = Read-Host "!!! DISCLAIMER !!! You assume all risk of data loss. Press (y/n) to agree and continue"

if ($continueScript -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}


## Telemetry, Tracking and Data Collection ##
Write-Host "Disabling Telemetry, Tracking, and Data Collection..." -ForegroundColor Magenta
# Disable Telemetry in Registry
$telemetryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
)

foreach ($key in $telemetryKeys) {
    if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name AllowTelemetry -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $key -Name PublishUserActivities -Type DWord -Value 0 -Force
}

Write-Host "Registry telemetry settings updated." -ForegroundColor Green

# Disable Windows Tracking Services
Write-Host "Disabling Tracking Services..." -ForegroundColor Magenta
$trackingServices = @(
    "DiagTrack",              # Connected User Experiences and Telemetry
    "dmwappushservice",       # Device Management Wireless Application Protocol
    "Wecsvc",                 # Windows Event Collector
    "WerSvc",                 # Windows Error Reporting
    "PcaSvc",                 # Program Compatibility Assistant
    "TrkWks",                 # Distributed Link Tracking Client
    "lfsvc",                  # Geolocation service
    "MapsBroker"              # Download maps for Windows Maps app
)

foreach ($service in $trackingServices) {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled
        Write-Host "Service '$service' disabled." -ForegroundColor Green
    } else {
        Write-Host "Service '$service' not found." -ForegroundColor Yellow
    }
}

Write-Host "Tracking Services Disabled." -ForegroundColor Green

# Disable Microsoft Data Collection Scheduled Tasks
Write-Host "Disabling Microsoft Data Collection Scheduled Tasks..." -ForegroundColor Magenta
$schedulePath = "\Microsoft\Windows\Application Experience"
$tasks = @("Microsoft Compatibility Appraiser", "ProgramDataUpdater", "StartupAppTask")

foreach ($task in $tasks) {
    if (Get-ScheduledTask -TaskName $task -TaskPath $schedulePath -ErrorAction SilentlyContinue) {
        Disable-ScheduledTask -TaskName $task -TaskPath $schedulePath
        Write-Host "Scheduled Task '$task' disabled." -ForegroundColor Green
    } else {
        Write-Host "Scheduled Task '$task' not found." -ForegroundColor Yellow
    }
}

Write-Host "Telemetry Scheduled Tasks Disabled." -ForegroundColor Green

# Disable Cortana via Group Policy
Write-Host "Disabling Cortana via Group Policy..." -ForegroundColor Yellow
$gpCortanaKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $gpCortanaKey)) { New-Item -Path $gpCortanaKey -Force | Out-Null }
Set-ItemProperty -Path $gpCortanaKey -Name "AllowCortana" -Type DWord -Value 0 -Force
Write-Host "Cortana disabled via Group Policy." -ForegroundColor Green

# Stop and Kill Cortana Process
Write-Host "Stopping and killing Cortana processes..." -ForegroundColor Yellow
Stop-Process -Name "Cortana" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "SearchUI" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Uninstall Cortana (For All Users)
Write-Host "Uninstalling Cortana..." -ForegroundColor Yellow
Get-AppxPackage -Name "Microsoft.549981C3F5F10" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Cortana*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
Write-Host "Cortana uninstalled successfully." -ForegroundColor Green

# Remove Remaining Cortana Directories
Write-Host "Removing leftover Cortana folders..." -ForegroundColor Yellow
Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.549981C3F5F10" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Cortana" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\Microsoft\Cortana" -Recurse -Force -ErrorAction SilentlyContinue

# Remove Cortana from Startup
Write-Host "Removing Cortana from Startup..." -ForegroundColor Yellow
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Cortana" /f 2>$null
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Cortana" /f 2>$null

# Remove Cortana Registry Entries
Write-Host "Removing Cortana registry entries..." -ForegroundColor Yellow
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Cortana" /f 2>$null

# Block Cortana from Reinstalling via Group Policy
Write-Host "Preventing Cortana from reinstalling..." -ForegroundColor Yellow
reg add "HKLM\Software\Policies\Microsoft\Windows\Cortana" /v "DisableCortana" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
Write-Host "Cortana is blocked from reinstalling." -ForegroundColor Green

# Disable Location Tracking
Write-Host "Disabling Location Tracking..." -ForegroundColor Magenta
$locationKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (!(Test-Path $locationKey)) { New-Item -Path $locationKey -Force | Out-Null }
Set-ItemProperty -Path $locationKey -Name "EnableLocation" -Type DWord -Value 0 -Force
Write-Host "Location Tracking Disabled." -ForegroundColor Green

# Disable tips and suggestions
Write-Host "Disabling all tips, suggestions and advertisements." -ForegroundColor Magenta 

## Enable open Terminal in directory with right click
#New-Item -Path "HKCR:\Directory\Background\shell\OpenTerminalHere" -Force | Out-Null
#New-ItemProperty -Path "HKCR:\Directory\Background\shell\OpenTerminalHere" -Name "(Default)" -Value "Open in Terminal" -PropertyType String -Force | Out-Null
#New-ItemProperty -Path "HKCR:\Directory\Background\shell\OpenTerminalHere" -Name "Icon" -Value "C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_8wekyb3d8bbwe\ms-appx://Images/Square44x44Logo.altform-lightunplated_targetsize-24.png" -PropertyType String -Force | Out-Null
#New-Item -Path "HKCR:\Directory\Background\shell\OpenTerminalHere\command" -Force | Out-Null
#New-ItemProperty -Path "HKCR:\Directory\Background\shell\OpenTerminalHere\command" -Name "(Default)" -Value "wt.exe -d '%V'" -PropertyType String -Force | Out-Null


# Disable Windows junk
# Function to set registry values
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    try {
        if (-Not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    } catch {
        Write-Host "Failed to set $Name at $Path" -ForegroundColor Red
    }
}

# Disable Windows Welcome Experience
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0

# Disable Tailored Experiences
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0

# Disable App Suggestions in Start Menu
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0

# Disable Windows Tips
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0

# Disable Ads in File Explorer
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0

# Disable 'Get More Out of Windows' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0

# Disable 'Suggested Content' in Settings App
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0

# Disable 'Show Me Windows Welcome Experience' After Updates
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0

# Disable 'Suggested Apps' in Share Dialog
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0

# Disable 'Windows Spotlight' on Lock Screen
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0

# Disable 'Get Even More Out of Windows' Page in Settings
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0

# Disable 'Consumer Features' (e.g., Candy Crush installation)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

# Disable 'Microsoft Account' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.MicrosoftAccount" -Name "Enabled" -Value 0

# Disable 'Windows Defender' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0

# Disable 'Windows Update' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\WindowsUpdateClient" -Name "Enabled" -Value 0

# Disable 'OneDrive' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\OneDrive" -Name "Enabled" -Value 0

# Disable 'Get Office' Notifications
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\OfficeHub" -Name "Enabled" -Value 0

# Disable 'Suggested Apps' in Share Dialog
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0

# Disable 'Online Tips' in Settings App
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353702Enabled" -Value 0

# Disable 'Windows Ink Workspace' Suggested Apps
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Value 0
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "SuggestedAppsEnabled" -Value 0

# Disable 'Windows Spotlight' on Lock Screen
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1

# Disable 'Windows Tips' Notifications
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0

Write-Host "Tips and suggestions have now been disabled." -ForegroundColor Green
Start-Sleep -Seconds 1
Write-Host "Your privacy has been enhanced. Tracking, telemetry, data collection and suggestions have been disabled!" -ForegroundColor Green


## DNS BLOCKING SECTION ##
# Prompt the user for consent to block telemetry domains
$blockTelemetry = Read-Host "Do you want to block major Microsoft tracking and telemetry domains? [Recommended] (y/n)"

if ($blockTelemetry -eq "y") {
    Write-Host "Blocking Telemetry Domains via Hosts File..." -ForegroundColor Magenta

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $backupPath = "$hostsPath.bak"
    $tempHostsPath = "$env:TEMP\hosts.temp"

    # Define telemetry domains
    $telemetryDomains = @(
        "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "telemetry.microsoft.com",
        "watson.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "settings-sandbox.data.microsoft.com",
        "statsfe2.ws.microsoft.com",
        "diagnostics.support.microsoft.com",
        "feedback.windows.com",
        "rad.msn.com",
        "ad.doubleclick.net",
        "ads.msn.com"
    )

    # Ensure PowerShell is running as Admin
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: You must run PowerShell as Administrator to modify the hosts file." -ForegroundColor Red
        exit
    }

    # Temporarily disable Windows Defender real-time protection to prevent locks
    Write-Host "Temporarily disabling Windows Defender real-time protection..." -ForegroundColor Yellow
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    # Stop processes that may be locking the hosts file
    $processesToKill = @("MpCmdRun", "MsMpEng", "smartscreen", "MicrosoftEdge", "msedge", "browser_broker")
    foreach ($proc in $processesToKill) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }
    
    # Take ownership of the hosts file and grant full control
    Write-Host "Taking ownership of the hosts file..." -ForegroundColor Yellow
    takeown /f $hostsPath /a > $null
    icacls $hostsPath /grant Administrators:F /c /l /q > $null

    # Backup the original hosts file
    if (-Not (Test-Path $backupPath)) {
        Copy-Item -Path $hostsPath -Destination $backupPath -Force
        Write-Host "Original hosts file backed up to $backupPath" -ForegroundColor Green
    } else {
        Write-Host "Backup hosts file already exists at $backupPath" -ForegroundColor Yellow
    }

    # Read the current hosts file content
    try {
        $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Failed to read the hosts file. It may be locked by another process." -ForegroundColor Red
        Start-Sleep -Seconds 3
        exit
    }

    # Create a new temporary hosts file
    Copy-Item -Path $hostsPath -Destination $tempHostsPath -Force

    # Add telemetry domains if not already present
    foreach ($domain in $telemetryDomains) {
        $entry = "0.0.0.0 $domain"
        if ($hostsContent -notcontains $entry) {
            Write-Host "Adding $domain to hosts file..." -ForegroundColor Green
            Add-Content -Path $tempHostsPath -Value $entry
        } else {
            Write-Host "$domain is already present in the hosts file." -ForegroundColor Yellow
        }
    }

    # Replace the hosts file with the modified version
    Move-Item -Path $tempHostsPath -Destination $hostsPath -Force

    # Exclude the hosts file from Windows Defender scans to prevent flagging
#    Write-Host "Adding hosts file to Windows Defender exclusions..." -ForegroundColor Cyan
    Set-MpPreference -ExclusionPath "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue

    # Disable Windows Defender PUA protection to prevent rollback
#    Write-Host "Disabling Windows Defender PUA protection..." -ForegroundColor Cyan
    Set-MpPreference -PUAProtection 0 -ErrorAction SilentlyContinue

    # Re-enable Windows Defender real-time protection
    Write-Host "Re-enabling Windows Defender real-time protection..." -ForegroundColor Yellow
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

    Write-Host "Telemetry domains have been blocked via the hosts file." -ForegroundColor Green
} else {
    Write-Host "Skipping the blocking of telemetry domains." -ForegroundColor Cyan
}


## SECURITY ENHANCEMENT ##
# Define registry paths
$acrobatReaderRegPath = "HKCU:\Software\Adobe\Acrobat Reader\DC\Privileged"
$wifiSenseRegPath = "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config"
$uacRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$secureBootRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
$smbv1RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

# Function to set Adobe Acrobat and Reader Protected View to 'All Files'
function Set-AcrobatProtectedView {
    Write-Host "Configuring Adobe Acrobat Reader Protected View to 'All Files'..." -ForegroundColor Cyan
    if (-Not (Test-Path $acrobatReaderRegPath)) {
        New-Item -Path $acrobatReaderRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $acrobatReaderRegPath -Name "bProtectedMode" -Value 1 -Force
    Set-ItemProperty -Path $acrobatReaderRegPath -Name "bProtectedView" -Value 2 -Force
    Write-Host "Adobe Acrobat Reader Protected View set to 'All Files'." -ForegroundColor Green
}

# Function to disable Wi-Fi Sense and auto-connect to open networks
function Disable-WiFiSense {
    Write-Host "Disabling Wi-Fi Sense and auto-connect to open networks..." -ForegroundColor Cyan
    if (-Not (Test-Path $wifiSenseRegPath)) {
        New-Item -Path $wifiSenseRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $wifiSenseRegPath -Name "AutoConnectAllowedOEM" -Value 0 -Force
    Set-ItemProperty -Path $wifiSenseRegPath -Name "WiFiSenseCredShared" -Value 0 -Force
    Set-ItemProperty -Path $wifiSenseRegPath -Name "WiFiSenseOpen" -Value 0 -Force
    Write-Host "Wi-Fi Sense and auto-connect to open networks disabled." -ForegroundColor Green
}

# Function to enforce User Account Control (UAC) to default level
function Set-UserAccountControl {
    Write-Host "Setting User Account Control (UAC) to default level..." -ForegroundColor Cyan
    Set-ItemProperty -Path $uacRegPath -Name "EnableLUA" -Value 1 -Force
    Set-ItemProperty -Path $uacRegPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force
    Set-ItemProperty -Path $uacRegPath -Name "PromptOnSecureDesktop" -Value 1 -Force
    Write-Host "User Account Control (UAC) set to default level." -ForegroundColor Green
}

# Function to check and enable Secure Boot
function Enable-SecureBoot {
    Write-Host "Checking Secure Boot status..." -ForegroundColor Cyan
    $secureBootState = Get-ItemProperty -Path $secureBootRegPath -Name "SecureBootEnabled" -ErrorAction SilentlyContinue
    if ($secureBootState -and $secureBootState.SecureBootEnabled -eq 1) {
        Write-Host "Secure Boot is already enabled." -ForegroundColor Green
    } else {
        Write-Host "!! Secure Boot is not enabled. Please enable it in the BIOS settings !!" -ForegroundColor Red
        Start-Sleep -Seconds 5
    }
}

# Function to disable SMBv1 Protocol
function Disable-SMBv1 {
    Write-Host "Disabling SMBv1 Protocol..." -ForegroundColor Magenta
    if (-Not (Test-Path $smbv1RegPath)) {
        New-Item -Path $smbv1RegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $smbv1RegPath -Name "SMB1" -Value 0 -Force
    Write-Host "SMBv1 Protocol disabled." -ForegroundColor Green
}

# Function to disable the built-in Administrator account
function Disable-BuiltInAdmin {
    Write-Host "Disabling the built-in Administrator account..." -ForegroundColor Cyan
    $adminStatus = Get-LocalUser -Name "Administrator" | Select-Object -ExpandProperty Enabled
    if ($adminStatus -eq $true) {
        Disable-LocalUser -Name "Administrator"
        Write-Host "Built-in Administrator account has been disabled." -ForegroundColor Green
    } else {
        Write-Host "Built-in Administrator account is already disabled." -ForegroundColor Yellow
    }
}

# Function to enable verbose logon messages
function Enable-VerboseLogonMessages {
    Write-Host "Enabling verbose logon messages..." -ForegroundColor Cyan
    $logonRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    if (-Not (Test-Path $logonRegPath)) {
        New-Item -Path $logonRegPath -Force | Out-Null
    }

    Set-ItemProperty -Path $logonRegPath -Name "VerboseStatus" -Value 1 -Force
    Write-Host "Verbose logon messages have been enabled. You will now see detailed status messages during startup and shutdown." -ForegroundColor Green
}

# Execute functions
Set-AcrobatProtectedView
Disable-WiFiSense
Set-UserAccountControl
Enable-SecureBoot
Disable-SMBv1
Disable-BuiltInAdmin
Enable-VerboseLogonMessages

Write-Host "Security configurations have been applied successfully." -ForegroundColor Green


## Bloatware and Crapware ##
# Prompt the user for bloatware removal
$removeBloatware = Read-Host "Do you want to remove preinstalled advertising apps and bloatware? [Recommended] (y/n)"

if ($removeBloatware -eq "y") {
    Write-Host "Removing Preinstalled Advertising Apps..." -ForegroundColor Magenta

    # List of bloatware apps to remove
    $crapware = @(
        "LinkedInforWindows",
        "Microsoft.3DBuilder",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Messaging",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.MicrosoftWhiteboard",
        "Microsoft.MixedReality.Portal",
        "Microsoft.News",
        "Microsoft.Office.OneNote",
        "Microsoft.OneConnect",
        "Microsoft.OneNote",
        "Microsoft.Paint3D",
        "Microsoft.People",
        "Microsoft.Print3D",
        "Microsoft.ScreenSketch",
        "Microsoft.SkypeApp",
        "Microsoft.Todos",
        "Microsoft.Wallet",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.WindowsCommunicationsApps"  # Mail and Calendar
    )

    foreach ($app in $crapware) {
        $removed = $false

        # Try removing using AppxPackage
        $appxPackage = Get-AppxPackage -AllUsers -Name $app -ErrorAction SilentlyContinue
        if ($appxPackage) {
            Remove-AppxPackage -Package $appxPackage.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            $removed = $true
        }

        # Try removing using AppxProvisionedPackage if AppxPackage removal didn't work
        if (!$removed) {
            $provisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ $app
            if ($provisionedPackage) {
                Remove-AppxProvisionedPackage -Online -PackageName $provisionedPackage.PackageName -ErrorAction SilentlyContinue
                $removed = $true
            }
        }

        # Try removing using DISM if needed
        if (!$removed) {
            $dismOutput = dism /Online /Remove-ProvisionedAppxPackage /PackageName:$app /Quiet 2>&1
            if ($dismOutput -match "successfully removed") {
                $removed = $true
            }
        }

        # Only output when successfully removed
        if ($removed) {
            Write-Host "$app successfully removed." -ForegroundColor Green
        }
    }

    Write-Host "Preinstalled advertising apps and bloatware removed." -ForegroundColor Green
} else {
    Write-Host "Skipping bloatware removal." -ForegroundColor Cyan
}

# Ask User If They Want to Disable Bing Search in the Start Menu
$disableBingSearch = Read-Host "Do you want to disable Bing Search integration in the Start Menu? [Recommended] (y/n)"

if ($disableBingSearch -match "^[Yy]$") {
    Write-Host "Disabling Bing Search in the Start Menu..." -ForegroundColor Yellow
    $searchKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    if (!(Test-Path $searchKey)) { New-Item -Path $searchKey -Force | Out-Null }
    Set-ItemProperty -Path $searchKey -Name "BingSearchEnabled" -Type DWord -Value 0 -Force
    Write-Host "Bing Search integration disabled in the Start Menu." -ForegroundColor Green
} else {
    Write-Host "Keeping Bing Search enabled in the Start Menu." -ForegroundColor Cyan
}



# Prompt the user about "Your Phone" app
$useYourPhone = Read-Host "Do you want to use the 'Your Phone' app to integrate your phone with Windows? (y/n)"

# Check if "Your Phone" is installed
$yourPhoneInstalled = Get-AppxPackage -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue

if ($useYourPhone -eq "y") {
    if ($yourPhoneInstalled) {
        Write-Host "'Your Phone' app is already installed. Keeping it." -ForegroundColor Green
    } else {
        Write-Host "'Your Phone' app is not installed. Installing now..." -ForegroundColor Yellow
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
        Get-AppxPackage -Name "Microsoft.YourPhone" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ "Microsoft.YourPhone" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "'Your Phone' app removed." -ForegroundColor Green
    } else {
        Write-Host "'Your Phone' app is not installed. No action needed." -ForegroundColor Cyan
    }
} else {
    Write-Host "Invalid selection. No changes made to 'Your Phone' app." -ForegroundColor Red
}


## Xbox Section ##
# Function to check if an app is installed
function Test-AppInstallation {
    param ([string]$AppName)
    return ($null -ne (Get-AppxPackage -Name $AppName -AllUsers -ErrorAction SilentlyContinue))
}

# List of Xbox Apps and their corresponding Winget/Microsoft Store IDs
$requiredXboxApps = @{
    "Microsoft.Xbox.TCUI"                = "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"                  = "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"          = "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"        = "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"     = "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"  = "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.XboxConsoleCompanion"     = "Microsoft.XboxConsoleCompanion"
    "Microsoft.GamingApp"                = "9MWPM2CQNLHN"  # Microsoft Store ID
    "Microsoft.GamingServices"           = "9NZKPSTSNW4P"  # Microsoft Store ID
}

# Check if any Xbox features are installed
$anyXboxInstalled = $false
foreach ($app in $requiredXboxApps.Keys) {
    if (Test-AppInstallation -AppName $app) {
        $anyXboxInstalled = $true
        break
    }
}


# Prompt user if they want to use Xbox/Game Pass features
$useXbox = Read-Host "Do you want to use Xbox features, including Game Pass and Windows Game Bar? (y/n)"

if ($useXbox -match "^[Nn]$") {
    if ($anyXboxInstalled) {
        Write-Host "Removing all Xbox apps and features..." -ForegroundColor Magenta

        # Stop any running Xbox processes and services
        Write-Host "Stopping Xbox services and processes..." -ForegroundColor Yellow
        $xboxProcesses = @("GameBar", "XboxApp", "XboxGameOverlay", "GamingServices")
        foreach ($proc in $xboxProcesses) {
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        }

        Get-Service -Name "*Xbox*" | Stop-Service -Force -ErrorAction SilentlyContinue
        Get-Service -Name "*GamingServices*" | Stop-Service -Force -ErrorAction SilentlyContinue

        # Remove all Xbox-related Appx packages
        Write-Host "Removing Xbox-related Appx packages..." -ForegroundColor Yellow
        foreach ($app in $requiredXboxApps.Keys) {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$app*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }

        # Remove Xbox-related registry keys
        Write-Host "Removing Xbox-related registry entries..." -ForegroundColor Yellow
        $xboxRegistryKeys = @(
            "HKCU\Software\Microsoft\Xbox",
            "HKCU\Software\Microsoft\GamingServices",
            "HKLM\Software\Microsoft\GamingServices",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
            "HKCU\Software\Microsoft\GameBar"
        )
        foreach ($key in $xboxRegistryKeys) {
            reg delete $key /f 2>$null
        }

        # Remove scheduled tasks related to Xbox
        Write-Host "Removing Xbox-related scheduled tasks..." -ForegroundColor Yellow
        schtasks /Delete /TN "Microsoft\XblGameSave\XblGameSaveTask" /F 2>$null
        schtasks /Delete /TN "Microsoft\Xbox\XblGameSaveTask" /F 2>$null
        schtasks /Delete /TN "Microsoft\Xbox\XblNetworkMonitorTask" /F 2>$null

        # Remove leftover Xbox folders
        Write-Host "Removing Xbox-related leftover folders..." -ForegroundColor Yellow
        $xboxFolders = @(
            "$env:LOCALAPPDATA\Packages\Microsoft.XboxApp*",
            "$env:LOCALAPPDATA\Microsoft\XboxGameOverlay",
            "$env:LOCALAPPDATA\Microsoft\Xbox",
            "$env:ProgramData\Microsoft\Xbox",
            "$env:APPDATA\Microsoft\Xbox",
            "$env:ProgramFiles\WindowsApps\Microsoft.XboxGamingOverlay*",
            "$env:ProgramFiles\WindowsApps\Microsoft.XboxGameOverlay*",
            "$env:ProgramFiles\WindowsApps\Microsoft.GamingApp*"
        )
        foreach ($folder in $xboxFolders) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        }

        # Disable Xbox services permanently
        Write-Host "Disabling Xbox services permanently..." -ForegroundColor Yellow
        Get-Service -Name "*Xbox*" | Set-Service -StartupType Disabled
        Get-Service -Name "*GamingServices*" | Set-Service -StartupType Disabled

        Write-Host "ALL Xbox apps, services, and features have been **COMPLETELY REMOVED**!" -ForegroundColor Green
    } else {
        Write-Host "Xbox features were already removed." -ForegroundColor Cyan
    }

} else {
    Write-Host "Checking for missing Xbox features and installing them if needed..." -ForegroundColor Cyan

    # Ensure Microsoft Store is installed
    if (-not (Test-AppInstallation -AppName "Microsoft.WindowsStore")) {
        Write-Host "Microsoft Store is missing! Reinstalling it first..." -ForegroundColor Yellow
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "Microsoft.WindowsStore"} | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppxManifest.xml"}
        Start-Sleep -Seconds 5
    }

    # Reinstall missing Xbox components
    foreach ($app in $requiredXboxApps.Keys) {
        if (-not (Test-AppInstallation -AppName $app)) {
            Write-Host "Installing missing Xbox feature: $app ..." -ForegroundColor Magenta
            Try {
                # Use AppxPackage re-registration method
                $appLocation = (Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $app }).InstallLocation
                if ($appLocation) {
                    Add-AppxPackage -DisableDevelopmentMode -Register "$appLocation\AppxManifest.xml"
                    Write-Host "$app installed successfully using AppxPackage re-registration." -ForegroundColor Green
                } else {
                    Throw "AppxPackage location not found."
                }
            } Catch {
                Write-Host "Failed to install $app via AppxPackage. Trying winget..." -ForegroundColor Yellow
                $wingetID = $requiredXboxApps[$app]
                Try {
                    if ($wingetID -match "^[0-9A-Z]{12}$") {
                        Write-Host "Installing $app from Microsoft Store..." -ForegroundColor Yellow
                        Start-Process -FilePath "ms-windows-store://pdp/?productid=$wingetID"
                    } else {
                        winget install --id "$wingetID" --silent --accept-package-agreements --accept-source-agreements
                        Write-Host "$app installed successfully using winget." -ForegroundColor Green
                    }
                } Catch {
                    Write-Host "Failed to install $app using winget. Trying Microsoft Store..." -ForegroundColor Yellow
                    Start-Process -FilePath "ms-windows-store://pdp/?productid=$wingetID"
                }
            }
        }
    }

    # Enable Xbox services
    Write-Host "Ensuring Xbox services are enabled..." -ForegroundColor Yellow
    Get-Service -Name "*Xbox*" | Set-Service -StartupType Automatic
    Get-Service -Name "*GamingServices*" | Set-Service -StartupType Automatic

    Write-Host "Xbox features are installed and enabled." -ForegroundColor Green
}

Pause ########################################################################################################################################################

## OneDrive Section ##
# Ask about OneDrive Removal
$removeOneDrive = Read-Host "Do you want to completely remove Microsoft OneDrive? [Recommended] (y/n)"

if ($removeOneDrive -eq "y") {
    Write-Host "FORCEFULLY REMOVING MICROSOFT ONEDRIVE..." -ForegroundColor Magenta

    # Stop and kill any running OneDrive processes
    Write-Host "Stopping and killing OneDrive processes..." -ForegroundColor Yellow
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Uninstall OneDrive - Try Multiple Methods
    Write-Host "Attempting to uninstall OneDrive..." -ForegroundColor Yellow

    $oneDriveExecutables = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    )

    $oneDriveUninstalled = $false

    foreach ($exe in $oneDriveExecutables) {
        if (Test-Path $exe) {
            Write-Host "Found OneDrive uninstaller at: $exe" -ForegroundColor Cyan
            try {
                Start-Process -FilePath $exe -ArgumentList "/uninstall" -NoNewWindow -Wait -WindowStyle Hidden -ErrorAction Stop
                $oneDriveUninstalled = $true
                Write-Host "OneDrive successfully uninstalled via executable." -ForegroundColor Green
                break
            } catch {}
        }
    }

    # Try Winget as a Backup Method
    if (-not $oneDriveUninstalled) {
        Write-Host "Attempting to remove OneDrive via Winget..." -ForegroundColor Cyan
        try {
            winget uninstall --id Microsoft.OneDrive --silent --accept-package-agreements --accept-source-agreements > $null 2>&1
            $oneDriveUninstalled = $true
            Write-Host "OneDrive removed via Winget." -ForegroundColor Green
        } catch {}
    }

    # Try Removing OneDrive AppX Package as Last Resort
    if (-not $oneDriveUninstalled) {
        Write-Host "Attempting to remove OneDrive via AppX package..." -ForegroundColor Cyan
        try {
            Get-AppxPackage -Name "Microsoft.OneDrive" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*OneDrive*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "OneDrive removed via AppX package." -ForegroundColor Green
        } catch {}
    }

    # Backup OneDrive Files Before Deleting Folders
    $oneDriveUserFolder = "$env:UserProfile\OneDrive"
    $backupFolder = "$env:UserProfile\Onedrive Files"

    if (Test-Path $oneDriveUserFolder) {
        $oneDriveSubfolders = @("Attachments", "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")

        # Ensure folders exist and move matching OneDrive folders to user profile
        foreach ($folder in $oneDriveSubfolders) {
            $sourcePath = "$oneDriveUserFolder\$folder"
            $destinationPath = "$env:UserProfile\$folder"

            if (Test-Path $sourcePath) {
                Write-Host "Moving OneDrive $folder to $destinationPath..." -ForegroundColor Yellow
                New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
                robocopy "$sourcePath" "$destinationPath" /E /MOVE /COPY:DAT /R:3 /W:3 /NFL /NDL /NJH /NJS
            }
        }

        # Move any remaining files and folders to the backup folder
        if ((Get-ChildItem -Path $oneDriveUserFolder -Recurse -ErrorAction SilentlyContinue).Count -gt 0) {
            Write-Host "Moving remaining OneDrive files to: $backupFolder" -ForegroundColor Yellow
            New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
            robocopy "$oneDriveUserFolder" "$backupFolder" /E /MOVE /COPY:DAT /R:3 /W:3 /NFL /NDL /NJH /NJS
        }

        Write-Host "OneDrive files successfully relocated." -ForegroundColor Green
    }

    # Remove leftover OneDrive directories
    Write-Host "Removing leftover OneDrive folders..." -ForegroundColor Yellow
    $oneDriveFolders = @(
        "$oneDriveUserFolder",
        "$env:LocalAppData\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "$env:SystemDrive\OneDriveTemp"
    )

    foreach ($folder in $oneDriveFolders) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $folder" -ForegroundColor Green
        }
    }

    # Remove OneDrive from Explorer Quick Access
    Write-Host "Removing OneDrive from Windows Explorer navigation pane..." -ForegroundColor Yellow
    reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f 2>$null
    reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f 2>$null

    # Remove OneDrive Registry Entries
    Write-Host "Removing OneDrive registry keys..." -ForegroundColor Yellow
    reg delete "HKCU\Software\Microsoft\OneDrive" /f 2>$null
    reg delete "HKLM\Software\Microsoft\OneDrive" /f 2>$null
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /f 2>$null

    # Disable OneDrive via Group Policy (Prevents Reinstallation)
    Write-Host "Preventing OneDrive from reinstalling..." -ForegroundColor Yellow
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f > $null 2>&1

    # Remove OneDrive Scheduled Tasks
    Write-Host "Removing OneDrive scheduled tasks..." -ForegroundColor Yellow
    schtasks /Delete /TN "OneDrive Standalone Update Task-S-1-5-21" /F 2>$null
    schtasks /Delete /TN "OneDrive Per-Machine Standalone Update Task" /F 2>$null

    # Remove OneDrive from Startup
    Write-Host "Removing OneDrive from Startup..." -ForegroundColor Yellow
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f 2>$null

    # Restore Default User Folder Paths (Fix Missing Documents Folder)
    Write-Host "Restoring default user folder locations..." -ForegroundColor Yellow
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

    $folders = @{
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

    foreach ($folder in $folders.Keys) {
        $defaultPath = $folders[$folder]
        if (!(Test-Path $defaultPath)) { New-Item -Path $defaultPath -ItemType Directory -Force | Out-Null }
        Set-ItemProperty -Path $registryPath -Name $folder -Value $defaultPath -Force
        Write-Host "Reset $folder to $defaultPath" -ForegroundColor Green
    }

    # Force remove of remaining Onedrive Folder
    # Final check and force removal of old OneDrive folder
    $oldOneDriveFolder = "$env:USERPROFILE\OneDrive"

    if (Test-Path $oldOneDriveFolder) {
        Write-Host "Final cleanup: Removing leftover OneDrive folder..." -ForegroundColor Yellow
        try {
            takeown /f "$oldOneDriveFolder" /r /d y > $null 2>&1
            icacls "$oldOneDriveFolder" /grant administrators:F /t /c /q > $null 2>&1
            Remove-Item -Path $oldOneDriveFolder -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed the old OneDrive folder." -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Failed to remove the old OneDrive folder. Try deleting it manually." -ForegroundColor Red
        }
    }

    Write-Host "ONEDRIVE HAS BEEN COMPLETELY REMOVED, AND USER FOLDERS ARE NOW RESTORED!" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "Keeping Microsoft OneDrive." -ForegroundColor Cyan
}


## Microsoft Teams Section ##
# Prompt User to Remove Microsoft Teams
$removeTeams = Read-Host "Do you want to completely remove Microsoft Teams? [Recommended] (y/n)"

if ($removeTeams -eq "y") {
    Write-Host "FORCEFULLY REMOVING MICROSOFT TEAMS..." -ForegroundColor Magenta

    # Stop and Kill Any Running Microsoft Teams Processes
    Write-Host "Stopping and killing Microsoft Teams processes..." -ForegroundColor Yellow
    $teamsProcesses = @("Teams", "Teams.exe", "Update.exe", "TeamsMachineUninstaller", "msteams")
    foreach ($proc in $teamsProcesses) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    # Temporarily Disable `msstore` Source to Suppress Agreement Prompt
    Write-Host "Disabling Microsoft Store as a winget source to suppress agreement prompt..." -ForegroundColor Cyan
    winget source remove msstore > $null 2>&1

    # Uninstall Microsoft Teams via Winget
    Write-Host "Attempting to uninstall Microsoft Teams via Winget..." -ForegroundColor Cyan
    try {
        winget uninstall --id Microsoft.Teams --silent --accept-source-agreements > $null 2>&1
        Write-Host "Microsoft Teams removed via Winget." -ForegroundColor Green
    } catch {}

    # Re-enable `msstore` Source After Uninstall
    Write-Host "Restoring Microsoft Store as a winget source..." -ForegroundColor Cyan
    winget source reset --force > $null 2>&1

    # Uninstall Microsoft Teams via Appx
    Write-Host "Attempting to remove Teams AppX package..." -ForegroundColor Cyan
    try {
        Get-AppxPackage -Name "MicrosoftTeams" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Teams*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "Microsoft Teams removed via AppX package." -ForegroundColor Green
    } catch {}

    # Remove Teams Machine-Wide Installer (Common on Enterprise PCs)
    $teamsInstallerPath = "C:\Program Files (x86)\Teams Installer\Teams.exe"
    if (Test-Path $teamsInstallerPath) {
        Write-Host "Removing Microsoft Teams Machine-Wide Installer..." -ForegroundColor Yellow
        Start-Process -FilePath $teamsInstallerPath -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    }

    # Remove Remaining Teams Directories
    Write-Host "Removing leftover Teams folders..." -ForegroundColor Yellow
    $teamsFolders = @(
        "$env:LOCALAPPDATA\Microsoft\Teams",
        "$env:APPDATA\Microsoft\Teams",
        "$env:ProgramData\Microsoft\Teams",
        "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe",
        "$env:ProgramFiles\Microsoft\Teams",
        "$env:ProgramFiles (x86)\Microsoft\Teams",
        "$env:USERPROFILE\AppData\Local\Microsoft\Teams",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Teams",
        "$env:ProgramFiles\Common Files\Microsoft Teams",
        "C:\ProgramData\Microsoft\Teams"
    )

    foreach ($folder in $teamsFolders) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $folder" -ForegroundColor Green
        }
    }

    # Remove Microsoft Teams from Startup
    Write-Host "Removing Microsoft Teams from Startup..." -ForegroundColor Yellow
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Teams" /f 2>$null
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Teams" /f 2>$null

    # Remove Microsoft Teams Registry Entries
    Write-Host "Removing Microsoft Teams registry entries..." -ForegroundColor Yellow
    $teamsRegistryKeys = @(
        "HKCU\Software\Microsoft\Office\Teams",
        "HKCU\Software\Microsoft\Teams",
        "HKLM\Software\Microsoft\Teams",
        "HKLM\Software\WOW6432Node\Microsoft\Teams",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
    )

    foreach ($key in $teamsRegistryKeys) {
        reg delete $key /f 2>$null
    }

    # Remove Microsoft Teams Start Menu Shortcuts
    Write-Host "Removing Microsoft Teams Start Menu shortcuts..." -ForegroundColor Yellow
    $teamsShortcuts = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Teams.lnk",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Teams.lnk"
    )

    foreach ($shortcut in $teamsShortcuts) {
        if (Test-Path $shortcut) {
            Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted shortcut: $shortcut" -ForegroundColor Green
        }
    }

    # Force Clear Start Menu Cache (Removes Ghost Icons)
    Write-Host "Refreshing Windows Start Menu to remove any lingering Microsoft Teams icons..." -ForegroundColor Yellow
    Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden

    # Remove "Meet Now" Icon from the Taskbar
    Write-Host "Removing 'Meet Now' icon from the taskbar..." -ForegroundColor Yellow
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
    Write-Host "'Meet Now' icon removed from the taskbar." -ForegroundColor Green

    # Block Microsoft Teams from Reinstalling via Group Policy
    Write-Host "Preventing Microsoft Teams from reinstalling..." -ForegroundColor Yellow
    reg add "HKLM\Software\Policies\Microsoft\Office\Teams" /v "PreventTeamsInstallation" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\Policies\Microsoft\Windows\Teams" /v "PreventTeamsAutoInstall" /t REG_DWORD /d 1 /f
    reg add "HKLM\Software\WOW6432Node\Policies\Microsoft\Office\Teams" /v "PreventTeamsInstallation" /t REG_DWORD /d 1 /f

    Write-Host "MICROSOFT TEAMS HAS BEEN COMPLETELY REMOVED AND BLOCKED FROM REINSTALLING!" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "Keeping Microsoft Teams." -ForegroundColor Cyan
}



## AI Removal Section (CoPilot and Recall) ##
# Prompt user to remove Microsoft Copilot
$removeCopilot = Read-Host "Do you want to completely remove Microsoft Copilot? [Recommended] (y/n)"

if ($removeCopilot -eq "y") {
    Write-Host "FORCEFULLY REMOVING MICROSOFT COPILOT..." -ForegroundColor Magenta

    # Disable Copilot via Registry
    Write-Host "Disabling Microsoft Copilot via registry..." -ForegroundColor Yellow
    reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null 2>&1
    reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null 2>&1
    reg add "HKLM\Software\Policies\Microsoft\Windows\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f > $null 2>&1
    reg add "HKLM\Software\Policies\Microsoft\Windows\Dsh" /v "AllowCopilotInWindows" /t REG_DWORD /d 0 /f > $null 2>&1
    reg add "HKLM\Software\Policies\Microsoft\Windows\Dsh" /v "EnableCopilotButton" /t REG_DWORD /d 0 /f > $null 2>&1
    Write-Host "Microsoft Copilot disabled via registry." -ForegroundColor Green

    # Remove Copilot from Taskbar
    Write-Host "Unpinning Microsoft Copilot from Taskbar and Start Menu..." -ForegroundColor Yellow
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f > $null 2>&1
    Write-Host "Microsoft Copilot icon removed from Taskbar and Start Menu." -ForegroundColor Green

    # Stop and Kill Microsoft Copilot Processes
    Write-Host "Stopping and killing Microsoft Copilot processes..." -ForegroundColor Yellow
    $copilotProcesses = @("Copilot", "Copilot.exe", "AI.exe", "CopilotRuntime", "CopilotBackground", "Microsoft365Copilot", "Microsoft365Copilot.exe")
    foreach ($proc in $copilotProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    # Uninstall Microsoft Copilot using Winget
    Write-Host "Attempting to uninstall Microsoft Copilot via Winget..." -ForegroundColor Cyan
    try {
        winget uninstall --id "Microsoft.Copilot" --silent --accept-source-agreements > $null 2>&1
        winget uninstall --id "Microsoft.365.Copilot" --silent --accept-source-agreements > $null 2>&1
        Write-Host "Microsoft Copilot removed via Winget." -ForegroundColor Green
    } catch {}

    # Remove Appx Packages
    $copilotPackages = @(
        "Microsoft.Windows.AI.Copilot",
        "MicrosoftWindows.Client.CBS",
        "Microsoft.Copilot",
        "Microsoft.365.Copilot"
    )

    foreach ($package in $copilotPackages) {
        try {
            Get-AppxPackage -Name $package -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$package*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "Removed: $package" -ForegroundColor Green
        } catch {}
    }

    # Remove Copilot from Microsoft 365 / Office
    Write-Host "Attempting to remove Microsoft 365 Copilot..." -ForegroundColor Yellow
    $officeUninstallPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    if (Test-Path $officeUninstallPath) {
        try {
            Start-Process -FilePath $officeUninstallPath -ArgumentList "/uninstall Copilot /quiet /norestart" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Write-Host "Microsoft 365 Copilot removed." -ForegroundColor Green
        } catch {}
    }

    # Remove Microsoft Copilot using MSI Uninstall (if applicable)
    Write-Host "Checking for MSI-installed Microsoft Copilot..." -ForegroundColor Yellow
    $msiCopilot = Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Copilot%'" -ErrorAction SilentlyContinue
    if ($msiCopilot) {
        foreach ($app in $msiCopilot) {
            try {
                Write-Host "Removing: $($app.Name)" -ForegroundColor Cyan
                $app.Uninstall()
                Write-Host "Uninstalled: $($app.Name)" -ForegroundColor Green
            } catch {}
        }
    }

    # Remove Remaining Copilot Directories
    Write-Host "Removing leftover Microsoft Copilot folders..." -ForegroundColor Yellow
    $copilotFolders = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.Windows.AI.Copilot",
        "$env:ProgramData\Microsoft\Windows\AI\Copilot",
        "$env:APPDATA\Microsoft\Copilot",
        "$env:ProgramFiles\Microsoft\Copilot",
        "$env:ProgramFiles (x86)\Microsoft\Copilot",
        "C:\ProgramData\Microsoft\Copilot"
    )

    foreach ($folder in $copilotFolders) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $folder" -ForegroundColor Green
        }
    }

    # Remove Microsoft Copilot from Startup
    Write-Host "Removing Microsoft Copilot from Startup..." -ForegroundColor Yellow
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Copilot" /f 2>$null

    # Remove Microsoft Copilot Registry Entries
    Write-Host "Removing Microsoft Copilot registry entries..." -ForegroundColor Yellow
    $copilotRegistryKeys = @(
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Copilot",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Copilot",
        "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Copilot",
        "HKCU\Software\Microsoft\Office\Copilot",
        "HKLM\Software\Microsoft\Office\Copilot"
    )

    foreach ($key in $copilotRegistryKeys) {
        reg delete $key /f 2>$null
    }

    # Block Microsoft Copilot from Reinstalling via Group Policy
    Write-Host "Preventing Microsoft Copilot from reinstalling..." -ForegroundColor Yellow
    reg add "HKLM\Software\Policies\Microsoft\Windows\Copilot" /v "DisableCopilot" /t REG_DWORD /d 1 /f > $null 2>&1
    reg add "HKLM\Software\Policies\Microsoft\Windows\Dsh" /v "EnableCopilotButton" /t REG_DWORD /d 0 /f > $null 2>&1

    # Clear Start Menu Cache & Refresh Windows Explorer
    Write-Host "Refreshing Windows Start Menu to remove lingering Microsoft Copilot icons..." -ForegroundColor Yellow
    Stop-Process -Name "StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden

    Write-Host "MICROSOFT COPILOT HAS BEEN COMPLETELY REMOVED AND BLOCKED FROM REINSTALLING!" -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "Keeping Microsoft Copilot." -ForegroundColor Cyan
}

# Ask about Microsoft Recall
$removeRecall = Read-Host "Do you want to remove Microsoft Recall? [Recommended] (y/n)"

if ($removeRecall.ToLower() -eq "y" -or $removeRecall.ToLower() -eq "yes") {
    Write-Host "Disabling Microsoft Recall..." -ForegroundColor Magenta

    # Disable Recall in Windows AI settings
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows AI" /v DisableWindowsAI /t REG_DWORD /d 1 /f

    # Disable Recall's data collection and logging
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows AI" /v DisableLogging /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows AI" /v DisableMemorySnapshots /t REG_DWORD /d 1 /f

    # Disable Recall indexing
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisableSearchIndexing /t REG_DWORD /d 1 /f

    # Block Recall from running at startup
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Recall /t REG_SZ /d "" /f

    # Disable Recall via Task Scheduler (if it has scheduled tasks)
    schtasks /Change /TN "Microsoft\Windows\AI\Recall" /Disable
    schtasks /Change /TN "Microsoft\Windows\AI\RecallIndexing" /Disable

    # Force policy updates to take effect immediately
    gpupdate /force

    Write-Host "Microsoft Recall fully disabled." -ForegroundColor Green
} else {
    Write-Host "Keeping Microsoft Recall." -ForegroundColor Cyan
}



## UI and Taskbar Section ##
# Prompt user to apply Windows 10 look and feel on Windows 11
$win10look = Read-Host "Do you want Windows 11 to look and feel like Windows 10? [Recommended] (y/n)"
if ($win10look -eq "y") {
    Write-Host "Applying UI tweaks..." -ForegroundColor Magenta
    # Enable Classic Start Menu Mode
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowClassicMode" /t REG_DWORD /d 1 /f
    # Align Taskbar to the Left
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f
    # Enable Windows 10 Classic Right-Click Context Menu (Disable Windows 11 context menu)
    reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f
    reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
    Write-Host "Windows UI tweaks applied successfully." -ForegroundColor Green
} else {
    Write-Host "Skipping Windows 10 UI tweaks." -ForegroundColor Cyan
}

# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
}

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator." -ForegroundColor Red
    exit
}

# Function to remove AppxPackage for all users
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

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator." -ForegroundColor Red
    exit
}

# Function to remove AppxPackage for all users
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

# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator." -ForegroundColor Red
    exit
}

# Function to run registry modifications with elevated privileges
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [string]$Value
    )
    try {
        Start-Process -FilePath "reg.exe" -ArgumentList "add `"$Path`" /v `"$Name`" /t $Type /d $Value /f" -NoNewWindow -Wait
        Write-Host "Set $Name to $Value in $Path" -ForegroundColor Green
    } catch {
        Write-Host "Failed to set $Name in $Path. Error: $_" -ForegroundColor Red
    }
}

# Function to disable Widgets
function Disable-Widgets {
    Write-Host "Disabling Widgets..." -ForegroundColor Cyan
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type REG_DWORD -Value 0
    # Stop and disable Widgets service
    Get-Service -Name "Widgets" -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }
    # Uninstall Widgets package
    Remove-AppxPackageAllUsers -PackageName "MicrosoftWindows.Client.WebExperience"
    Write-Host "Widgets have been disabled." -ForegroundColor Green
}

# Function to remove News and Interests
function Remove-NewsAndInterests {
    Write-Host "Removing News and Interests..." -ForegroundColor Cyan
    # Uninstall Microsoft News App
    Remove-AppxPackageAllUsers -PackageName "Microsoft.BingNews"
    # Disable News and Interests via registry
    Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type REG_DWORD -Value 0
    Write-Host "News and Interests have been removed." -ForegroundColor Green
}

# Function to unpin Microsoft Store from taskbar properly
function Remove-MicrosoftStoreFromTaskbar {
    Write-Host "Unpinning Microsoft Store from Taskbar..." -ForegroundColor Cyan

    $taskbarLayout = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Store.lnk"
    
    if (Test-Path $taskbarLayout) {
        Remove-Item $taskbarLayout -Force -ErrorAction SilentlyContinue
        Write-Host "Microsoft Store has been unpinned from the taskbar." -ForegroundColor Green
    } else {
        Write-Host "Microsoft Store was not pinned to the taskbar." -ForegroundColor Yellow
    }

    # Prevent Microsoft Store from being pinned in the future
    Set-RegistryValue -Path "HKCU\Software\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Type REG_DWORD -Value 1
}

# Function to remove unnecessary taskbar icons
function Remove-TaskbarIcons {
    Write-Host "Removing unnecessary taskbar icons..." -ForegroundColor Magenta

    # Remove Task View Button
    Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type REG_DWORD -Value 0

    # Remove Search Bar
    Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type REG_DWORD -Value 0

    # Remove People Icon
    Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type REG_DWORD -Value 0

    # Remove Ink Workspace
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Type REG_DWORD -Value 0

    # Change Tray Icons to 2 Rows
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" -Name "Settings" -Value ([byte[]](0x30,0x00,0x00,0x00,0xFE,0xFF,0xFF,0xFF,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    
    # Remove "Meet Now" from Taskbar
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type REG_DWORD -Value 1
}

# Prompt user to debloat the taskbar
$debloatTaskbar = Read-Host "Do you want to debloat the taskbar and remove unnecessary icons, including News, Weather, Widgets, and Microsoft Store? [Recommended] (y/n)"

if ($debloatTaskbar -eq "y") {
    Remove-TaskbarIcons
    Disable-Widgets
    Remove-NewsAndInterests
    Remove-MicrosoftStoreFromTaskbar

    # Uninstall MSN News & Weather apps (if present)
    Write-Host "Removing MSN News & Weather Apps..." -ForegroundColor Yellow
    $newsWeatherApps = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather"
    )
    foreach ($app in $newsWeatherApps) {
        Remove-AppxPackageAllUsers -PackageName $app
        Write-Host "Removed: $app" -ForegroundColor Green
    }

    # Unpin News & Weather from Taskbar
    Write-Host "Unpinning News & Weather from Taskbar..." -ForegroundColor Yellow
    Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type REG_DWORD -Value 2
    Write-Host "News & Weather unpinned from taskbar." -ForegroundColor Green

    # Remove News & Interests via Group Policy
    Write-Host "Ensuring News & Interests is fully removed via Group Policy..." -ForegroundColor Yellow
    Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type REG_DWORD -Value 0
    Write-Host "News & Interests fully removed via Group Policy." -ForegroundColor Green

} else {
    Write-Host "Skipping taskbar debloating." -ForegroundColor Cyan
}

# Enable Dark Mode
$enableDarkMode = Read-Host "Do you want to enable Dark Mode for Windows and supported applications? [Recommended] (y/n)"
if ($enableDarkMode -eq "y") {
    Write-Host "Enabling Dark Mode for Windows and applications..." -ForegroundColor Magenta

    # Enable Dark Mode for Windows system and apps
    $personalizePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty -Path $personalizePath -Name "AppsUseLightTheme" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $personalizePath -Name "SystemUsesLightTheme" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Dark Mode enabled for Windows system and apps." -ForegroundColor Green

    # Enable Dark Mode for Microsoft Office apps (only if Office is installed)
    $officeKeyPath = "HKCU:\Software\Microsoft\Office\16.0\Common"
    if (Test-Path $officeKeyPath) {
        $officeThemeValue = 4  # 4 corresponds to the 'Black' theme in Office
        Set-ItemProperty -Path $officeKeyPath -Name "UI Theme" -Value $officeThemeValue -Type DWord -ErrorAction SilentlyContinue
        Write-Host "Dark Mode enabled for Microsoft Office apps." -ForegroundColor Green
    } else {
        Write-Host "Microsoft Office is not installed or the registry key does not exist. Skipping Office Dark Mode." -ForegroundColor Yellow
    }
} else {
    Write-Host "Dark Mode not enabled." -ForegroundColor Cyan
}

# Ask if user wants to debloat Edge
$debloatEdge = Read-Host "Do you want to remove Edges forced features? [Recommended] (y/n)"
if ($debloatEdge -eq "y") {
    Write-Host "Disabling Edge forced features..." -ForegroundColor Magenta
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "RestorePdfAssociationsEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
    Write-Host "Edge features disabled!" -ForegroundColor Green
}

# Ask if user wants gaming optimizations
$gameOptimizations = Read-Host "Do you want to enable gaming features like Game Mode, VRR, HAGS (GPU Scheduling)? [Recommended for Gamers] (y/n)"

if ($gameOptimizations -match "^[Yy]$") {
    Write-Host "Applying gaming optimizations..." -ForegroundColor Magenta
    # Enable Game Mode
    reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f
    Write-Host "Game Mode enabled!" -ForegroundColor Green
    # Enable Hardware Accelerated GPU Scheduling (HAGS)
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GraphicsSettings" /v "HwSchMode" /t REG_DWORD /d 2 /f
    Write-Host "Hardware Accelerated GPU Scheduling (HAGS) enabled!" -ForegroundColor Green
    # Enable Variable Refresh Rate (VRR) if supported
    $vrrSupported = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "VRRFeatureEnabled" -ErrorAction SilentlyContinue
    if ($null -ne $vrrSupported) {
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "VRRFeatureEnabled" /t REG_DWORD /d 1 /f
        Write-Host "Variable Refresh Rate (VRR) enabled!" -ForegroundColor Green
    } else {
        Write-Host "VRR support not detected on this system. Skipping VRR activation." -ForegroundColor Yellow
    }
    Write-Host "All selected gaming features have been enabled!" -ForegroundColor Cyan
} else {
    Write-Host "Skipping gaming optimizations." -ForegroundColor Cyan
}

# Disable USB Selective Suspention
$usbsuspend = Read-Host "Do you intend to use controllers or joysticks with your games? [Recommended] (y/n)"
if ($usbsuspend -match "^[Yy]$") {
    Write-Host "Disabling Selective USB Suspend.."
    powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0​
}

## Disable Gaming Inhibitors ##
# Prompt User to Disable Memory Core Isolation
$disableMemoryIsolation = Read-Host "Do you want to disable Memory Core Isolation for better gaming performance? (Recommended) (y/n)"

if ($disableMemoryIsolation -match "^[Yy]$") {
    Write-Host "Disabling Memory Core Isolation and Related Features..." -ForegroundColor Magenta

    # Ensure PowerShell is Running as Admin
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: You must run PowerShell as Administrator to modify Core Isolation settings." -ForegroundColor Red
        exit
    }

    # Disable Hypervisor Enforced Code Integrity (HVCI)
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
    Write-Host "Memory Core Isolation (HVCI) disabled." -ForegroundColor Green

    # Disable Virtualization-Based Security (VBS) and Device Guard
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
    Write-Host "Virtualization-Based Security (VBS) disabled." -ForegroundColor Green

    # Disable Windows Defender Credential Guard
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 0 /f
    Write-Host "Credential Guard disabled." -ForegroundColor Green

    # Disable Hypervisor Launch Type
    bcdedit /set hypervisorlaunchtype off
    Write-Host "Hypervisor Launch Type set to OFF." -ForegroundColor Green

    # Notify User That a Restart Is Needed for Full Effect
    Write-Host "Memory Core Isolation and related settings have been disabled." -ForegroundColor Green
    Write-Host "⚠ Some changes will not take effect until the system is restarted." -ForegroundColor Yellow
} else {
    Write-Host "Keeping Memory Core Isolation enabled." -ForegroundColor Cyan
}

# Restart Explorer to apply any UI and Taskbar Tweaks
Write-Host "Restarting Windows Explorer to apply changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force
Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
Write-Host "Windows Explorer Restarted." -ForegroundColor Green

# Function to create a desktop shortcut for OGCWin.bat
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

# Define shortcut paths
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "OGC Windows Utility.lnk")
$ogcwinbat = "$parentFolder\OGCWin.bat"

# Use Windows Start Menu-style icon
$windowsIcon = "C:\Windows\System32\imageres.dll,97"  # Windows-style system icon

# Create the shortcut with the Windows icon
New-Shortcut -TargetPath $ogcwinbat -ShortcutPath $desktopPath -Description "Launch OGC Windows Utility" -IconPath $windowsIcon

Clear-Host


## Software Installation Secion ##
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
Write-Host ""

# Install Gaming Apps (Steam, Epic, GOG, Discord, Medal)
$installGamingApps = Read-Host "Do you want to install gaming apps like Steam, Epic, GOG, Discord, and Medal? (y/n)"
if ($installGamingApps -eq "y") {
    Write-Host "Installing Gaming Apps..." -ForegroundColor Cyan

    $installSteam = Read-Host "Do you want to install Steam? (y/n)"
    if ($installSteam -eq "y") {
        Write-Host "Installing Steam..." -ForegroundColor Magenta
        winget install Valve.Steam --silent --accept-package-agreements --accept-source-agreements
    }

    $installEpic = Read-Host "Do you want to install Epic Games Launcher? (y/n)"
    if ($installEpic -eq "y") {
        Write-Host "Installing Epic Games Launcher..." -ForegroundColor Magenta
        winget install EpicGames.EpicGamesLauncher --silent --accept-package-agreements --accept-source-agreements
    }

    $installGOG = Read-Host "Do you want to install GOG Galaxy? (y/n)"
    if ($installGOG -eq "y") {
        Write-Host "Installing GOG Galaxy..." -ForegroundColor Magenta
        winget install GOG.Galaxy --silent --accept-package-agreements --accept-source-agreements
    }

    $installDiscord = Read-Host "Do you want to install Discord for voice chat? (y/n)"
    if ($installDiscord -eq "y") {
        Write-Host "Installing Discord..." -ForegroundColor Magenta
        winget install Discord.Discord --silent --accept-package-agreements --accept-source-agreements
    }

    $installMedal = Read-Host "Do you want to install Medal for game clip recording? (y/n)"
    if ($installMedal -eq "y") {
        Write-Host "Installing Medal..." -ForegroundColor Magenta
        winget install Medal.TV --silent --accept-package-agreements --accept-source-agreements
    }

    Write-Host "Gaming app installation process completed." -ForegroundColor Green
}

# Install Gaming and Monitoring Utilities
$installGamingUtilities = Read-Host "Do you want to install gaming and monitoring utilities? (y/n)"
if ($installGamingUtilities -eq "y") {
    Write-Host "Installing Gaming and Monitoring Utilities..." -ForegroundColor Cyan

    $installHWInfo = Read-Host "Do you want to install HWiNFO for system monitoring? (y/n)"
    if ($installHWInfo -eq "y") {
        Write-Host "Installing HWiNFO..." -ForegroundColor Magenta
        winget install REALiX.HWiNFO --silent --accept-package-agreements --accept-source-agreements
    }

    $installMSIAfterburner = Read-Host "Do you want to install MSI Afterburner for overclocking? (y/n)"
    if ($installMSIAfterburner -eq "y") {
        Write-Host "Installing MSI Afterburner..." -ForegroundColor Magenta
        winget install MSI.Afterburner --silent --accept-package-agreements --accept-source-agreements
    }

    $installRTSS = Read-Host "Do you want to install RivaTuner Statistics Server (RTSS) for FPS monitoring? (y/n)"
    if ($installRTSS -eq "y") {
        Write-Host "Installing RivaTuner Statistics Server (RTSS)..." -ForegroundColor Magenta
        winget install Guru3D.RTSS --silent --accept-package-agreements --accept-source-agreements
    }

    $installCPUID = Read-Host "Do you want to install CPU-Z for CPU information? (y/n)"
    if ($installCPUID -eq "y") {
        Write-Host "Installing CPU-Z..." -ForegroundColor Magenta
        winget install CPUID.CPU-Z --silent --accept-package-agreements --accept-source-agreements
    }

    $installGPUZ = Read-Host "Do you want to install GPU-Z for GPU information? (y/n)"
    if ($installGPUZ -eq "y") {
        Write-Host "Installing GPU-Z..." -ForegroundColor Magenta
        winget install TechPowerUp.GPU-Z --silent --accept-package-agreements --accept-source-agreements
    }

    Write-Host "Gaming and monitoring utilities installation completed." -ForegroundColor Green
}

# Function to remove Edge from the taskbar properly
function Remove-EdgeTaskbarShortcut {
    Write-Host "Unpinning Microsoft Edge from Taskbar..." -ForegroundColor Cyan
    $edgeShortcut = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk"
    
    if (Test-Path $edgeShortcut) {
        Remove-Item $edgeShortcut -Force -ErrorAction SilentlyContinue
        Write-Host "Microsoft Edge has been unpinned from the taskbar." -ForegroundColor Green
    } else {
        Write-Host "Microsoft Edge was not pinned to the taskbar." -ForegroundColor Yellow
    }
}

# Function to add a browser shortcut to the taskbar
function Add-BrowserToTaskbar {
    param (
        [string]$BrowserExe
    )
    Write-Host "Adding $BrowserExe to the taskbar..." -ForegroundColor Cyan

    $browserPath = ""

    # Locate the installed browser's full path
    switch ($BrowserExe) {
        "firefox.exe" { $browserPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe" }
        "brave.exe" { $browserPath = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe" }
        "opera.exe" { $browserPath = "$env:ProgramFiles\Opera GX\launcher.exe" }
        "chrome.exe" { $browserPath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" }
    }

    if (Test-Path $browserPath) {
        # Pin to Taskbar
        Start-Process -FilePath "$browserPath" -PassThru
        Start-Sleep -Seconds 2  # Allow time for the application to launch
        Stop-Process -Name "$BrowserExe" -Force -ErrorAction SilentlyContinue
        Write-Host "$BrowserExe has been added to the taskbar." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Could not find $BrowserExe. It may not have installed correctly." -ForegroundColor Red
    }
}

# Install a Web Browser
$installBrowser = Read-Host "Do you want to install a web browser? (y/n)"
if ($installBrowser -eq "y") {
    Write-Host "Select a browser to install..." -ForegroundColor Cyan
    Write-Host "1. Firefox" -ForegroundColor Yellow
    Write-Host "2. Brave" -ForegroundColor Yellow
    Write-Host "3. Opera GX" -ForegroundColor Yellow
    Write-Host "4. Chrome" -ForegroundColor Yellow
    Write-Host "5. Edge (Already Installed)" -ForegroundColor Yellow
    Write-Host "6. Skip Browser Installation" -ForegroundColor Yellow

    $browser = Read-Host "Enter the number corresponding to your browser choice"

    switch ($browser) {
        "1" {
            Write-Host "Installing Firefox..." -ForegroundColor Magenta
            winget install Mozilla.Firefox
            Remove-EdgeTaskbarShortcut
        }
        "2" {
            Write-Host "Installing Brave..." -ForegroundColor Magenta
            winget install Brave.Brave
            Remove-EdgeTaskbarShortcut
        }
        "3" {
            Write-Host "Installing Opera GX..." -ForegroundColor Magenta
            winget install Opera.OperaGX
            Remove-EdgeTaskbarShortcut
        }
        "4" {
            Write-Host "Installing Chrome..." -ForegroundColor Magenta
            winget install Google.Chrome
            Remove-EdgeTaskbarShortcut
        }
        "5" {
            Write-Host "Microsoft Edge selected." -ForegroundColor Green

            # Ensure Edge Background Mode is Enabled
            $edgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (!(Test-Path $edgeRegPath)) { 
                New-Item -Path $edgeRegPath -Force | Out-Null 
            }
            Set-ItemProperty -Path $edgeRegPath -Name "BackgroundModeEnabled" -Type DWord -Value 1 -Force
        }
        "6" {
            Write-Host "Skipping browser installation." -ForegroundColor Cyan
        }
        default {
            Write-Host "Invalid selection. No browser will be installed." -ForegroundColor Red
        }
    }
}


# Ask the user about Office Suite preference
Write-Host "Choose an office suite to install or remove Office Hub and other office software:" -ForegroundColor Cyan
Write-Host "1. Microsoft Office" -ForegroundColor Yellow
Write-Host "2. LibreOffice" -ForegroundColor Yellow
Write-Host "3. OpenOffice" -ForegroundColor Yellow
Write-Host "4. No Office Suite (Remove all office software)" -ForegroundColor Yellow
Write-Host "5. Skip this section (No changes to office software)" -ForegroundColor Yellow

$officeChoice = Read-Host "Enter your choice (1/2/3/4/5)"

# List of all Office-related apps that need to be removed
$officeApps = @(
    "Microsoft.Office.Desktop",
    "Microsoft.Office.OneNote",
    "Microsoft.OfficeHub",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.Office",
    "TheDocumentFoundation.LibreOffice",
    "Apache.OpenOffice",
    "Microsoft.OutlookForWindows",
    "Microsoft.OutlookWebApp",
    "Microsoft.Office.OneDriveSync"
)

# Function to Remove Office Hub (Only when installing an Office suite)
function Remove-OfficeHub {
    Write-Host "Removing Office Hub and any leftover Office components..." -ForegroundColor Magenta
    $officeHubApp = "Microsoft.MicrosoftOfficeHub"

    if ($null -ne (Get-AppxPackage -Name $officeHubApp -ErrorAction SilentlyContinue)) {
        Get-AppxPackage -Name $officeHubApp | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Host "Office Hub removed." -ForegroundColor Green
    } else {
        Write-Host "Office Hub was not installed." -ForegroundColor Cyan
    }

    # Remove Office Web Apps from Start Menu
    Write-Host "Removing Office Web Apps from Start Menu..." -ForegroundColor Yellow
    $officeWebApps = @(
        "Microsoft.Office.WordWebApp",
        "Microsoft.Office.ExcelWebApp",
        "Microsoft.Office.PowerPointWebApp"
    )
    foreach ($app in $officeWebApps) {
        if ($null -ne (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue)) {
            Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Host "Removed: $app" -ForegroundColor Green
        }
    }
}

# Function to Fully Remove All Office Software
function Remove-AllOffice {
    Write-Host "Removing all Office-related software (Microsoft Office, Office Hub, LibreOffice, OpenOffice, Outlook, Web Apps)..." -ForegroundColor Magenta
    foreach ($app in $officeApps) {
        if ($null -ne (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue)) {
            Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Host "Removed: $app" -ForegroundColor Green
        }
    }

    # Remove Office-related folders
    Write-Host "Deleting residual Office files..." -ForegroundColor Yellow
    $officeFolders = @(
        "$env:ProgramFiles\Microsoft Office",
        "$env:ProgramFiles (x86)\Microsoft Office",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:LOCALAPPDATA\Microsoft\Office",
        "$env:APPDATA\Microsoft\Office",
        "$env:ProgramFiles\LibreOffice",
        "$env:ProgramFiles (x86)\LibreOffice",
        "$env:ProgramFiles\OpenOffice",
        "$env:ProgramFiles (x86)\OpenOffice"
    )
    foreach ($folder in $officeFolders) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $folder" -ForegroundColor Green
        }
    }

    # Remove Office-related registry entries
    Write-Host "Cleaning up Office-related registry entries..." -ForegroundColor Yellow
    $officeRegKeys = @(
        "HKCU:\Software\Microsoft\Office",
        "HKCU:\Software\Microsoft\Outlook",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\LibreOffice",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenOffice",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LibreOffice",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenOffice"
    )
    foreach ($regKey in $officeRegKeys) {
        if (Test-Path $regKey) {
            Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed registry key: $regKey" -ForegroundColor Green
        }
    }

    Write-Host "All Office-related software has been removed." -ForegroundColor Green
}

# User Selection Handling
if ($officeChoice -eq "1") {
    Write-Host "Installing Microsoft Office..." -ForegroundColor Magenta
    winget install --id Microsoft.Office --silent --accept-package-agreements --accept-source-agreements
    Write-Host "Microsoft Office installed." -ForegroundColor Green
    Remove-OfficeHub  # Remove Office Hub after installation

} elseif ($officeChoice -eq "2") {
    Write-Host "Installing LibreOffice..." -ForegroundColor Magenta
    winget install --id TheDocumentFoundation.LibreOffice --silent --accept-package-agreements --accept-source-agreements
    Write-Host "LibreOffice installed." -ForegroundColor Green
    Remove-OfficeHub  # Remove Office Hub after installation

} elseif ($officeChoice -eq "3") {
    Write-Host "Installing Apache OpenOffice..." -ForegroundColor Magenta
    winget install --id Apache.OpenOffice --silent --accept-package-agreements --accept-source-agreements
    Write-Host "OpenOffice installed." -ForegroundColor Green
    Remove-OfficeHub  # Remove Office Hub after installation

} elseif ($officeChoice -eq "4") {
    Remove-AllOffice  # Fully remove all office-related apps

} elseif ($officeChoice -eq "5") {
    Write-Host "Skipping office software installation and removal." -ForegroundColor Cyan

} else {
    Write-Host "Invalid selection. No changes made to office software." -ForegroundColor Red
}


## Driver Installation Section ##
# Prompt User to Install Graphics Drivers
$installGPUDrivers = Read-Host "Do you want to install graphics drivers? (y/n)"
$gpuChoice = ""

if ($installGPUDrivers -eq "y") {
    # Prompt User for GPU Brand
    Write-Host "Select your GPU brand to install drivers:" -ForegroundColor Cyan
    Write-Host "1. NVIDIA" -ForegroundColor Green
    Write-Host "2. AMD" -ForegroundColor Red
    Write-Host "3. Intel" -ForegroundColor Blue
    Write-Host "4. Skip (No driver installation)" -ForegroundColor Yellow

    $gpuChoice = Read-Host "Enter the number of your choice (1/2/3/4)"

    # Function to Download and Install Driver Using curl.exe
    function Install-Driver {
        param (
            [string]$DriverURL,
            [string]$DriverPath,
            [string]$InstallArgs
        )

        Write-Host "Downloading driver from $DriverURL ..." -ForegroundColor Cyan
        Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$DriverPath`" `"$DriverURL`"" -NoNewWindow -Wait

        if (Test-Path $DriverPath) {
            Write-Host "Download complete. Installing driver..." -ForegroundColor Green
            Start-Process -FilePath $DriverPath -ArgumentList $InstallArgs -NoNewWindow -Wait
            Remove-Item -Path $DriverPath -Force
            Write-Host "Driver installed successfully." -ForegroundColor Green
        } else {
            Write-Host "Failed to download the driver." -ForegroundColor Red
        }
    }

    # NVIDIA Driver Installation
    function Install-NVIDIA-Drivers {
        Install-Driver `
            -DriverURL "https://us.download.nvidia.com/Windows/572.60/572.60-desktop-win10-win11-64bit-international-dch-whql.exe" `
            -DriverPath "$env:TEMP\NVIDIA-Driver.exe" `
            -InstallArgs "-s"
    }

    # AMD Driver Installation
    function Install-AMD-Drivers {
        Install-Driver `
            -DriverURL "https://drivers.amd.com/drivers/whql-amd-software-adrenalin-edition-24.12.1-win10-win11-dec-rdna.exe" `
            -DriverPath "$env:TEMP\AMD-Driver.exe" `
            -InstallArgs "/INSTALL /SILENT"
    }

    # Intel HD (Integrated Graphics) Installation
    function Install-Intel-HD-Drivers {
        Install-Driver `
            -DriverURL "https://downloadmirror.intel.com/815427/gfx_win_101.2111.exe" `
            -DriverPath "$env:TEMP\Intel-HD-Driver.exe" `
            -InstallArgs "-s"
    }

    # Intel Arc (Dedicated GPU) Installation
    function Install-Intel-Arc-Drivers {
        Install-Driver `
            -DriverURL "https://downloadmirror.intel.com/848516/gfx_win_101.6632.exe" `
            -DriverPath "$env:TEMP\Intel-Arc-Driver.exe" `
            -InstallArgs "-s"
    }

    # Process User Choice
    switch ($gpuChoice) {
        "1" { Install-NVIDIA-Drivers }
        "2" { Install-AMD-Drivers }
        "3" {
            Write-Host "You selected Intel. Please choose the type of Intel GPU you have:" -ForegroundColor Cyan
            Write-Host "1. Intel HD Graphics (Integrated)" -ForegroundColor Yellow
            Write-Host "2. Intel Arc Graphics (Dedicated)" -ForegroundColor Yellow

            $intelChoice = Read-Host "Enter the number of your choice (1/2)"

            switch ($intelChoice) {
                "1" { Install-Intel-HD-Drivers }
                "2" { Install-Intel-Arc-Drivers }
                default { Write-Host "Invalid selection. No Intel drivers will be installed." -ForegroundColor Red }
            }
        }
        "4" { Write-Host "Skipping graphics driver installation." -ForegroundColor Cyan }
        default { Write-Host "Invalid selection. No drivers will be installed." -ForegroundColor Red }
    }
}

# Function to disable a service
function Disable-Service {
    param ([string]$serviceName)
    Write-Host "Disabling service: $serviceName" -ForegroundColor Yellow
    try {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Host "Service $serviceName disabled successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable service $serviceName. It may not exist on this system." -ForegroundColor Red
    }
}

# Function to disable a scheduled task
function Disable-ScheduledTask {
    param ([string]$taskPath)
    Write-Host "Disabling scheduled task: $taskPath" -ForegroundColor Yellow
    try {
        schtasks /Change /TN $taskPath /Disable
        Write-Host "Scheduled task $taskPath disabled successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable scheduled task $taskPath. It may not exist on this system." -ForegroundColor Red
    }
}

# Function to set a registry value
function Set-RegistryValue {
    param ([string]$path, [string]$name, [string]$value)
    Write-Host "Setting registry value: Path = $path, Name = $name, Value = $value" -ForegroundColor Yellow
    try {
        New-Item -Path $path -Force | Out-Null
        Set-ItemProperty -Path $path -Name $name -Value $value
        Write-Host "Registry value $name set successfully at $path." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set registry value $name at $path." -ForegroundColor Red
    }
}

Write-Host "Checking installed GPU drivers for telemetry removal..." -ForegroundColor Magenta

# Detect Installed GPU Drivers
$installedDrivers = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name

if ($installedDrivers -match "NVIDIA") {
    Write-Host "Detected NVIDIA drivers. Disabling NVIDIA telemetry..." -ForegroundColor Cyan

    # Disable NVIDIA Telemetry Services
    $nvTelemetryServices = @("NvTelemetryContainer", "NvContainerLocalSystem", "NvContainerNetworkService")
    foreach ($service in $nvTelemetryServices) { Disable-Service -serviceName $service }

    # Disable NVIDIA Telemetry Scheduled Tasks
    $nvTelemetryTasks = @("\NvTmMon", "\NvTmRep", "\NvTmRepOnLogon")
    foreach ($task in $nvTelemetryTasks) { Disable-ScheduledTask -taskPath $task }

    # Disable NVIDIA Telemetry via Registry
    Set-RegistryValue -path "HKLM:\Software\NVIDIA Corporation\Global\NvTelemetry" -name "EnableTelemetry" -value 0

    # Check for NVIDIA GeForce Experience and disable its telemetry
    if (Test-Path "C:\Program Files\NVIDIA Corporation\GeForce Experience") {
        Write-Host "Detected GeForce Experience. Disabling telemetry..." -ForegroundColor Cyan
        Set-RegistryValue -path "HKLM:\Software\NVIDIA Corporation\Global\GeForce Experience" -name "EnableCEIP" -value 0
    }
}

if ($installedDrivers -match "AMD") {
    Write-Host "Detected AMD drivers. Disabling AMD telemetry..." -ForegroundColor Cyan

    # Disable AMD User Experience Program via Registry
    Set-RegistryValue -path "HKLM:\Software\AMD\CN" -name "UserExperienceProgram" -value 0

    # Disable AMD External Events Utility Service
    Disable-Service -serviceName "AMD External Events Utility"
}

Write-Host "GPU tracking and telemetry disabled where applicable." -ForegroundColor Green




# Restart explorer one last time.
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
Write-Host ""
Start-Sleep -Seconds 2

# Inform the user that a restart is recommended
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


#$continue = Read-Host "Do you want to return to the OGC Windows Utility to make additional optimizations or changes to your PC? (Y/N)"
#if ($continue -match "^[Yy]$") {
#    # Launch OGC Windows Utility
#    powershell.exe -NoExit -ExecutionPolicy Bypass -NoProfile -Command "
#        `$host.UI.RawUI.BackgroundColor = 'Black'; 
#        `$host.UI.RawUI.ForegroundColor = 'White'; 
#        Clear-Host;
#        & '$scriptsFolder\OGCWin.ps1'
#    "
#} else {
#    Write-Host "This window will now close" -ForegroundColor Green
#    Start-Sleep -Seconds 3
#    `$host.UI.RawUI.FlushInputBuffer()
#    Stop-Process -Id `$PID -Force
#}
