# OGC Windows and Gaming Utility by Honest Goat
# Version: 1.1
# This script disables tracking and data collection, optimizes Windows for gaming, removes bloatware,
# disables invasive and annoying features like CoPilot and Recall, removes Edge integrations and annoyances
# and allows the user to install a host of common applications drivers.

# Set PowerShell Execution Policy to allow scripts (requires admin)
Set-ExecutionPolicy Bypass -Scope Process -Force

# Define color functions for better visibility
function Write-Color {
    param (
        [string]$Text,
        [string]$ForegroundColor = "White",
        [string]$BackgroundColor = "Black"
    )
    Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
}

# Function to show progress bar
function Show-Progress {
    param (
        [string]$Message
    )
    Write-Host "[$Message]" -ForegroundColor Blue
    Start-Sleep -Seconds 2
}

# OGC Banner
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
Write-Host "                                       " -ForegroundColor Cyan
Write-Host "       OGC Windows Gaming Utility      " -ForegroundColor Yellow
Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
Write-Host "        Created by Honest Goat         " -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor DarkBlue
Write-Host ""

# Welcome & Instructions
Write-Host "Welcome to the OGC Windows Gaming Utility!" -ForegroundColor Cyan
Write-Host ""
Write-Host "This utility will help you optimize your Windows installation by:" -ForegroundColor Yellow
Write-Host "✔ Removing unnecessary bloatware and preinstalled apps" -ForegroundColor Green
Write-Host "✔ Disabling telemetry, tracking, and data collection" -ForegroundColor Green
Write-Host "✔ Customizing Windows settings for a better gaming experience" -ForegroundColor Green
Write-Host "✔ Improving privacy and performance" -ForegroundColor Green
Write-Host "✔ Allow you to remove or install common applications." -ForegroundColor Green
Write-Host ""
Write-Host "! For optimal performance and privacy, settings marked [Recommended] should be chosen. !" -ForegroundColor Magenta
Write-Host ""
Write-Host "⚠ IMPORTANT: This utility will make changes to your system, but no critical functionality will be lost." -ForegroundColor Red
Write-Host "Please read each prompt carefully before proceeding." -ForegroundColor Red
Write-Host ""

# Confirm User Wants to Continue
$continueScript = Read-Host "Do you want to continue with the script? (y/n)"

if ($continueScript -ne "y") {
    Write-Host "Exiting script. No changes have been made." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}

# Detect Windows Version
$winVer = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Detected Windows Version: $winVer" -ForegroundColor Yellow

if ($winVer -match "Windows 11") {
    Write-Host "Windows 11 optimizations selected." -ForegroundColor Green
    $win11 = $true
    Start-Sleep -Seconds 1
} elseif ($winVer -match "Windows 10") {
    Write-Host "Windows 10 optimizations selected." -ForegroundColor Green
    $win11 = $false
    Start-Sleep -Seconds 1
} else {
    Write-Host "Unsupported Windows Version. Exiting." -ForegroundColor Red
    exit
}

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

# Disable Cortana via Group Policy Registry Settings
Write-Host "Disabling Cortana via Group Policy..." -ForegroundColor Magenta
$gpCortanaKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $gpCortanaKey)) { New-Item -Path $gpCortanaKey -Force | Out-Null }
Set-ItemProperty -Path $gpCortanaKey -Name "AllowCortana" -Type DWord -Value 0 -Force
Write-Host "Cortana has been disabled via Group Policy." -ForegroundColor Green

# Disable Cortana & Bing Search in User's Search Settings
Write-Host "Disabling Cortana & Bing Search in User Settings..." -ForegroundColor Magenta
$searchKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
if (!(Test-Path $searchKey)) { New-Item -Path $searchKey -Force | Out-Null }
Set-ItemProperty -Path $searchKey -Name "CortanaConsent" -Type DWord -Value 0 -Force
Set-ItemProperty -Path $searchKey -Name "BingSearchEnabled" -Type DWord -Value 0 -Force
Write-Host "Cortana and Bing Search have been disabled in User Settings." -ForegroundColor Green

# Disable Location Tracking
Write-Host "Disabling Location Tracking..." -ForegroundColor Magenta
$locationKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (!(Test-Path $locationKey)) { New-Item -Path $locationKey -Force | Out-Null }
Set-ItemProperty -Path $locationKey -Name "EnableLocation" -Type DWord -Value 0 -Force
Write-Host "Location Tracking Disabled." -ForegroundColor Green

Write-Host "Your privacy has been enhanced and tracking, telemetry and data collection has been disabled!" -ForegroundColor Green

# Prompt the user for consent to block telemetry domains
$blockTelemetry = Read-Host "Do you want to block known Microsoft tracking and telemetry domains via the hosts file? [Recommended] (y/n)"

if ($blockTelemetry -eq "y") {
    Write-Host "Blocking Telemetry Domains via Hosts File..." -ForegroundColor Magenta

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $backupPath = "$hostsPath.bak"

    # Define telemetry domains
    $telemetryDomains = @(
        "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "telemetry.microsoft.com",
        "watson.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "telemetry.appex.bing.net:443",
        "settings-sandbox.data.microsoft.com",
        "survey.watson.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com",
        "watson.microsoft.com",
        "watson.live.com",
        "redir.metaservices.microsoft.com",
        "choice.microsoft.com",
        "df.telemetry.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com",
        "sqm.df.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com",
        "watson.telemetry.microsoft.com.nsatc.net",
        "redir.metaservices.microsoft.com",
        "choice.microsoft.com.nsatc.net",
        "df.telemetry.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com",
        "sqm.df.telemetry.microsoft.com",
        "telemetry.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "settings-sandbox.data.microsoft.com",
        "s0.2mdn.net",
        "statsfe2.ws.microsoft.com",
        "corpext.msitadfs.glbdns2.microsoft.com",
        "compatexchange.cloudapp.net",
        "a-0001.a-msedge.net",
        "statsfe2.update.microsoft.com.akadns.net",
        "diagnostics.support.microsoft.com",
        "corp.sts.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "feedback.windows.com",
        "feedback.microsoft-hohm.com",
        "feedback.search.microsoft.com",
        "rad.msn.com",
        "preview.msn.com",
        "ad.doubleclick.net",
        "ads.msn.com",
        "ads1.msads.net",
        "ads1.msn.com",
        "a.ads1.msn.com",
        "a.ads2.msn.com",
        "adnexus.net",
        "adnxs.com",
        "az361816.vo.msecnd.net",
        "az512334.vo.msecnd.net",
        "ssw.live.com",
        "ca.telemetry.microsoft.com",
        "i1.services.social.microsoft.com",
        "i1.services.social.microsoft.com.nsatc.net"
    )

    # Ensure PowerShell is running as Admin
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: You must run PowerShell as Administrator to modify the hosts file." -ForegroundColor Red
        exit 1
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
        exit 1
    }

    # Add telemetry domains to the hosts file if they are not already present
    foreach ($domain in $telemetryDomains) {
        $entry = "0.0.0.0 $domain"
        if ($hostsContent -notcontains $entry) {
            Write-Host "Adding $domain to hosts file..." -ForegroundColor Green
            "$entry" | Out-File -FilePath $hostsPath -Encoding utf8 -Append
        } else {
            Write-Host "$domain is already present in the hosts file." -ForegroundColor Yellow
        }
    }

    Write-Host "Telemetry domains have been blocked via the hosts file." -ForegroundColor Green
} else {
    Write-Host "Skipping the blocking of telemetry domains." -ForegroundColor Cyan
}

# Prompt the user for bloatware removal
$removeBloatware = Read-Host "Do you want to remove preinstalled advertising apps and bloatware? [Recommended] (y/n)"

if ($removeBloatware -eq "y") {
    Write-Host "Removing Preinstalled Advertising Apps..." -ForegroundColor Magenta

    $crapware = @(
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
        "Microsoft.WindowsSoundRecorder"
    )

    foreach ($app in $crapware) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }

    Write-Host "Preinstalled advertising apps and bloatware removed." -ForegroundColor Green

} else {
    Write-Host "Skipping bloatware removal." -ForegroundColor Cyan
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

# Function to check if an app is installed
function Test-AppInstalled {
    param (
        [string]$AppName
    )
    return ($null -ne (Get-AppxPackage -Name $AppName -ErrorAction SilentlyContinue))
}

# List of Xbox and Game Pass related apps
$xboxApps = @{
    "Microsoft.Xbox.TCUI" = "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp" = "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay" = "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay" = "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider" = "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay" = "Microsoft.XboxSpeechToTextOverlay"
}

# Prompt the user
$useXbox = Read-Host "Do you want to use Windows Game Pass or xBox features? (y/n)"

foreach ($app in $xboxApps.Keys) {
    $isInstalled = Test-AppInstalled -AppName $app

    if ($useXbox -eq "y") {
        if ($isInstalled) {
            Write-Host "$app is already installed. Keeping it." -ForegroundColor Green
        } else {
            Write-Host "$app is not installed. Installing now..." -ForegroundColor Yellow
            winget install --id $xboxApps[$app] --silent --accept-package-agreements --accept-source-agreements
            Write-Host "$app installed successfully." -ForegroundColor Green
        }
    } else {
        if ($isInstalled) {
            Write-Host "Removing $app..." -ForegroundColor Magenta
            Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Host "$app removed." -ForegroundColor Green
        } else {
            Write-Host "$app is not installed. No action needed." -ForegroundColor Cyan
        }
    }
}

# Ask about OneDrive
$removeOneDrive = Read-Host "Do you want to remove Microsoft OneDrive? [Recommended] (y/n)"

if ($removeOneDrive -eq "y") {
    Write-Host "Removing Microsoft OneDrive..." -ForegroundColor Magenta

    # Possible OneDriveSetup.exe locations
    $oneDrivePaths = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDriveSetup.exe"
    )

    # Find the correct path
    $oneDriveSetup = $oneDrivePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($oneDriveSetup) {
        # Stop OneDrive process if running
        Write-Host "Stopping OneDrive process..." -ForegroundColor Yellow
        Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Uninstall OneDrive
        Write-Host "Running OneDrive uninstaller..." -ForegroundColor Yellow
        Start-Process -FilePath $oneDriveSetup -ArgumentList "/uninstall" -NoNewWindow -Wait
        Write-Host "Microsoft OneDrive removed successfully." -ForegroundColor Green
    } else {
        Write-Host "Error: OneDriveSetup.exe not found. OneDrive may already be removed." -ForegroundColor Red
    }

} else {
    Write-Host "Keeping Microsoft OneDrive." -ForegroundColor Cyan
}

# Ask the user if they want to use Microsoft Teams
$useTeams = Read-Host "Do you use Microsoft Teams? (y/n)"

# Check if Teams is installed
$teamsInstalled = Get-AppxPackage -Name "MicrosoftTeams" -ErrorAction SilentlyContinue

if ($useTeams -eq "y") {
    if ($teamsInstalled) {
        Write-Host "Microsoft Teams is already installed. Keeping Teams." -ForegroundColor Green
    } else {
        Write-Host "Microsoft Teams is not installed. Installing now..." -ForegroundColor Yellow
        winget install Microsoft.Teams -e --accept-package-agreements --accept-source-agreements
        Write-Host "Microsoft Teams installed successfully." -ForegroundColor Green
    }

    # Ensure Teams icon remains on the taskbar
    Write-Host "Keeping Microsoft Teams icon on the taskbar." -ForegroundColor Cyan

} elseif ($useTeams -eq "n") {
    if ($teamsInstalled) {
        Write-Host "Removing Microsoft Teams..." -ForegroundColor Magenta
        Get-AppxPackage -Name "MicrosoftTeams" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Host "Microsoft Teams removed." -ForegroundColor Green
    } else {
        Write-Host "Microsoft Teams is not installed. No action needed." -ForegroundColor Cyan
    }

    # Remove "Meet Now" icon from the taskbar
    Write-Host "Removing 'Meet Now' icon from the taskbar..." -ForegroundColor Yellow
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
    Write-Host "'Meet Now' icon removed from the taskbar." -ForegroundColor Green
} else {
    Write-Host "Invalid selection. No changes made to Microsoft Teams." -ForegroundColor Red
}

# Ask about Microsoft Copilot
$removeCopilot = Read-Host "Do you want to remove Microsoft Copilot? [Recommended] (y/n)"

if ($removeCopilot -eq "y") {
    Write-Host "Removing Microsoft Copilot..." -ForegroundColor Magenta
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
    Write-Host "Microsoft Copilot disabled." -ForegroundColor Green
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

# Apply Windows 10 Look on Windows 11 (Only if Windows 11 is detected)
if ($win11) {
    $win10look = Read-Host "Do you want Windows 11 to look and feel like Windows 10? [Recommended] (y/n)"

    if ($win10look -eq "y") {
        Write-Host "Applying Windows 10 UI tweaks..." -ForegroundColor Magenta

        # Enable Classic Start Menu Mode
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowClassicMode" /t REG_DWORD /d 1 /f

        # Align Taskbar to the Left
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f

        # Enable Windows 10 Classic Right-Click Context Menu (Disable Windows 11 context menu)
        reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f
        reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f

        Write-Host "Windows 10 UI tweaks applied! Explorer will restart after all tweaks have been selected." -ForegroundColor Green
    }
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

# Prompt user to debloat the taskbar
$debloatTaskbar = Read-Host "Do you want to debloat the taskbar and remove unnecessary icons? [Recommended] (y/n)"

if ($debloatTaskbar -eq "y") {
    Write-Host "Debloating the taskbar..." -ForegroundColor Magenta

    # Apply all taskbar tweaks
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0  # Remove Task View
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0  # Remove Search Bar
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value 2  # Remove News & Interests (Weather Widget)
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0  # Remove People Icon
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -Value 0  # Remove Ink Workspace

    Write-Host "Disabling Weather & News Widget..." -ForegroundColor Magenta

    # Windows 10 & 11: Disable the Feeds & News Widget in Taskbar
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "EnableFeeds" -Type DWord -Value 0 -Force
    
    # Windows 11: Disable Widgets via Taskbar settings
    if ((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarDa -ErrorAction SilentlyContinue)) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarDa -Type DWord -Value 0 -Force
    }
    
    # Windows 10 & 11: Disable News & Interests via Taskbar settings
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0 -Force
    
#    # Disable the Widgets Service in Windows 11
#    Get-Service "Widgets" -ErrorAction SilentlyContinue | Stop-Service -Force
#    Set-Service -Name "Widgets" -StartupType Disabled
    
    Write-Host "Weather & News Widget fully disabled." -ForegroundColor Green
        
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
$debloatEdge = Read-Host "Do you want to remove Edge's forced features? [Recommended] (y/n)"
if ($debloatEdge -eq "y") {
    Write-Host "Disabling Edge forced features..." -ForegroundColor Magenta
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "RestorePdfAssociationsEnabled" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
    Write-Host "Edge features disabled!" -ForegroundColor Green
}

# Ask if user wants gaming optimizations
$gameOptimizations = Read-Host "Do you want to enable gaming features like Game Mode, VRR, HAGS? [Recommended] (y/n)"
if ($gameOptimizations -eq "y") {
    Write-Host "Applying gaming optimizations..." -ForegroundColor Magenta
    reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GraphicsSettings" /v "HwSchMode" /t REG_DWORD /d 2 /f
    Write-Host "Gaming features enabled!" -ForegroundColor Green
}

# Restart Explorer to apply any UI and Taskbar Tweaks
Write-Host "Restarting Windows Explorer to apply changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force
Start-Process -FilePath "explorer.exe" -ArgumentList "/n" -WindowStyle Hidden
Write-Host "Windows Explorer Restarted." -ForegroundColor Green

# Install Gaming Apps (Steam, Epic, GOG, Discord, Medal)
$installGamingApps = Read-Host "Do you want to install gaming apps like Steam, Epic, GOG, Discord, and Medal? (y/n)"
if ($installGamingApps -eq "y") {
    Write-Host "Installing Gaming Apps..." -ForegroundColor Cyan

    $installSteam = Read-Host "Do you want to install Steam? (y/n)"
    if ($installSteam -eq "y") {
        Write-Host "Installing Steam..." -ForegroundColor Magenta
        winget install Valve.Steam
    }

    $installEpic = Read-Host "Do you want to install Epic Games Launcher? (y/n)"
    if ($installEpic -eq "y") {
        Write-Host "Installing Epic Games Launcher..." -ForegroundColor Magenta
        winget install EpicGames.EpicGamesLauncher
    }

    $installGOG = Read-Host "Do you want to install GOG Galaxy? (y/n)"
    if ($installGOG -eq "y") {
        Write-Host "Installing GOG Galaxy..." -ForegroundColor Magenta
        winget install GOG.Galaxy
    }

    $installDiscord = Read-Host "Do you want to install Discord for voice chat? (y/n)"
    if ($installDiscord -eq "y") {
        Write-Host "Installing Discord..." -ForegroundColor Magenta
        winget install Discord.Discord
    }

    $installMedal = Read-Host "Do you want to install Medal for game clip recording? (y/n)"
    if ($installMedal -eq "y") {
        Write-Host "Installing Medal..." -ForegroundColor Magenta
        winget install Medal.TV
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
        winget install REALiX.HWiNFO
    }

    $installMSIAfterburner = Read-Host "Do you want to install MSI Afterburner for overclocking? (y/n)"
    if ($installMSIAfterburner -eq "y") {
        Write-Host "Installing MSI Afterburner..." -ForegroundColor Magenta
        winget install MSI.Afterburner
    }

    $installRTSS = Read-Host "Do you want to install RivaTuner Statistics Server (RTSS) for FPS monitoring? (y/n)"
    if ($installRTSS -eq "y") {
        Write-Host "Installing RivaTuner Statistics Server (RTSS)..." -ForegroundColor Magenta
        winget install Guru3D.RTSS
    }

    $installCPUID = Read-Host "Do you want to install CPU-Z for CPU information? (y/n)"
    if ($installCPUID -eq "y") {
        Write-Host "Installing CPU-Z..." -ForegroundColor Magenta
        winget install CPUID.CPU-Z
    }

    $installGPUZ = Read-Host "Do you want to install GPU-Z for GPU information? (y/n)"
    if ($installGPUZ -eq "y") {
        Write-Host "Installing GPU-Z..." -ForegroundColor Magenta
        winget install TechPowerUp.GPU-Z
    }

    Write-Host "Gaming and monitoring utilities installation completed." -ForegroundColor Green
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
        }
        "2" {
            Write-Host "Installing Brave..." -ForegroundColor Magenta
            winget install Brave.Brave
        }
        "3" {
            Write-Host "Installing Opera GX..." -ForegroundColor Magenta
            winget install Opera.OperaGX
        }
        "4" {
            Write-Host "Installing Chrome..." -ForegroundColor Magenta
            winget install Google.Chrome
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
Write-Host "3. No Office Suite (Remove all office software)" -ForegroundColor Yellow
Write-Host "4. Skip this section (No changes to office software)" -ForegroundColor Yellow

$officeChoice = Read-Host "Enter your choice (1/2/3/4)"

# Office Hub app and unnecessary office apps
$officeHubApp = "Microsoft.MicrosoftOfficeHub"
$officeApps = @(
    "Microsoft.Office.Desktop",
    "Microsoft.Office.OneNote",
    "Microsoft.OfficeHub",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.Office",
    "TheDocumentFoundation.LibreOffice",
    "Apache.OpenOffice"
)

# Function to Remove Office Hub (Only when installing an Office suite)
function Remove-OfficeHub {
    Write-Host "Removing Office Hub..." -ForegroundColor Magenta
    if ($null -ne (Get-AppxPackage -Name $officeHubApp -ErrorAction SilentlyContinue)) {
        Get-AppxPackage -Name $officeHubApp | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Host "Office Hub removed." -ForegroundColor Green
    } else {
        Write-Host "Office Hub was not installed." -ForegroundColor Cyan
    }
}

# Function to Fully Remove All Office Software
function Remove-AllOffice {
    Write-Host "Removing all Office-related software (Microsoft Office, Office Hub, LibreOffice, OpenOffice)..." -ForegroundColor Magenta
    foreach ($app in $officeApps) {
        if ($null -ne (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue)) {
            Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Host "Removed: $app" -ForegroundColor Green
        }
    }
    Write-Host "Office software cleanup completed." -ForegroundColor Green
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
    Remove-AllOffice  # Fully remove all office-related apps

} elseif ($officeChoice -eq "4") {
    Write-Host "Skipping office software installation and removal." -ForegroundColor Cyan

} else {
    Write-Host "Invalid selection. No changes made to office software." -ForegroundColor Red
}

# Prompt User to Install Graphics Drivers
$installGPUDrivers = Read-Host "Do you want to install graphics drivers? (y/n)"
if ($installGPUDrivers -eq "y") {

    # Prompt User for GPU Brand
    Write-Host "Select your GPU brand to install drivers:" -ForegroundColor Cyan
    Write-Host "1. NVIDIA" -ForegroundColor Green
    Write-Host "2. AMD" -ForegroundColor Red
    Write-Host "3. Intel" -ForegroundColor Blue
    Write-Host "4. Skip (No driver installation)" -ForegroundColor Yellow

    $gpuChoice = Read-Host "Enter the number of your choice (1/2/3/4)"

    # Function to Download & Install Driver Using curl.exe
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
            # Intel: Ask if the user has an Integrated (HD) or Dedicated (Arc) GPU
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

} else {
    Write-Host "Skipping graphics driver installation." -ForegroundColor Cyan
}

# Check for OGCWin shortcut.
# Define the desktop path for the OGCWin shortcut
$desktopPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "OGCWin.lnk")

# Define the shortcut target
$shortcutTarget = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcutArguments = "-ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -verb runas -ArgumentList 'irm https://raw.githubusercontent.com/HonestGoat/OGCWin/main/launch.ps1 | iex'`""

# Check if the shortcut already exists
if (-Not (Test-Path $desktopPath)) {
    Write-Host "OGCWin shortcut not found. Creating one now..." -ForegroundColor Yellow

    # Create a new WScript Shell object
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($desktopPath)
    $Shortcut.TargetPath = $shortcutTarget
    $Shortcut.Arguments = $shortcutArguments
    $Shortcut.Description = "Run OGCWin Script"
    $Shortcut.IconLocation = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  # Optional: Set an icon
    $Shortcut.Save()

        # Exempt the shortcut and PowerShell from Windows Defender
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-Command Add-MpPreference -ExclusionPath '$desktopPath'"
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-Command Add-MpPreference -ExclusionProcess 'powershell.exe'"

    Write-Host "OGCWin shortcut created successfully on the desktop." -ForegroundColor Green

} else {
    Write-Host "OGCWin shortcut already exists. No changes made." -ForegroundColor Cyan
}

Write-Host "===========================================" -ForegroundColor Green
Write-Host "  OGC Windows Gaming Utility is complete!  " -ForegroundColor Cyan
Write-Host "  Enjoy your optimized gaming experience.  " -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""
Start-Sleep -Seconds 1
Write-Host "In future you can easily run this utility by simply" -ForegroundColor Magenta
Write-Host "double clicking on  the OGCWin icon on your desktop." -ForegroundColor Magenta
Start-Sleep -Seconds 1
Write-Host ""
Write-Host "You may now close the window." -ForegroundColor Green
Pause