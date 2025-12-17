# ==========================================
#        OGC Desktop Layout Manager
#              By Honest Goat
#               Version: 0.2
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
$host.UI.RawUI.WindowTitle = "OGC Desktop Layout Manager"
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
$tempFolder = "$parentFolder\temp"
$scriptsFolder = "$parentFolder\scripts"
$utilitiesFolder = "$parentFolder\utilities"
$logFolder = "$parentFolder\logs"
$desktopProfiles = "$parentFolder\backups\desktop profiles"

# Filename definitions
$ogcwin = "$scriptsFolder\OGCWin.ps1"
$desktopLayout = "$utilitiesFolder\desktop-layout.ps1"
$desktopLogFile = "$logFolder\desktop-layout_log.txt"
$ShortcutPath = "$env:USERPROFILE\Desktop\Desktop Layout Manager.lnk"
$tempReg = "$tempFolder\modern_layout.reg"

# Registry Keys
$regKeyLegacy = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop"
$regKeyModern = "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\1\Desktop"

# Function Variables
$currentScriptPath = $MyInvocation.MyCommand.Definition
$WshShell = New-Object -comObject WScript.Shell

# ==========================================
#             FUNCTIONS
# ==========================================

# --- Logging Function ---
function Write-Log {
    param (
        [Parameter(Mandatory=$true)] [string]$Message,
        [Parameter(Mandatory=$true)] [ValidateSet("SUCCESS","FAILURE","INFO","WARNING")] [string]$Status,
        [string]$Module = "DesktopManager"
    )
    # Check dir exists
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    
    # Build string
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$Status] [$timestamp] [$Module] $Message"
    
    # Save to file
    try { Add-Content -Path $desktopLogFile -Value $logEntry -Force -ErrorAction Stop }
    catch { Write-Host "CRITICAL: Can't write to $desktopLogFile" -ForegroundColor Red }
    
    # Alert console on issues
    if ($Status -eq "FAILURE") { Write-Host "Error ($Module): $Message" -ForegroundColor Red }
    elseif ($Status -eq "WARNING") { Write-Host "Warning ($Module): $Message" -ForegroundColor Yellow }
}

Function Install-Utility {
    Write-Host "Checking installation status..." -ForegroundColor Cyan
    try {
        # Check if directories exist
        if (-not (Test-Path $utilitiesFolder)) { New-Item -Path $utilitiesFolder -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $desktopProfiles)) { New-Item -Path $desktopProfiles -ItemType Directory -Force | Out-Null }
        
        # Check if script is running from the correct location
        if ($currentScriptPath -ne $desktopLayout) {
            Write-Log -Message "Installing utility to: $utilitiesFolder" -Status INFO
            Write-Host "Installing utility to: $utilitiesFolder" -ForegroundColor Yellow
            Copy-Item -Path $currentScriptPath -Destination $desktopLayout -Force
            
            # Create Desktop Shortcut
            $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$desktopLayout`""
            $Shortcut.IconLocation = "shell32.dll,276"
            $Shortcut.WindowStyle = 1
            $Shortcut.Description = "OGC Desktop Layout Manager"
            $Shortcut.Save()
            
            Write-Log -Message "Installation complete." -Status SUCCESS
            Write-Host "Installation complete. Restarting for changes to take effect..." -ForegroundColor Green
            Start-Sleep -Seconds 2
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$desktopLayout`""
            Exit
        }
    }
    catch {
        Write-Log -Message "Installation failed: $_" -Status FAILURE
        Write-Host "Installation failed. Check logs." -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
}

Function Restart-Explorer {
    Write-Host "Restarting Windows Explorer to apply profile..." -ForegroundColor Yellow
    try {
        Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        # Check if explorer restarted automatically, if not, start it
        if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
            Start-Process explorer.exe
        }
        Write-Log -Message "Explorer restarted successfully." -Status SUCCESS
    }
    catch {
        Write-Log -Message "Failed to restart Explorer: $_" -Status FAILURE
    }
}

# ==========================================
#        INSTALLATION & SETUP
# ==========================================

Write-Host "Checking installation status..." -ForegroundColor Cyan
Start-Sleep -Seconds 1
Install-Utility

# ==========================================
#            MENU LOOP
# ==========================================

while ($true) {
    # Refresh profiles list on every loop
    $profiles = Get-ChildItem -Path $desktopProfiles -Filter "*.reg"

    Clear-Host
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Host "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Host "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Host "                                       " -ForegroundColor Cyan
    Write-Host "      OGC Desktop Layout Manager       " -ForegroundColor Yellow
    Write-Host "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Host "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "---------------------------------------" -ForegroundColor Cyan
    Write-Host " Profiles: $desktopProfiles            " -ForegroundColor Gray
    Write-Host "=======================================" -ForegroundColor DarkBlue
    Write-Host "1. Save Desktop Layout (Create Profile)" -ForegroundColor Green
    Write-Host "2. Restore Desktop Layout (Load saved Profile)" -ForegroundColor Blue
    Write-Host "3. Open Profiles Folder                " -ForegroundColor Yellow
    Write-Host "R. Return to OGC Windows Utility       " -ForegroundColor Gray
    Write-Host "Q. Quit to Desktop                     " -ForegroundColor DarkGray
    Write-Host "=======================================" -ForegroundColor DarkBlue
    
    $choice = Read-Host "Choose and option (1-3)"
    switch ($choice) {
        "1" {
            # --- Save Profile ---
            Write-Host "`n[SAVE PROFILE]" -ForegroundColor Green
            Write-Host "NOTE: Desktop layouts are resolution dependent." -ForegroundColor Red
            Write-Host "If you use multiple resolutions, save separate profiles (e.g. 'Work-4K', 'Gaming-1080p')." -ForegroundColor Gray
            
            $profileName = Read-Host "Enter a name for this profile (Use _ or - instead of spaces)"
            if ([string]::IsNullOrWhiteSpace($profileName)) {
                Write-Host "Invalid name." -ForegroundColor Red
                Start-Sleep -Seconds 1
                continue
            }
            
            Write-Host "Exporting Desktop Layout..."
            $userSavePath = "$desktopProfiles\$profileName.reg"
            try {
                if (-not (Test-Path $tempFolder)) { New-Item -Path $tempFolder -ItemType Directory | Out-Null }
                reg export "$regKeyLegacy" "$userSavePath" /y 2>$null | Out-Null 
                reg export "$regKeyModern" "$tempReg" /y 2>$null | Out-Null 

                # Combine keys if modern exists
                if (Test-Path $tempReg) {
                    Get-Content "$tempReg" | Select-Object -Skip 1 | Add-Content "$userSavePath"
                    Remove-Item "$tempReg" -Force
                }

                if (Test-Path $userSavePath) {
                    Write-Log -Message "Profile '$profileName' saved successfully." -Status SUCCESS
                    Write-Host "Profile '$profileName' saved successfully!" -ForegroundColor Green
                } else {
                    throw "Failed saving profile '$profileName'"
                }
            }
            catch {
                Write-Log -Message "Error saving profile '$profileName': $_" -Status FAILURE
            }
            Start-Sleep -Seconds 1
        }

        "2" {
            # --- Restore Profile ---
            Write-Host "`n[RESTORE PROFILE]" -ForegroundColor Green
            if ($profiles.Count -eq 0) {
                Write-Host "No profiles found in $desktopProfiles" -ForegroundColor Red
                Start-Sleep -Seconds 2
                continue
            }
            # --- List Profiles ---
            $i = 1
            foreach ($p in $profiles) {
                Write-Host "$i. $($p.BaseName)"
                $i++
            }
            Write-Host "C. Cancel"

            $selection = Read-Host "Select a profile number to restore"
            if ($selection -match "^\d+$" -and $selection -le $profiles.Count -and $selection -gt 0) {
                $selectedProfile = $profiles[$selection - 1]
                Write-Host "Restoring profile: $($selectedProfile.BaseName)..." -ForegroundColor Cyan
                
                try {
                    reg import "$($selectedProfile.FullName)" 2>$null | Out-Null
                    Write-Log -Message "Profile restored: $($selectedProfile.BaseName)" -Status SUCCESS
                    Restart-Explorer
                    Write-Host "Desktop layout restored successfully." -ForegroundColor Green
                }
                catch {
                    Write-Log -Message "Failed to restore profile $($selectedProfile.BaseName): $_" -Status FAILURE
                }
                Start-Sleep -Seconds 2
            } elseif ($selection -eq "C" -or $selection -eq "c") {
                continue
            } else {
                Write-Host "Invalid selection." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }

        "3" {Start-Process explorer.exe $desktopProfiles
        }

        "R" {
            # Return to OGCWin
            Write-Host "Returning to OGC Windows Utility..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            if (Test-Path $ogcwin) {
                & $ogcwin
            } else {
                Write-Host "Warning: OGCWin not found." -ForegroundColor Red
                Start-Sleep -Seconds 1
                Write-Host "Repairing OGC Windows Utility..." -ForegroundColor Cyan
                Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -NoExit -Command `" `
                `$host.UI.RawUI.BackgroundColor = 'Black'; `
                `$host.UI.RawUI.ForegroundColor = 'White'; `
                `Clear-Host; `
                `& '$scriptsFolder\launch.ps1'`""
            }
            Exit
        }
        # Quit to Desktop
        "Q" {
            Write-Host "Quitting to desktop..." -ForegroundColor Yellow
            Exit
        }

        Default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }

    }
}