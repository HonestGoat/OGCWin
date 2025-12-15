# ==========================================
#        OGC Desktop Layout Manager
#              By Honest Goat
#               Version: 0.1
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

# ==========================================
# Variable Definitions
# ==========================================

# Folder definitions
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$tempFolder = "$parentFolder\temp"
$scriptsFolder = "$parentFolder\scripts"
$utilitiesFolder = "$parentFolder\utilities"
$desktopProfiles = "$parentFolder\backups\desktop profiles"

# Filenane definitions
$ogcwin = "$scriptsFolder\OGCWin.ps1"
$desktopLayout = "$utilitiesFolder\desktop-layout.ps1"
$ShortcutPath = "$env:USERPROFILE\Desktop\Desktop Layout Manager.lnk"
$savePath = "$desktopProfiles\$profileName.reg"
$tempReg = "$tempFolder\modern_layout.reg"

# Function Variables
$currentScriptPath = $MyInvocation.MyCommand.Definition
$WshShell = New-Object -comObject WScript.Shell
$winVer = Get-OSVersion
$profiles = Get-ChildItem -Path $desktopProfiles -Filter "*.reg"

# Registry Keys (Targets both known registry locations for desktop layouts in Windows 10 & 11)
$regKeyLegacy = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop"
$regKeyModern = "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\1\Desktop"


# ==========================================
# FUNCTIONS
# ==========================================

Function Install-Utility {
    Write-Host "Checking installation status..." -ForegroundColor Cyan
    # Check if directories exist
    if (-not (Test-Path $utilitiesFolder)) { New-Item -Path $utilitiesFolder -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $desktopProfiles)) { New-Item -Path $desktopProfiles -ItemType Directory -Force | Out-Null }
    # Check if script is running from the correct location
        
    if ($currentScriptPath -ne $desktopLayout) {
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
        Write-Host "Installation complete. Restarting for changes to take effect..." -ForegroundColor Green
        Start-Sleep -Seconds 2
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$desktopLayout`""
        Exit
    }
}

Function Get-OSVersion {
    $os = Get-CimInstance Win32_OperatingSystem
    return $os.Caption # Returns Windows 10 or 11
}

Function Restart-Explorer {
    Write-Host "Restarting Windows Explorer to apply profile..." -ForegroundColor Yellow
    Stop-Process -ProcessName explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    # Check if explorer restarted automatically, if not, start it
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
        Start-Process explorer.exe
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
    Clear-Host
    Write-Color "OGC Banner" -ForegroundColor Yellow
    Write-Color "=======================================" -ForegroundColor DarkBlue
    Write-Color "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Color "      OO    OO  GG        CC           " -ForegroundColor Cyan
    Write-Color "      OO    OO  GG   GGG  CC           " -ForegroundColor Cyan
    Write-Color "      OO    OO  GG    GG  CC           " -ForegroundColor Cyan
    Write-Color "       OOOOOO    GGGGGG    CCCCCC      " -ForegroundColor Cyan
    Write-Color "                                       " -ForegroundColor Cyan
    Write-Color "      OGC Desktop Layout Manager       " -ForegroundColor Yellow
    Write-Color "        https://discord.gg/ogc         " -ForegroundColor Magenta
    Write-Color "        Created by Honest Goat         " -ForegroundColor Green
    Write-Host "----------------------------------------" -ForegroundColor Blue
    Write-Host " OS Detected: $winVer                " -ForegroundColor Gray
    Write-Host " Location: $desktopLayout               " -ForegroundColor Gray
    Write-Color "=======================================" -ForegroundColor DarkBlue
    Write-Host "1. Save Desktop Layout (Create Profile)"
    Write-Host "2. Restore Desktop Layout (Load saved Profile)"
    Write-Host "3. Exit to OGC Windows Utility"
    Write-Host "Q. Quit to Desktop"
    Write-Host "====================================="
    
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
            reg export "$regKeyLegacy" "$savePath" /y | Out-Null # Export Legacy Key (User Confirmed)
            
            # Gathers both registry keys and exports them to temp then combines them into a single reg file.
            if (-not (Test-Path $tempFolder)) { New-Item -Path $tempFolder -ItemType Directory | Out-Null }
            reg export "$regKeyModern" "$tempReg" /y 2>$null | Out-Null # Exports both keys to a single reg file
            if (Test-Path $tempReg) {
                Get-Content "$tempReg" | Select-Object -Skip 1 | Add-Content "$savePath"
                Remove-Item "$tempReg" -Force
            }

            if (Test-Path $savePath) {
                Write-Host "Profile '$profileName' saved successfully!" -ForegroundColor Green
            } else {
                Write-Host "Error saving profile." -ForegroundColor Red
            }
            Start-Sleep -Seconds 2
        }

        "2" {
            # --- Restore Profile ---
            Write-Host "`n[RESTORE PROFILE]" -ForegroundColor Green
            
            if ($profiles.Count -eq 0) {
                Write-Host "No profiles found in $desktopProfiles" -ForegroundColor Red
                Pause
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
                reg import "$($selectedProfile.FullName)"
                Restart-Explorer
                
                Write-Host "Desktop layout restored successfully." -ForegroundColor Green
                Start-Sleep -Seconds 2
            } elseif ($selection -eq "C" -or $selection -eq "c") {
                continue
            } else {
                Write-Host "Invalid selection." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }

        "3" {
            # Return to OGCWin
            Write-Host "Returning to OGC Windows Utility..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            if (Test-Path $ogcwin) {
                & $ogcwin
            } else {
                Write-Host "Warning: $ogcwin not found." -ForegroundColor Red
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