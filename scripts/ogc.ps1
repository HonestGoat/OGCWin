param (
    [string]$action,
    [string]$parameter
)

# Define paths
$parentFolder = "C:\ProgramData\OGC Windows Utility"
$scriptsFolder = "$parentFolder\scripts"
#$bin = "$parentFolder\bin"
$logFolder = "$parentFolder\logs"
$logFile = "$logFolder\ogc.log"
$backupFolder = "$parentFolder\backups"
$desktopRegFile = "$backupFolder\desktop-layout.reg"

# Ensure necessary directories exist
if (!(Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder -Force | Out-Null }
if (!(Test-Path $backupFolder)) { New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null }

# Function to log commands
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $message"
}

switch ($action) {
    
    ### OGC Utility Command ###
    "win" {
        Write-Host "Launching OGCWin Utility..."
        & "$scriptsFolder\OGCWin.ps1"
        Write-Log "Launched OGCWin.ps1"
    }

    ### DESKTOP ICON LAYOUT COMMANDS ###
    "desktop" {
        switch ($parameter) {
            "save" {
                Write-Host "Saving desktop icon layout..."
                Start-Process "reg" -ArgumentList "export `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop` `"$desktopRegFile`" /y" -NoNewWindow -Wait
                Write-Log "Saved desktop icon layout to $desktopRegFile"
            }
            "load" {
                if (Test-Path $desktopRegFile) {
                    Write-Host "Restoring desktop icon layout..."
                    Start-Process "reg" -ArgumentList "import `"$desktopRegFile`"" -NoNewWindow -Wait
                    Write-Log "Restored desktop icon layout from $desktopRegFile"
                    Start-Process "taskkill" -ArgumentList "/f /im explorer.exe" -NoNewWindow -Wait
                    Start-Process "explorer.exe"
                } else {
                    Write-Host "No saved desktop layout found! Run 'ogc desktop save' first."
                }
            }
            "restart" {
                Write-Host "Restarting Windows Explorer..."
                Start-Process "taskkill" -ArgumentList "/f /im explorer.exe" -NoNewWindow -Wait
                Start-Process "explorer.exe"
                Write-Log "Restarted Explorer"
            }
            default {
                Write-Host "Usage: ogc desktop <save | load | restart>"
            }
        }
    }

    ### SERVICE COMMANDS ###
    "services" {
        switch ($parameter) {
            "list" {
                Write-Host "Listing all services..."
                Get-Service
                Write-Log "Listed all services"
            }
            default {
                Write-Host "Restarting service: $parameter..."
                Restart-Service -Name $parameter -Force
                Write-Log "Restarted service: $parameter"
            }
        }
    }

    ### SYSTEM CLEANUP COMMAND ###
    "cleanup" {
        if ($parameter -eq "temp") {
            Write-Host "Cleaning temporary files..."
            Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned temporary files"
        }
    }

    ### POWER PLAN COMMANDS ###
    "power" {
        switch ($parameter) {
            "plan" {
                Write-Host "Current Power Plan:"
                powercfg /getactivescheme
                Write-Log "Checked power plan"
            }
            "plan high" {
                Write-Host "Setting power plan to High Performance..."
                powercfg /setactive SCHEME_MIN
                Write-Log "Switched to High Performance power plan"
            }
            "plan balanced" {
                Write-Host "Setting power plan to Balanced..."
                powercfg /setactive SCHEME_BALANCED
                Write-Log "Switched to Balanced power plan"
            }
            "plan saver" {
                Write-Host "Setting power plan to Power Saver..."
                powercfg /setactive SCHEME_MAX
                Write-Log "Switched to Power Saver power plan"
            }
        }
    }

    ### FIREWALL COMMANDS ###
    "firewall" {
        if ($parameter -eq "enable") {
            Write-Host "Enabling Windows Firewall..."
            Start-Process "netsh" -ArgumentList "advfirewall set allprofiles state on" -NoNewWindow -Wait
            Write-Log "Enabled Windows Firewall"
        } elseif ($parameter -eq "disable") {
            Write-Host "Disabling Windows Firewall..."
            Start-Process "netsh" -ArgumentList "advfirewall set allprofiles state off" -NoNewWindow -Wait
            Write-Log "Disabled Windows Firewall"
        } else {
            Write-Host "Usage: ogc firewall <enable | disable>"
        }
    }

    ### LOG COMMANDS ###
    "log" {
        switch ($parameter) {
            "clear" {
                Clear-Content $logFile
                Write-Host "Log cleared."
            }
            default {
                Write-Host "Showing last 10 log entries..."
                Get-Content $logFile -Tail 10
            }
        }
    }

    ### HELP SECTION ###
    "help" {
        Write-Host "OGC Windows Utility Command Reference"
        Write-Host "------------------------------------"
        Write-Host "ogc win                  - Launch the OGCWin Utility"
        Write-Host "ogc install <app>        - Install software using Winget"
        Write-Host "ogc update [all]         - Update installed apps (Winget)"
        Write-Host "ogc restart [bios]       - Restart Windows or boot into BIOS"
        Write-Host "ogc repair [windows]     - Run SFC/DISM repair tools"
        Write-Host "ogc desktop save/load    - Save or restore desktop icon layout"
        Write-Host "ogc desktop restart      - Restart Windows Explorer"
        Write-Host "ogc network <cmd>        - Network troubleshooting commands"
        Write-Host "ogc services list        - List all Windows services"
        Write-Host "ogc services restart <x> - Restart a Windows service"
        Write-Host "ogc cleanup temp         - Delete temporary files"
        Write-Host "ogc power plan <mode>    - Change power plan (high/balanced/saver)"
        Write-Host "ogc firewall enable/dis  - Enable/Disable Windows Firewall"
        Write-Host "ogc log [clear]          - View or clear OGC logs"
        Write-Host "ogc help                 - Show this help menu"
    }

    ### DEFAULT MESSAGE ###
    Default {
        Write-Host "Invalid command! Use 'ogc help' for a list of commands."
    }
}
